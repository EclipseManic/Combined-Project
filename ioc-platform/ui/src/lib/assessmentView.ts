// Derives the verdict header of the result view from final_assessment — the
// authoritative verdict — so the header can never disagree with the reason
// text. Domain-aware: vulnerability (CVE) and credential-exposure lookups carry
// their own verdict vocabulary and metrics instead of reading "Unknown 0/100".

import type { IOCAssessment, LookupResponse } from "../services/api";
import { formatDate, formatDuration, formatNumber, formatPercent, titleCase, toFiniteNumber, EMPTY } from "./format";
import { isPositiveFinding, isThreatFinding, type GroupedProviders } from "./providerEvidence";
import { formatVerdictLabel, getVerdictBucket } from "./verdictColors";

export type MetricTone = "danger" | "warn" | "ok" | "info" | "neutral";

export interface HeadlineMetric {
  label: string;
  value: string;
  detail?: string;
  tone?: MetricTone;
}

export interface Headline {
  verdict: string;
  verdictLabel: string;
  domain: string;
  domainLabel: string;
  /** 0-100, or null when the verdict carries no score. */
  score: number | null;
  scoreText: string;
  scoreCaption: string;
  confidence: string;
  confidenceScore: number | null;
  reason: string;
  needsReview: boolean;
  reviewReasons: string[];
  metrics: HeadlineMetric[];
}

const DOMAIN_LABELS: Record<string, string> = {
  ioc_reputation: "Threat reputation",
  vulnerability: "Vulnerability",
  credential_exposure: "Credential exposure",
  identity_reputation: "Credential exposure",
  security_test_artifact: "Security test artifact",
  attack_technique: "ATT&CK technique",
  infrastructure: "Infrastructure context",
  context_only: "Context only",
};

const CREDENTIAL_DOMAINS = new Set(["credential_exposure", "identity_reputation"]);
const SCORELESS_BUCKETS = new Set(["context_only", "malicious_test_artifact", "unknown", "error"]);

type Loose = Record<string, unknown>;

function asRecord(value: unknown): Loose | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Loose) : null;
}

/** First non-empty value among `keys` on any of `sources`. */
function pick(sources: (Loose | null | undefined)[], keys: string[]): unknown {
  for (const source of sources) {
    if (!source) continue;
    for (const key of keys) {
      const value = source[key];
      if (value !== null && value !== undefined && value !== "") return value;
    }
  }
  return undefined;
}

export function domainLabel(domain: string | null | undefined): string {
  if (!domain) return DOMAIN_LABELS.ioc_reputation;
  return DOMAIN_LABELS[domain] ?? titleCase(domain);
}

export function isCredentialDomain(domain: string | null | undefined): boolean {
  return CREDENTIAL_DOMAINS.has(domain ?? "");
}

function confidenceMetric(confidence: string, confidenceScore: number | null): HeadlineMetric {
  return {
    label: "Confidence",
    value: titleCase(confidence || "low"),
    detail: confidenceScore != null ? `${Math.round(confidenceScore * 100)}% calibrated` : undefined,
    tone: confidence === "high" ? "ok" : confidence === "medium" ? "info" : "warn",
  };
}

function coverageMetric(assessment: IOCAssessment | null | undefined, grouped: GroupedProviders): HeadlineMetric {
  const summary = asRecord(assessment?.evidence_summary);
  const answered = grouped.findings.length + grouped.context.length + grouped.notFound.length;
  // Prefer reputation-provider coverage: context-only providers must not pad it.
  const repExpected = toFiniteNumber(summary?.reputation_providers_expected);
  const repEvaluated = toFiniteNumber(summary?.reputation_providers_evaluated);
  const useReputation = repExpected !== null && repExpected > 0 && repEvaluated !== null;
  const expected = useReputation ? repExpected : toFiniteNumber(summary?.expected_providers) ?? answered + grouped.problems.length;
  const evaluated = useReputation ? repEvaluated : toFiniteNumber(summary?.evaluated_providers) ?? answered;
  const problems = grouped.problems.length;
  return {
    label: useReputation ? "Reputation coverage" : "Provider coverage",
    value: expected > 0 ? `${evaluated}/${expected}` : "No providers",
    detail: expected === 0
      ? "none applicable to this type"
      : problems > 0
      ? `${problems} provider problem${problems === 1 ? "" : "s"}`
      : "all planned providers answered",
    tone: problems > 0 ? "warn" : expected > 0 ? "ok" : "neutral",
  };
}

interface VulnerabilityFacts {
  cvss: number | null;
  severity: string;
  epss: number | null;
  epssPercentile: number | null;
  kev: boolean;
  kevDate: string;
  exploitStatus: string;
  knownExploited: boolean;
}

export function vulnerabilityFacts(result: LookupResponse): VulnerabilityFacts {
  const assessment = asRecord(result.final_assessment);
  const cve = asRecord(result.enrichment?.cve);
  // scorer.py puts severity / cvss_score / epss_score / known_exploited in
  // evidence_summary for the vulnerability domain.
  const nested = asRecord(assessment?.evidence_summary);
  const records = [
    ...(Array.isArray(result.final_assessment?.vulnerabilities) ? result.final_assessment!.vulnerabilities! : []),
    ...(result.results ?? []).filter((item) => item && item.cvss_score != null),
  ].map((item) => asRecord(item)).filter(Boolean) as Loose[];
  const best = records.reduce<Loose | null>((current, item) => {
    const score = toFiniteNumber(item.cvss_score);
    if (score === null) return current;
    return current && (toFiniteNumber(current.cvss_score) ?? -1) >= score ? current : item;
  }, null);
  const cvss = toFiniteNumber(pick([nested, assessment, cve, best], ["cvss_score", "cvss"]));
  const severity = String(pick([nested, assessment, cve, best], ["cvss_severity", "severity"]) ?? "");
  const epss = toFiniteNumber(pick([nested, assessment, cve, best], ["epss_score", "epss"]));
  const epssPercentile = toFiniteNumber(pick([nested, assessment, cve], ["epss_percentile"]));
  const kev = pick([cve, nested], ["is_in_kev"]) === true;
  const kevDate = String(pick([cve, nested], ["kev_date_added"]) ?? "");
  const exploitStatus = String(pick([nested, assessment, cve, best], ["exploit_status"]) ?? "");
  const knownExploited = kev || nested?.known_exploited === true || exploitStatus === "known_exploited";
  return { cvss, severity, epss, epssPercentile, kev, kevDate, exploitStatus, knownExploited };
}

function vulnerabilityMetrics(result: LookupResponse): HeadlineMetric[] {
  const facts = vulnerabilityFacts(result);
  const severity = facts.severity && facts.severity.toLowerCase() !== "informational" ? titleCase(facts.severity.toLowerCase()) : "";
  const exploited = facts.knownExploited;
  return [
    {
      label: "CVSS base score",
      value: facts.cvss != null ? facts.cvss.toFixed(1) : EMPTY,
      detail: severity || (facts.cvss == null ? "not scored" : undefined),
      tone: facts.cvss == null ? "neutral" : facts.cvss >= 7 ? "danger" : facts.cvss >= 4 ? "warn" : "ok",
    },
    {
      label: "EPSS",
      value: formatPercent(facts.epss, 1),
      detail: facts.epssPercentile != null ? `${formatPercent(facts.epssPercentile, 0)} percentile` : "exploit probability (30 d)",
      tone: facts.epss == null ? "neutral" : facts.epss >= 0.1 ? "danger" : facts.epss >= 0.01 ? "warn" : "ok",
    },
    {
      label: "Known exploitation",
      value: facts.kev ? "CISA KEV" : exploited ? "Exploited" : facts.exploitStatus ? titleCase(facts.exploitStatus) : "No signal",
      detail: facts.kev && facts.kevDate ? `added ${formatDate(facts.kevDate)}` : undefined,
      tone: exploited ? "danger" : "neutral",
    },
  ];
}

function credentialMetrics(result: LookupResponse, grouped: GroupedProviders): HeadlineMetric[] {
  const breach = asRecord(result.enrichment?.breach);
  const infostealer = asRecord(result.enrichment?.infostealer);
  const assessment = asRecord(result.final_assessment);
  const summary = asRecord(assessment?.evidence_summary);
  const breachCount = toFiniteNumber(pick([summary, breach], ["breach_enrichment_count", "breach_count"]));
  const infections = toFiniteNumber(pick([infostealer], ["total_employee_compromises"]));
  const exposureSources = Array.isArray(summary?.exposure_sources) ? summary!.exposure_sources.length : null;
  const exposing = exposureSources ?? grouped.findings.filter(isPositiveFinding).length;
  const recent = typeof breach?.most_recent_breach === "string" ? breach.most_recent_breach : "";
  return [
    {
      label: "Public breaches",
      value: breachCount != null ? formatNumber(breachCount) : EMPTY,
      detail: breachCount == null ? "no breach data" : recent ? `most recent: ${recent}` : undefined,
      tone: breachCount == null ? "neutral" : breachCount > 0 ? "danger" : "ok",
    },
    {
      label: "Infostealer infections",
      value: infections != null ? formatNumber(infections) : EMPTY,
      detail: infections == null ? "no infostealer data" : undefined,
      tone: infections == null ? "neutral" : infections > 0 ? "danger" : "ok",
    },
    {
      label: "Exposure sources",
      value: String(exposing),
      detail: exposing === 1 ? "source reports exposure" : "sources report exposure",
      tone: exposing > 0 ? "danger" : "ok",
    },
  ];
}

function reputationMetrics(result: LookupResponse, assessment: IOCAssessment | null | undefined, grouped: GroupedProviders): HeadlineMetric[] {
  const positive = grouped.findings.filter(isThreatFinding);
  const reputationFindings = grouped.findings.filter((row) => row.evidenceClass !== "test_artifact" && row.evidenceClass !== "vulnerability");
  const latencies = (result.results ?? []).map((item) => toFiniteNumber(item?.latency_ms)).filter((value): value is number => value !== null);
  const cachedCount = (result.results ?? []).filter((item) => item?.cached).length;
  const freshness = assessment?.freshness
    ? titleCase(assessment.freshness)
    : cachedCount === 0 ? "Live" : cachedCount === (result.results ?? []).length ? "Cached" : "Mixed";
  return [
    {
      label: "Flagged by",
      value: reputationFindings.length ? `${positive.length}/${reputationFindings.length}` : "0",
      detail: reputationFindings.length
        ? `${positive.length} of ${reputationFindings.length} providers with findings`
        : "no provider findings",
      tone: positive.length > 0 ? "danger" : reputationFindings.length > 0 ? "ok" : "neutral",
    },
    {
      label: "Evidence freshness",
      value: freshness,
      detail: latencies.length ? `slowest provider ${formatDuration(Math.max(...latencies))}` : undefined,
      tone: "neutral",
    },
  ];
}

export function buildHeadline(result: LookupResponse, grouped: GroupedProviders): Headline {
  const assessment = result.final_assessment ?? null;
  const verdict = (assessment?.final_verdict || result.composite?.verdict || "unknown").toLowerCase();
  const domain = assessment?.assessment_domain || "ioc_reputation";
  const confidence = (assessment?.confidence || result.composite?.confidence || "low").toLowerCase();
  const confidenceScore = toFiniteNumber(assessment?.confidence_score);
  let score = toFiniteNumber(assessment ? assessment.normalized_score : result.composite?.score);
  if (score === null && assessment) {
    const risk = toFiniteNumber(assessment.risk_score);
    score = risk === null ? null : risk * 100;
  }
  if (score !== null) score = Math.max(0, Math.min(100, score));
  const scoreless = SCORELESS_BUCKETS.has(getVerdictBucket(verdict));
  if (scoreless && (score === null || score === 0)) score = null;

  let scoreText: string;
  let scoreCaption: string;
  if (score === null) {
    scoreCaption = "Score";
    scoreText = getVerdictBucket(verdict) === "malicious_test_artifact"
      ? "Test artifact — not scored"
      : verdict === "context_only"
      ? "Context only — not scored"
      : "Not scored";
  } else if (domain === "vulnerability") {
    scoreCaption = "Vulnerability risk";
    const facts = vulnerabilityFacts(result);
    scoreText = facts.cvss != null ? `CVSS ${facts.cvss.toFixed(1)} · risk ${Math.round(score)}/100` : `Risk ${Math.round(score)}/100`;
  } else if (isCredentialDomain(domain)) {
    scoreCaption = "Exposure score";
    scoreText = `${Math.round(score)}/100`;
  } else {
    scoreCaption = "Threat score";
    scoreText = `${Math.round(score)}/100`;
  }

  const metrics: HeadlineMetric[] = [confidenceMetric(confidence, confidenceScore)];
  if (domain === "vulnerability") metrics.push(...vulnerabilityMetrics(result));
  else if (isCredentialDomain(domain)) metrics.push(...credentialMetrics(result, grouped));
  else metrics.push(...reputationMetrics(result, assessment, grouped), coverageMetric(assessment, grouped));
  if (domain === "vulnerability" || isCredentialDomain(domain)) {
    // Keep coverage visible for typed domains without exceeding four tiles.
    if (metrics.length < 4) metrics.push(coverageMetric(assessment, grouped));
  }

  const reviewReasons = Array.isArray(assessment?.review_reasons)
    ? assessment!.review_reasons!.filter((item): item is string => typeof item === "string" && item.trim() !== "")
    : [];

  return {
    verdict,
    verdictLabel: titleCase(formatVerdictLabel(verdict)),
    domain,
    domainLabel: domainLabel(domain),
    score,
    scoreText,
    scoreCaption,
    confidence,
    confidenceScore,
    reason: typeof assessment?.reason === "string" ? assessment.reason : "",
    needsReview: Boolean(assessment?.needs_review || assessment?.analyst_review_recommended),
    reviewReasons,
    metrics: metrics.slice(0, 4),
  };
}
