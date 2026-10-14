// Grouping, ordering and labelling of per-provider evidence for the analyst.
//
// The result view presents providers in a fixed order:
//   1. findings   — what providers FOUND: positive (malicious / suspicious),
//                   conflicting, typed records (CVE, test artifact) and explicit
//                   negative (clean) observations
//   2. context    — infrastructure / enrichment observations that do not score
//   3. not_found  — the provider had no record (not evidence of benignness)
//   4. problem    — the provider could not answer (rate limited, timeout,
//                   unavailable, error, missing key, …) with a concrete reason
// `not_applicable` rows are never shown: applicability lives in provider_plan.

import type { EvidenceObservation, NormalizedResult } from "../services/api";
import { getVerdictBand } from "./verdictColors";
import { titleCase } from "./format";

export type ProviderGroup = "finding" | "context" | "not_found" | "problem";

export interface ProviderRow {
  source: string;
  group: ProviderGroup;
  /** Execution state (success, not_found, rate_limited, …). */
  state: string;
  /** Normalized verdict used for colouring. */
  verdict: string;
  evidenceClass?: string;
  result?: NormalizedResult;
  observation?: EvidenceObservation;
  /** Human-readable reason; set for the problem group. */
  reason?: string;
}

export interface GroupedProviders {
  findings: ProviderRow[];
  context: ProviderRow[];
  notFound: ProviderRow[];
  problems: ProviderRow[];
}

const SUCCESS_STATES = new Set(["success", "found"]);
const HIDDEN_STATES = new Set(["not_applicable"]);
// Evidence classes emitted by app/backend/scorer.py. Findings are what a provider
// found about the indicator itself; context classes describe surroundings.
const FINDING_CLASSES = new Set([
  "direct", "supporting", "negative", "conflicting", "vulnerability", "test_artifact",
  "credential_exposure", "anonymization",
]);
const CONTEXT_CLASSES = new Set(["contextual", "exposure_context"]);
const REPUTATION_VERDICTS = new Set([
  "malicious", "suspicious", "clean", "benign", "harmless", "whitelisted", "undetected",
  "breached", "compromised", "pwned", "not_breached", "not_pwned",
]);

export const STATE_LABELS: Record<string, string> = {
  rate_limited: "Rate limited",
  timeout: "Timed out",
  unavailable: "Unavailable",
  error: "Error",
  invalid_request: "Request rejected",
  not_configured: "Not configured",
  aborted_due_to_ioc_deadline: "Stopped at IOC deadline",
  batch_deadline_exceeded: "Batch deadline exceeded",
  cancelled: "Cancelled",
  not_found: "Not found",
  success: "Response received",
};

/** Machine tags that explain a provider problem, mapped to analyst wording. */
export const TAG_REASONS: Record<string, string> = {
  no_api_key_configured: "no API key configured",
  missing_api_key: "no API key configured",
  not_configured: "not configured",
  disabled_by_policy: "disabled by ENABLED_SOURCES policy",
  invalid_api_key: "API key rejected as invalid",
  unauthorized: "API key not authorized",
  auth_error: "authentication failed",
  forbidden: "access forbidden",
  daily_quota_exhausted: "daily quota exhausted",
  weekly_quota_exhausted: "weekly quota exhausted",
  monthly_quota_exhausted: "monthly quota exhausted",
  quota_exhausted: "quota exhausted",
  out_of_credits: "out of credits",
  circuit_open: "skipped after repeated failures (circuit open)",
  connection_error: "connection failed",
  request_error: "request failed",
  feed_unavailable: "feed unavailable",
  lite_api_unavailable: "lite API unavailable",
  provider_unavailable: "provider unavailable",
  malformed_response: "malformed response",
  unexpected_response: "unexpected response",
  unsupported_type: "IOC type not supported",
  invalid_hash_format: "invalid hash format",
  invalid_hash_length: "invalid hash length",
  domain_search_restricted: "search restricted for broad public domains",
  censys_organization_id_missing: "Censys organization ID not configured",
  ioc_deadline_exceeded: "per-IOC deadline reached",
};

/** Tags that only restate state already shown elsewhere. Never rendered as chips. */
const STATE_TAGS = new Set([
  "cached", "stale", "rate_limited", "timeout", "timed_out", "error", "invalid_request", "unavailable",
  "not_found", "not_in_feed", "record_found", "unsupported_provider_type", "not_applicable",
  ...Object.keys(TAG_REASONS),
]);

const GENERIC_SUMMARY = /^(provider (rate limited|timed out|unavailable|returned an error|error)|no matching record|rate limited|timeout|error|unavailable)\.?$/i;

function lower(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

export function executionState(result?: NormalizedResult, observation?: EvidenceObservation): string {
  return (
    lower(result?.execution_state) ||
    lower(observation?.execution_state) ||
    lower(result?.status) ||
    lower(observation?.status) ||
    "unknown"
  );
}

function verdictOf(result?: NormalizedResult, observation?: EvidenceObservation): string {
  return (
    lower(observation?.normalized_verdict) ||
    lower(result?.normalized_verdict) ||
    lower(result?.verdict) ||
    lower(observation?.verdict) ||
    "unknown"
  );
}

function groupFor(state: string, verdict: string, evidenceClass: string | undefined, contribution: string | undefined): ProviderGroup | null {
  if (HIDDEN_STATES.has(state)) return null;
  if (state === "not_found") return "not_found";
  if (!SUCCESS_STATES.has(state)) return "problem";
  if (evidenceClass === "provider_status") return "problem";
  if (evidenceClass === "non_observation") return "not_found";
  if (evidenceClass && FINDING_CLASSES.has(evidenceClass)) return "finding";
  if (evidenceClass && CONTEXT_CLASSES.has(evidenceClass)) return "context";
  // Records that only matched related indicators count as findings while they
  // score; once the scorer demotes them to platform-abuse context they are context.
  if (evidenceClass === "related_indicator") return contribution === "positive" ? "finding" : "context";
  if (evidenceClass) return contribution === "positive" || contribution === "negative" ? "finding" : "context";
  return REPUTATION_VERDICTS.has(verdict) ? "finding" : "context";
}

/** Sort key inside the findings group: positive first, negative last. */
function findingRank(row: ProviderRow): number {
  if (row.evidenceClass === "conflicting" || row.evidenceClass === "anonymization") return 2;
  if (row.evidenceClass === "test_artifact" || row.evidenceClass === "vulnerability") return 3;
  const band = getVerdictBand(row.verdict);
  if (band === "malicious") return 0;
  if (band === "suspicious") return 1;
  if (band === "benign" || row.evidenceClass === "negative") return 5;
  return 4;
}

function tagList(tags: unknown): string[] {
  if (!Array.isArray(tags)) return [];
  return tags
    .filter((tag) => typeof tag === "string" || typeof tag === "number")
    .map((tag) => String(tag).trim())
    .filter(Boolean);
}

/** Concrete, analyst-readable reason for a provider that could not answer. */
export function problemReason(result?: NormalizedResult, observation?: EvidenceObservation): string {
  const state = executionState(result, observation);
  const label = SUCCESS_STATES.has(state) ? "Incomplete response" : STATE_LABELS[state] ?? titleCase(state);
  const details: string[] = [];
  const add = (text: string | null | undefined) => {
    const value = (text ?? "").trim();
    if (value && !details.some((item) => item.toLowerCase() === value.toLowerCase())) details.push(value);
  };
  for (const tag of [...tagList(result?.tags), ...tagList(observation?.tags)]) {
    const key = tag.toLowerCase();
    if (TAG_REASONS[key]) add(TAG_REASONS[key]);
    else if (/^http_[45]\d\d$/.test(key)) add(`HTTP ${key.slice(5)}`);
  }
  const summary = result?.provider_summary?.trim();
  if (summary && !GENERIC_SUMMARY.test(summary)) add(summary);
  const obsReason = observation?.reason?.trim();
  if (!details.length && obsReason && !GENERIC_SUMMARY.test(obsReason) && !/excluded from|not evidence/i.test(obsReason)) add(obsReason);
  const httpStatus = result?.http_status ?? (observation?.http_status as number | null | undefined);
  if (typeof httpStatus === "number" && Number.isFinite(httpStatus) && !details.some((item) => item.includes(`HTTP ${httpStatus}`))) {
    add(`HTTP ${httpStatus}`);
  }
  const retryAfter = result?.retry_after_seconds ?? observation?.retry_after_seconds;
  if (typeof retryAfter === "number" && Number.isFinite(retryAfter) && retryAfter > 0) add(`retry after ${Math.round(retryAfter)} s`);
  if (state === "timeout" && typeof result?.latency_ms === "number" && Number.isFinite(result.latency_ms)) {
    add(`after ${(result.latency_ms / 1000).toFixed(1)} s`);
  }
  return details.length ? `${label}: ${details.join("; ")}` : label;
}

/**
 * Join provider results with their evidence observations and assign each
 * provider to exactly one display group. Observations without a matching result
 * row (e.g. batch payloads) still produce a row.
 */
export function buildProviderRows(results: NormalizedResult[] | undefined, observations: EvidenceObservation[] | undefined): ProviderRow[] {
  const bySource = new Map<string, EvidenceObservation>();
  for (const observation of observations ?? []) {
    if (observation && typeof observation.source === "string") bySource.set(observation.source, observation);
  }
  const rows: ProviderRow[] = [];
  const seen = new Set<string>();
  const push = (result: NormalizedResult | undefined, observation: EvidenceObservation | undefined) => {
    const source = result?.source ?? observation?.source;
    if (!source || seen.has(source)) return;
    seen.add(source);
    const state = executionState(result, observation);
    const verdict = verdictOf(result, observation);
    const evidenceClass = lower(observation?.evidence_class) || undefined;
    const group = groupFor(state, verdict, evidenceClass, lower(observation?.contribution) || undefined);
    if (!group) return;
    const row: ProviderRow = { source, group, state, verdict, evidenceClass, result, observation };
    if (group === "problem") row.reason = problemReason(result, observation);
    rows.push(row);
  };
  for (const result of results ?? []) {
    if (result && typeof result.source === "string") push(result, bySource.get(result.source));
  }
  for (const observation of observations ?? []) push(undefined, observation);
  return rows;
}

export function groupProviderRows(rows: ProviderRow[]): GroupedProviders {
  const byName = (left: ProviderRow, right: ProviderRow) => left.source.localeCompare(right.source);
  const findings = rows.filter((row) => row.group === "finding")
    .sort((left, right) => findingRank(left) - findingRank(right) || byName(left, right));
  return {
    findings,
    context: rows.filter((row) => row.group === "context").sort(byName),
    notFound: rows.filter((row) => row.group === "not_found").sort(byName),
    problems: rows.filter((row) => row.group === "problem").sort(byName),
  };
}

/** Labels for EvidenceObservation.evidence_class (see scorer.py). */
export const EVIDENCE_CLASS_LABELS: Record<string, string> = {
  direct: "Direct threat evidence",
  supporting: "Supporting threat evidence",
  negative: "Negative (clean) evidence",
  conflicting: "Conflicting evidence",
  vulnerability: "Vulnerability record",
  test_artifact: "Security test artifact",
  contextual: "Context",
  anonymization: "Anonymization context",
  exposure_context: "Exposure context",
  related_indicator: "Related indicator (not this IOC)",
  credential_exposure: "Credential exposure",
};

/** Evidence classes that are exposure/context signals, never direct threat evidence. */
const NON_THREAT_CLASSES = new Set([
  "credential_exposure", "related_indicator", "anonymization", "exposure_context",
  "test_artifact", "vulnerability", "negative",
]);

/** A malicious/suspicious finding that counts as threat evidence about the indicator itself. */
export function isThreatFinding(row: ProviderRow): boolean {
  if (row.group !== "finding") return false;
  if (row.evidenceClass && NON_THREAT_CLASSES.has(row.evidenceClass)) return false;
  const band = getVerdictBand(row.verdict);
  return band === "malicious" || band === "suspicious";
}

export function isPositiveFinding(row: ProviderRow): boolean {
  if (row.group !== "finding") return false;
  if (row.evidenceClass === "credential_exposure") return true;
  if (row.evidenceClass === "test_artifact" || row.evidenceClass === "vulnerability" || row.evidenceClass === "negative") return false;
  const band = getVerdictBand(row.verdict);
  return band === "malicious" || band === "suspicious";
}

// ─── Tags ────────────────────────────────────────────────────────────────

export interface TidyTags {
  /** Short labels rendered as chips (deduplicated, human-readable). */
  chips: string[];
  /** "key: value" tags turned into structured attributes (shown in details). */
  attributes: [string, string][];
}

const KEY_VALUE_TAG = /^([A-Za-z][\w .-]{0,40}?)\s*:\s*(.+)$/;

/**
 * Split provider tags into tidy chips and structured attributes.
 *
 * Adapters historically used tags as a data transport ("votes_malicious: 59",
 * "ISP: Google LLC", "reported_by: x"). Those duplicate structured data and are
 * moved out of the chip row into attributes; pure state tags ("cached",
 * "rate_limited", …) are dropped because the state is shown elsewhere.
 */
export function tidyTags(tags: unknown): TidyTags {
  const chips: string[] = [];
  const chipKeys = new Set<string>();
  const attributes = new Map<string, string[]>();
  for (const tag of tagList(tags)) {
    const key = tag.toLowerCase();
    if (STATE_TAGS.has(key) || /^http_[45]\d\d$/.test(key)) continue;
    const match = KEY_VALUE_TAG.exec(tag);
    if (match && !match[2].startsWith("//")) {
      const name = titleCase(match[1]);
      const value = match[2].trim();
      const values = attributes.get(name) ?? [];
      if (!values.includes(value)) values.push(value);
      attributes.set(name, values);
      continue;
    }
    const label = tag.includes(" ") ? tag : tag.replace(/_/g, " ");
    const dedupe = label.toLowerCase();
    if (chipKeys.has(dedupe)) continue;
    chipKeys.add(dedupe);
    chips.push(label);
  }
  return {
    chips,
    attributes: [...attributes.entries()].map(([name, values]) => [name, values.join(", ")]),
  };
}
