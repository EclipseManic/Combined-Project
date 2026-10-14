import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { showToast } from "../components/Toast";
import IocAssessmentCard from "../components/IocAssessmentCard";
import VerdictBadge from "../components/VerdictBadge";
import {
  ApiError,
  buildLookupResponseFromBatch,
  cancelBatch,
  errorMessage,
  getBatchIOCResult,
  getBatchResult,
  getBatchStatus,
  startBatch,
  uploadBatchFile,
  type BatchResult,
  type BatchResultItem,
  type BatchStatus,
  type IOCAssessment,
  type LookupResponse,
} from "../services/api";
import type { NavigateEvent } from "../App";
import { formatDuration } from "../lib/format";
import { problemReason } from "../lib/providerEvidence";
import { getVerdictBucket, type VerdictBucket } from "../lib/verdictColors";

/**
 * Verdict bucketing comes from lib/verdictColors, which is the single source of
 * truth. A local reimplementation used to live here and disagreed with it: it had
 * no case for the vulnerability severity vocabulary (critical/high/medium/low),
 * so every CVE in a batch bucketed to "unknown" and the verdict filter could not
 * isolate any of them. The shared map resolves critical/high to "malicious",
 * medium to "suspicious" and low to "benign".
 */
type BatchGroup = { key: string; assessment?: IOCAssessment; results: BatchResultItem[]; value: string; type: string };

/** Donut/legend colours, taken from the shared palette so the two never drift. */
const VERDICT_COLORS: Record<VerdictBucket, string> = {
  malicious: "#ef4444",
  breached: "#f43f5e",
  suspicious: "#f59e0b",
  benign: "#22c55e",
  not_breached: "#10b981",
  context_only: "#6b7280",
  malicious_test_artifact: "#3b82f6",
  unknown: "#6b7280",
  error: "#ef4444",
};

/** Severity order for sorting, most severe first. */
const VERDICT_ORDER: VerdictBucket[] = [
  "malicious",
  "breached",
  "suspicious",
  "context_only",
  "benign",
  "not_breached",
  "malicious_test_artifact",
  "unknown",
  "error",
];

const CREDENTIAL_MARKERS = ["password", "passwd", "secret", "admin", "root", "qwerty", "letmein", "welcome", "login", "auth", "user", "service"];

function isCredentialCandidate(value: string): boolean {
  const input = value.trim().toLowerCase();
  if (!input) return false;
  const explicit = input.match(/^(?:pass|password|password_sha1):(.+)$/);
  if (explicit) return !/^[a-f0-9]{40}$/i.test(explicit[1]);
  if (/^(?:email|domain|url|ipv4|ipv6|md5|sha1|sha256|cve|asn|password_sha1):/.test(input)) return false;
  if (/^[a-z0-9_\\-]{6,}$/.test(input) && CREDENTIAL_MARKERS.some((marker) => input.includes(marker))) return true;
  if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$/.test(input)) return false;
  if (/@|^[a-z0-9.-]+\.[a-z]{2,}$/.test(input)) {
    return CREDENTIAL_MARKERS.some((marker) => input.includes(marker));
  }
  return /^[^\s]{4,128}$/.test(input) && /[A-Z]/.test(input) && /[a-z]/.test(input) && /[\d!@#$%^&*(),.?":{}|<>]/.test(input);
}

async function prepareBatchValues(values: string[]): Promise<string[]> {
  const prepared: string[] = [];
  for (const value of values) {
    const input = value.trim();
    const match = input.match(/^(?:pass|password|password_sha1):(.+)$/i);
    if (match) {
      const candidate = match[1]?.trim() ?? "";
      if (/^[a-f0-9]{40}$/i.test(candidate)) {
        prepared.push(`password_sha1:${candidate.toLowerCase()}`);
        continue;
      }
      if (!window.crypto?.subtle) throw new Error("Secure password hashing is unavailable in this browser");
      const digest = await window.crypto.subtle.digest("SHA-1", new TextEncoder().encode(candidate));
      const hash = Array.from(new Uint8Array(digest)).map((part) => part.toString(16).padStart(2, "0")).join("");
      prepared.push(`password:${hash}`);
      continue;
    }
    if (isCredentialCandidate(input)) {
      throw new Error("Credential-like batch values must use an explicit password: prefix");
    }
    prepared.push(input);
  }
  return prepared;
}

// Verdict bucketing is delegated to lib/verdictColors (getVerdictBucket). The
// implementation that used to live here had no case for the vulnerability
// severity vocabulary, so critical/high/medium/low all fell through to
// "unknown" and a batch of CVEs could not be filtered by verdict at all.
const verdictBucket = getVerdictBucket;

function verdictLabel(verdict: VerdictBucket): string {
  if (verdict === "not_breached") return "Not Breached";
  if (verdict === "breached") return "Breached";
  return verdict === "benign" ? "Benign" : verdict.charAt(0).toUpperCase() + verdict.slice(1);
}

const ACTIVE_BATCH_KEY = "ioc-platform.active-batch";
/** Consecutive transient status-poll failures tolerated before showing the retry card. */
export const MAX_BATCH_POLL_FAILURES = 5;

function readActiveBatch(): string | null {
  try {
    return window.sessionStorage.getItem(ACTIVE_BATCH_KEY);
  } catch {
    return null;
  }
}

function writeActiveBatch(batchId: string | null): void {
  try {
    if (batchId) window.sessionStorage.setItem(ACTIVE_BATCH_KEY, batchId);
    else window.sessionStorage.removeItem(ACTIVE_BATCH_KEY);
  } catch {
    // sessionStorage unavailable: the batch simply is not resumed after a tab switch.
  }
}

function count(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function keyFor(value: string, type: string): string {
  return `${type}:${value.trim().toLowerCase()}`;
}

function domainFor(assessment?: IOCAssessment): string {
  return assessment?.assessment_domain ?? "ioc_reputation";
}

function riskMatches(score: number, filter: string): boolean {
  if (filter === "low") return score < 30;
  if (filter === "medium") return score >= 30 && score < 70;
  if (filter === "high") return score >= 70;
  return true;
}

function timestampFor(group: BatchGroup): number {
  const value = group.assessment?.timestamps?.newest_observation ?? group.assessment?.analyzed_at;
  const time = value ? Date.parse(String(value)) : 0;
  return Number.isFinite(time) ? time : 0;
}

function statusFor(assessment: IOCAssessment): string {
  if (assessment.assessment_status === "not_applicable") return "not_applicable";
  if (assessment.assessment_status === "unavailable") return "unavailable";
  if (assessment.assessment_status === "cancelled") return "cancelled";
  if (assessment.assessment_status === "error") return "error";
  if (assessment.assessment_status === "batch_deadline_exceeded") return "batch_deadline_exceeded";
  const expected = count(Number(assessment.evidence_summary?.expected_providers ?? 0));
  const evaluated = count(Number(assessment.evidence_summary?.evaluated_providers ?? 0));
  const rateLimited = assessment.rate_limited_sources ?? [];
  const hasHealthFailure = rateLimited.length > 0
    || (assessment.unavailable_sources ?? []).length > 0
    || (assessment.error_sources ?? []).length > 0;
  if (assessment.final_verdict === "unknown" && rateLimited.length > 0 && evaluated === 0) return "rate_limited";
  if (hasHealthFailure || (expected > 0 && evaluated < expected)) return "partial";
  return "complete";
}

/**
 * Whether an indicator had any provider in a given failure bucket.
 *
 * Deliberately separate from `statusFor`, which produces one status per
 * indicator and folds provider-level problems into "partial".
 */
function providerIssueMatches(assessment: IOCAssessment | undefined, filter: string): boolean {
  if (filter === "all") return true;
  if (!assessment) return false;
  if (filter === "rate_limited") return (assessment.rate_limited_sources ?? []).length > 0;
  if (filter === "unavailable") return (assessment.unavailable_sources ?? []).length > 0;
  if (filter === "error") return (assessment.error_sources ?? []).length > 0;
  if (filter === "any") {
    return (assessment.rate_limited_sources ?? []).length > 0
      || (assessment.unavailable_sources ?? []).length > 0
      || (assessment.error_sources ?? []).length > 0;
  }
  if (filter === "none") {
    return (assessment.rate_limited_sources ?? []).length === 0
      && (assessment.unavailable_sources ?? []).length === 0
      && (assessment.error_sources ?? []).length === 0;
  }
  return true;
}

function buildGroups(result: BatchResult): BatchGroup[] {
  const byKey = new Map<string, BatchGroup>();
  for (const assessment of result.assessments ?? result.final_results ?? []) {
    const value = assessment.normalized_ioc || assessment.ioc;
    const key = keyFor(value, assessment.ioc_type);
    byKey.set(key, { key, assessment, results: [], value, type: assessment.ioc_type });
  }
  for (const item of result.results ?? []) {
    if ((item.execution_state || item.status) === "not_applicable") continue;
    const value = item.ioc || item._ioc;
    if (!value) continue;
    const key = keyFor(value, item.ioc_type);
    const existing = byKey.get(key);
    if (existing) existing.results.push(item);
    else byKey.set(key, { key, results: [item], value, type: item.ioc_type });
  }
  return [...byKey.values()];
}

function VerdictDonut({ counts }: { counts: Record<VerdictBucket, number> }) {
  const total = VERDICT_ORDER.reduce((sum, verdict) => sum + counts[verdict], 0);
  if (total === 0) return <div className="text-sm text-text-secondary">No reputation assessments in this batch.</div>;
  let offset = 0;
  const radius = 50;
  const circumference = 2 * Math.PI * radius;
  return (
    <div className="flex items-center gap-5">
      <div className="relative h-28 w-28 shrink-0">
        <svg viewBox="0 0 120 120" className="h-28 w-28 -rotate-90">
          {VERDICT_ORDER.map((verdict) => {
            const count = counts[verdict];
            if (!count) return null;
            const dash = (count / total) * circumference;
            const currentOffset = circumference - offset - dash;
            offset += dash;
            return <circle key={verdict} cx="60" cy="60" r={radius} fill="none" stroke={VERDICT_COLORS[verdict]} strokeWidth="12" strokeDasharray={`${dash} ${circumference - dash}`} strokeDashoffset={currentOffset} />;
          })}
        </svg>
        <span className="absolute inset-0 flex items-center justify-center text-lg font-bold font-mono">{total}</span>
      </div>
      <div className="grid grid-cols-2 gap-x-5 gap-y-1 text-xs">
        {VERDICT_ORDER.map((verdict) => <div key={verdict} className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: VERDICT_COLORS[verdict] }} /><span className="text-text-secondary">{verdictLabel(verdict)}</span><span className="font-mono">{counts[verdict]}</span></div>)}
      </div>
    </div>
  );
}

function UnassessedGroup({ group }: { group: BatchGroup }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <article className="overflow-hidden rounded-xl border border-border bg-bg-card">
      <button type="button" onClick={() => setExpanded((value) => !value)} aria-expanded={expanded} className="w-full p-4 text-left hover:bg-bg-elevated/30">
        <div className="flex flex-wrap items-center justify-between gap-3"><div className="min-w-0"><div className="mb-1 text-xs uppercase tracking-wider text-text-secondary">{group.type} · assessment unavailable</div><div className="truncate font-mono text-sm" title={group.value}>{group.value}</div></div><div className="flex items-center gap-2"><VerdictBadge verdict="unknown" /><span className="rounded-full border border-rose-500/40 bg-rose-500/10 px-2 py-0.5 text-xs font-semibold uppercase text-rose-300">Pipeline health</span><span className="text-text-secondary">{expanded ? "^" : "?"}</span></div></div>
        <p className="mt-2 text-xs text-text-secondary">The IOC-level assessment was not returned. Provider results are retained below for audit.</p>
      </button>
      {expanded && <div className="space-y-2 border-t border-border p-4">{group.results.map((item) => <div key={item.source} className="rounded border border-border bg-bg-elevated/40 p-2 text-xs"><div className="flex justify-between gap-2"><span className="font-semibold">{item.source}</span><span className="text-text-secondary">{item.execution_state || item.status}</span></div><div className="mt-1 text-text-secondary">{(item.execution_state || item.status) === "success" ? `Provider verdict: ${item.provider_verdict ?? item.verdict}` : problemReason(item)}</div></div>)}</div>}
    </article>
  );
}

function BatchSummary({ result, groups }: { result: BatchResult; groups: BatchGroup[] }) {
  const counts = useMemo(() => {
    const next = Object.fromEntries(VERDICT_ORDER.map((bucket) => [bucket, 0])) as Record<VerdictBucket, number>;
    for (const group of groups) {
      next[verdictBucket(group.assessment?.final_verdict ?? "unknown")] += 1;
    }
    return next;
  }, [groups]);
  const domainCounts = useMemo(() => {
    const next: Record<string, number> = {};
    for (const group of groups) {
      const domain = domainFor(group.assessment);
      next[domain] = (next[domain] ?? 0) + 1;
    }
    return Object.entries(next).sort((left, right) => right[1] - left[1]);
  }, [groups]);
  const health = result.provider_health ?? [];
  const cached = health.reduce((sum, item) => sum + count(item.cache_hit_count), 0);
  // `failed_lookups` is a SUPERSET, verified against app/backend/batch.py
  // (BatchTask.refresh_metrics): execution_state "rate_limited" increments both
  // `rate_limited_lookups` and `failed_lookups`; "timeout" increments both
  // `timeout_lookups` and `failed_lookups`; every other non-success, non-N/A,
  // non-deadline state increments `failed_lookups` alone. Deadline aborts go to
  // `batch_deadline_exceeded` only and are never in `failed_lookups`. So this
  // subtraction correctly isolates genuine provider errors/unavailability.
  const rateLimited = count(result.rate_limited_lookups);
  const timeouts = count(result.timeout_lookups);
  const errors = Math.max(0, count(result.failed_lookups) - rateLimited - timeouts);
  const deadline = count(result.batch_deadline_exceeded ?? result.execution_health?.batch_deadline_exceeded);
  const averageLatency = health.length ? health.reduce((sum, item) => sum + count(item.average_latency_ms), 0) / health.length : 0;
  const healthMetrics = [
    ["Provider lookups", count(result.expected_lookups)],
    ["Successful", count(result.successful_lookups)],
    ["Cached", cached],
    ["Not found", count(result.not_found_lookups)],
    ["Rate limited", rateLimited],
    ["Timeouts", timeouts],
    ["Errors / unavailable", errors],
    ["Batch deadline", deadline],
    ["Avg provider latency", health.length ? formatDuration(averageLatency) : "—"],
  ] as const;
  return (
    <section className="rounded-xl border border-border bg-bg-card p-5">
      <div className="flex flex-wrap items-start justify-between gap-5">
        <div><h3 className="text-sm font-semibold uppercase tracking-wider text-text-secondary">IOC reputation summary</h3><p className="mt-1 text-xs text-text-secondary">Only reputation-domain verdicts appear in this chart; typed domains stay separate.</p><div className="mt-4"><VerdictDonut counts={counts} /></div><div className="mt-4 flex flex-wrap gap-2">{domainCounts.map(([domain, count]) => <span key={domain} className="rounded-full border border-border bg-bg-elevated px-2.5 py-1 text-xs text-text-secondary">{domain.replace(/_/g, " ")}: <span className="font-semibold text-text-primary">{count}</span></span>)}</div></div>
        <div className="min-w-[min(100%,34rem)] flex-1"><h3 className="text-sm font-semibold uppercase tracking-wider text-text-secondary">Provider lookup health</h3><div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3">{healthMetrics.map(([name, value]) => <div key={name} className="rounded-md border border-border bg-bg-elevated/60 p-2.5"><div className="text-xs uppercase tracking-wider text-text-secondary">{name}</div><div className={`mt-1 text-lg font-semibold ${name === "Rate limited" || name === "Timeouts" || name === "Errors / unavailable" ? "text-amber-300" : "text-text-primary"}`}>{value}</div></div>)}</div><div className="mt-3 flex flex-wrap gap-2 text-xs text-text-secondary"><span>{count(result.completed)}/{count(result.total)} IOCs complete</span><span>·</span><span>{count(result.not_found_lookups)} not found (not clean)</span><span>·</span><span>{groups.filter((group) => group.assessment?.needs_review).length} needs review</span></div></div>
      </div>
      {(rateLimited > 0 || timeouts > 0 || errors > 0 || deadline > 0) && <p className="mt-4 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">Provider-health failures and deadline aborts are shown as execution status and excluded from malicious/benign scoring. UNKNOWN with incomplete coverage is not proof of safety.</p>}
    </section>
  );
}

export default function Batch({
  initialBatchId = "",
  initialResult,
  autoRescan = false,
}: {
  initialBatchId?: string;
  initialResult?: BatchResult | null;
  autoRescan?: boolean;
}) {
  const [iocs, setIocs] = useState("");
  const [batchId, setBatchId] = useState<string | null>(null);
  const [status, setStatus] = useState<BatchStatus | null>(null);
  const [result, setResult] = useState<BatchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [query, setQuery] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("all");
  const [domainFilter, setDomainFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [providerFilter, setProviderFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  /**
   * Provider-level failures, filtered independently of the IOC's own status.
   *
   * `statusFor` is a single per-IOC rollup: one rate-limited provider out of
   * twelve makes the whole indicator "partial", so the rate-limited, unavailable
   * and error signals are lost. This asks the assessment directly whether any
   * provider in that bucket failed, which is the question an analyst asking
   * "which indicators did we only partly answer?" actually means.
   */
  const [providerIssueFilter, setProviderIssueFilter] = useState("all");
  const [confidenceFilter, setConfidenceFilter] = useState("all");
  const [freshnessFilter, setFreshnessFilter] = useState("all");
  const [riskFilter, setRiskFilter] = useState("all");
  const [coverageFilter, setCoverageFilter] = useState("all");
  const [malwareFilter, setMalwareFilter] = useState("");
  const [reviewOnly, setReviewOnly] = useState(false);
  const [sortBy, setSortBy] = useState("severity");
  const [expandAll, setExpandAll] = useState(false);
  const [pollError, setPollError] = useState<string | null>(null);
  const [batchFailure, setBatchFailure] = useState<string | null>(null);
  // Non-null while a batch is being fetched/started but has produced no status,
  // result or error yet. Without it that window renders the "paste IOCs" form.
  const [loadingNotice, setLoadingNotice] = useState<string | null>(initialBatchId ? "Loading saved batch…" : null);
  const [openingKey, setOpeningKey] = useState<string | null>(null);
  const pollingRef = useRef<number | null>(null);
  const pollingGenerationRef = useRef(0);
  const pollFailuresRef = useRef(0);
  const autoRescanTriggeredRef = useRef(false);

  const stopPolling = useCallback(() => {
    pollingGenerationRef.current += 1;
    if (pollingRef.current !== null) {
      clearTimeout(pollingRef.current);
      pollingRef.current = null;
    }
    return pollingGenerationRef.current;
  }, []);

  useEffect(() => () => { stopPolling(); }, [stopPolling]);

  useEffect(() => {
    const resumeId = initialBatchId || readActiveBatch();
    if (!resumeId) {
      setLoadingNotice(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setLoadingNotice(initialBatchId ? "Loading saved batch…" : "Resuming batch…");
    getBatchResult(resumeId).then((loaded) => {
      if (!cancelled) {
        setBatchId(loaded.batch_id || resumeId);
        setResult(loaded);
        setLoading(false);
        setLoadingNotice(null);
      }
    }).catch((error: unknown) => {
      if (cancelled) return;
      if (error instanceof ApiError && error.status === 425) {
        // Still running on the server: follow its progress instead of failing.
        setBatchId(resumeId);
        setLoadingNotice("Batch still running — reconnecting…");
        void pollBatchRef.current?.(resumeId);
        return;
      }
      setLoading(false);
      setLoadingNotice(null);
      if (!initialBatchId) {
        writeActiveBatch(null);
        return;
      }
      if (initialResult && Array.isArray(initialResult.results)) {
        setBatchId(initialResult.batch_id || initialBatchId);
        setResult({ ...initialResult, batch_id: initialResult.batch_id || initialBatchId });
        showToast("Showing the locally stored copy of this batch", "info");
        return;
      }
      showToast("This batch is no longer available on the server", "error");
    });
    return () => { cancelled = true; };
  }, [initialBatchId, initialResult]);

  const pollBatch = useCallback(async (bid: string) => {
    stopPolling();
    setPollError(null);
    setBatchFailure(null);
    pollFailuresRef.current = 0;
    writeActiveBatch(bid);
    const generation = pollingGenerationRef.current;
    const poll = async () => {
      if (generation !== pollingGenerationRef.current) return;
      try {
        const current = await getBatchStatus(bid);
        if (generation !== pollingGenerationRef.current) return;
        pollFailuresRef.current = 0;
        setLoadingNotice(null);
        setStatus(current);
        if (current.status === "cancelled") {
          const stoppedGeneration = stopPolling();
          setLoading(false);
          try {
            const cancelledResult = await getBatchResult(bid);
            if (stoppedGeneration === pollingGenerationRef.current) setResult(cancelledResult);
          } catch {
            setBatchId(null);
            setStatus(null);
            writeActiveBatch(null);
          }
          showToast("Batch cancelled", "info");
          return;
        }
        if (current.status === "error") {
          const message = current.error || "Batch failed";
          stopPolling(); setLoading(false); setStatus(null); setBatchId(null); writeActiveBatch(null);
          setBatchFailure(message);
          showToast(message, "error");
          return;
        }
        if (current.status === "done" || current.status === "completed") {
          const stoppedGeneration = stopPolling();
          // `stopPolling()` already bumped the generation, so a throw here would
          // fall into the outer catch and be discarded by its stale-generation
          // guard — leaving `loading` true and the progress card spinning with no
          // error. This branch therefore recovers on its own.
          let finalResult: BatchResult;
          try {
            finalResult = await getBatchResult(bid);
          } catch {
            if (stoppedGeneration !== pollingGenerationRef.current) return;
            setLoading(false);
            setLoadingNotice(null);
            // `status` is intentionally kept: setting `pollError` hides the
            // progress card (it requires `!pollError`) and shows the retry card.
            setPollError("Batch finished but results could not be loaded. Retry to fetch them.");
            showToast("Batch finished but results could not be loaded — retry to fetch them", "error");
            return;
          }
          if (stoppedGeneration !== pollingGenerationRef.current) return;
          setResult(finalResult);
          setLoading(false);
          setLoadingNotice(null);
          showToast(`Batch complete: ${finalResult.completed}/${finalResult.total} IOCs`, "success");
          return;
        }
      } catch (error) {
        if (generation !== pollingGenerationRef.current) return;
        const notFound = error instanceof ApiError && error.status === 404;
        pollFailuresRef.current += 1;
        if (notFound || pollFailuresRef.current > MAX_BATCH_POLL_FAILURES) {
          stopPolling(); setLoading(false); setLoadingNotice(null);
          if (notFound) writeActiveBatch(null);
          const message = notFound
            ? "The server no longer knows this batch (it may have restarted)."
            : `Batch polling failed: ${errorMessage(error)}. The batch may still be running on the server.`;
          setPollError(message);
          showToast(notFound ? message : "Batch polling failed — retry to resume", "error");
          return;
        }
      }
      if (generation === pollingGenerationRef.current) {
        pollingRef.current = window.setTimeout(() => {
          void poll();
        }, 1000);
      }
    };
    pollingRef.current = window.setTimeout(() => {
      void poll();
    }, 1000);
  }, [stopPolling]);

  const pollBatchRef = useRef<typeof pollBatch | null>(null);
  pollBatchRef.current = pollBatch;

  function clearBatch() {
    stopPolling();
    writeActiveBatch(null);
    setPollError(null); setBatchFailure(null); setLoadingNotice(null); setLoading(false);
    setIocs(""); setBatchId(null); setStatus(null); setResult(null);
  }

  async function handleSubmit() {
    const list = iocs.split("\n").map((value) => value.trim()).filter(Boolean);
    if (list.length === 0) { showToast("Enter at least one IOC", "error"); return; }
    if (list.length > 100) { showToast("Maximum 100 IOCs", "error"); return; }
    let preparedList: string[];
    try {
      preparedList = await prepareBatchValues(list);
    } catch (error) {
      showToast(error instanceof Error ? error.message : "Could not secure batch input", "error");
      return;
    }
    setLoading(true); setBatchId(null); setStatus(null); setResult(null); setBatchFailure(null); setLoadingNotice("Starting batch…");
    try { const started = await startBatch(preparedList); setBatchId(started.batch_id); await pollBatch(started.batch_id); } catch (error) { showToast(errorMessage(error, "Could not start batch"), "error"); setLoading(false); setLoadingNotice(null); }
  }

  async function handleFileUpload(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const hasCredential = text.split(/\r?\n/).some((line) => isCredentialCandidate(line.trim()));
      if (hasCredential) {
        showToast("Credential values are not accepted in batch files; use password: entries in the text field", "error");
        return;
      }
    } catch {
      showToast("Could not inspect batch file", "error");
      return;
    }
    setLoading(true); setBatchId(null); setStatus(null); setResult(null); setBatchFailure(null); setLoadingNotice("Uploading batch file…");
    try { const started = await uploadBatchFile(file); setBatchId(started.batch_id); await pollBatch(started.batch_id); } catch (error) { showToast(errorMessage(error, "Could not upload batch"), "error"); setLoading(false); setLoadingNotice(null); }
  }

  function navigateToLookup(group: BatchGroup, lookupResponse: LookupResponse) {
    window.dispatchEvent(new CustomEvent<NavigateEvent>("navigate", {
      detail: {
        page: "lookup",
        ioc: group.value,
        iocType: group.type === "password" ? "password_sha1" : group.type,
        batchResultItem: lookupResponse,
        fromBatch: true,
        batchId: result?.batch_id,
      },
    }));
  }

  async function handleOpenGroup(group: BatchGroup) {
    const fallback = () => buildLookupResponseFromBatch(
      group.value,
      group.type,
      group.assessment,
      group.results,
      result?.relationships,
      result?.provider_health,
      group.assessment?.task_id ?? group.results.find((item) => item.task_id)?.task_id
    );
    const bid = result?.batch_id ?? batchId;
    if (!bid) { navigateToLookup(group, fallback()); return; }
    setOpeningKey(group.key);
    try {
      const full = await getBatchIOCResult(bid, group.value);
      navigateToLookup(group, full);
    } catch {
      showToast("Could not load the full analysis; showing batch evidence only", "info");
      navigateToLookup(group, fallback());
    } finally {
      setOpeningKey(null);
    }
  }

  const handleRescanBatch = useCallback(async (customList?: string[]) => {
    const list = customList && customList.length > 0
      ? customList
      : result ? [...new Set(buildGroups(result).map((g) => `${g.type === "password" ? "password_sha1" : g.type}:${g.value}`))] : [];
    if (list.length === 0) return;
    setLoading(true);
    setBatchId(null);
    setStatus(null);
    setResult(null);
    setBatchFailure(null);
    setLoadingNotice("Starting re-scan…");
    try {
      const started = await startBatch(list);
      setBatchId(started.batch_id);
      await pollBatch(started.batch_id);
    } catch (error) {
      showToast(errorMessage(error, "Could not re-scan batch"), "error");
      setLoading(false);
      setLoadingNotice(null);
    }
  }, [pollBatch, result]);

  const handleRetryPoll = useCallback(async () => {
    if (!batchId) return;
    setLoading(true);
    await pollBatch(batchId);
  }, [batchId, pollBatch]);

  useEffect(() => {
    if (!autoRescan || !result || autoRescanTriggeredRef.current) return;
    autoRescanTriggeredRef.current = true;
    const list = [...new Set(buildGroups(result).map((g) => `${g.type === "password" ? "password_sha1" : g.type}:${g.value}`))];
    if (list.length > 0) {
      handleRescanBatch(list);
    }
  }, [autoRescan, result, handleRescanBatch]);

  const inputList = iocs.split("\n").map((value) => value.trim()).filter(Boolean);
  const overLimit = inputList.length > 100;
  const groups = useMemo(() => result ? buildGroups(result) : [], [result]);
  const providerOptions = useMemo(() => [...new Set(groups.flatMap((group) => [
    ...group.results.map((item) => item.source),
    ...(group.assessment?.provider_plan ?? []).map((item) => String(item.provider ?? "")),
  ].filter(Boolean)))].sort(), [groups]);
  const domainOptions = useMemo(() => [...new Set(groups.map((group) => domainFor(group.assessment)))].sort(), [groups]);
  // Only offer the verdict buckets that actually occur in this batch. A fixed
  // list means selecting "Malicious" on a batch of clean IOCs silently shows an
  // empty table with no indication that the bucket was simply absent, and a
  // bucket the backend can emit but the list omits is unreachable entirely.
  const verdictOptions = useMemo(() => {
    const present = new Set(groups.map((group) => verdictBucket(group.assessment?.final_verdict ?? "unknown")));
    return VERDICT_ORDER.filter((bucket) => present.has(bucket));
  }, [groups]);
  const visibleGroups = useMemo(() => {
    const filtered = groups.filter((group) => {
      const assessment = group.assessment;
      const verdict = verdictBucket(assessment?.final_verdict ?? "unknown");
      const lookupState = assessment ? statusFor(assessment) : "partial";
      const haystack = [group.value, group.type, domainFor(assessment), ...(assessment?.malware_families ?? []), ...(assessment?.mitre_attck ?? []), ...(assessment?.vulnerabilities ?? []).map((item) => JSON.stringify(item)), ...group.results.map((item) => item.source), ...(assessment?.provider_plan ?? []).map((item) => String(item.provider ?? ""))].join(" ").toLowerCase();
      return (!query || haystack.includes(query.toLowerCase()))
        && (verdictFilter === "all" || verdict === verdictFilter)
        && (domainFilter === "all" || domainFor(assessment) === domainFilter)
        && (typeFilter === "all" || group.type === typeFilter)
        && (providerFilter === "all" || group.results.some((item) => item.source === providerFilter) || (assessment?.provider_plan ?? []).some((item) => item.provider === providerFilter))
        && (statusFilter === "all" || lookupState === statusFilter)
        && providerIssueMatches(assessment, providerIssueFilter)
        && (confidenceFilter === "all" || assessment?.confidence === confidenceFilter)
        && (freshnessFilter === "all" || assessment?.freshness === freshnessFilter)
        && riskMatches(assessment?.normalized_score ?? 0, riskFilter)
        && (coverageFilter === "all" || (coverageFilter === "low" ? (assessment?.coverage ?? 0) < 0.5 : (assessment?.coverage ?? 0) >= 0.5))
        && (!malwareFilter || (assessment?.malware_families ?? []).some((family) => family.toLowerCase().includes(malwareFilter.toLowerCase())))
        && (!reviewOnly || Boolean(assessment?.needs_review));
    });
    return filtered.sort((left, right) => {
      if (sortBy === "coverage") return (left.assessment?.coverage ?? 0) - (right.assessment?.coverage ?? 0);
      if (sortBy === "risk") return (right.assessment?.normalized_score ?? 0) - (left.assessment?.normalized_score ?? 0);
      if (sortBy === "evidence") return (right.assessment?.evidence_strength ?? 0) - (left.assessment?.evidence_strength ?? 0);
      if (sortBy === "newest") return timestampFor(right) - timestampFor(left);
      if (sortBy === "oldest") return timestampFor(left) - timestampFor(right);
      if (sortBy === "duration") return Math.max(...right.results.map((item) => item.latency_ms ?? 0), 0) - Math.max(...left.results.map((item) => item.latency_ms ?? 0), 0);
      if (sortBy === "confidence") return ({ high: 0, medium: 1, low: 2 }[left.assessment?.confidence ?? "low"] ?? 2) - ({ high: 0, medium: 1, low: 2 }[right.assessment?.confidence ?? "low"] ?? 2);
      if (sortBy === "ioc") return left.value.localeCompare(right.value);
      const severity = (group: BatchGroup) => VERDICT_ORDER.indexOf(verdictBucket(group.assessment?.final_verdict ?? "unknown"));
      return severity(left) - severity(right);

    });
  }, [confidenceFilter, coverageFilter, domainFilter, freshnessFilter, groups, malwareFilter, providerFilter, providerIssueFilter, query, reviewOnly, riskFilter, sortBy, statusFilter, typeFilter, verdictFilter]);

  return (
    <div>
      <div className="mb-6"><h2 className="text-lg font-bold">Batch Processing</h2><p className="text-sm text-text-secondary">Analyze up to 100 IOCs. Results are grouped by unique IOC so provider evidence does not overwhelm the analyst view.</p></div>

      {batchFailure && !batchId && <div role="alert" className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-verdict-malicious/30 bg-verdict-malicious/10 px-4 py-3 text-sm"><span><span className="font-semibold text-verdict-malicious">Batch failed: </span><span className="text-text-secondary">{batchFailure}</span></span><button type="button" onClick={() => setBatchFailure(null)} className="rounded-md border border-border bg-bg-elevated px-3 py-1 text-xs text-text-secondary hover:text-text-primary">Dismiss</button></div>}

      {loadingNotice && !status && !result && !pollError && <div role="status" className="rounded-lg border border-border bg-bg-card p-6 text-center text-sm text-text-secondary">{loadingNotice}</div>}

      {!batchId && !loadingNotice && <div className="space-y-4"><label role="button" tabIndex={0} aria-label="Upload CSV or JSON file" className={`flex h-32 flex-col items-center justify-center rounded-lg border-2 border-dashed transition-colors focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent ${dragOver ? "border-accent bg-accent/5" : "border-border hover:border-accent/50"}`} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); (event.currentTarget.querySelector("input[type=file]") as HTMLInputElement | null)?.click(); } }} onDragOver={(event) => { event.preventDefault(); setDragOver(true); }} onDragLeave={() => setDragOver(false)} onDrop={(event) => { event.preventDefault(); setDragOver(false); const file = event.dataTransfer.files?.[0]; if (file) { const dataTransfer = new DataTransfer(); dataTransfer.items.add(file); handleFileUpload({ target: { files: dataTransfer.files } } as React.ChangeEvent<HTMLInputElement>); } }}><svg className="mb-2 h-8 w-8 text-text-secondary" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" /></svg><span className="text-xs text-text-secondary">Drop CSV/JSON/TXT file or click to browse</span><input type="file" accept=".csv,.json,.txt" onChange={handleFileUpload} className="hidden" /></label><div><textarea value={iocs} onChange={(event) => setIocs(event.target.value)} placeholder={"Paste IOCs here, one per line — auto-detected or typed:\n185.199.108.153\nexample.com\ndomain:eclipsemanic.me\nip:8.8.8.8\nsha256:d41d8cd98f00b204e9800998ecf8427e..."} className="h-40 w-full resize-y rounded-lg border border-border bg-bg-card px-4 py-3 font-mono text-sm text-text-primary outline-none transition-all placeholder-text-secondary focus:border-accent focus:ring-1 focus:ring-accent" disabled={loading} /><div className="mt-1.5 rounded-md border border-accent/20 bg-accent/5 px-3 py-1.5 text-xs text-text-secondary"><span className="font-semibold text-accent">?? Typed prefixes:</span> Force IOC type with <code className="rounded bg-bg-elevated px-1 py-0.5 font-mono text-accent">type:value</code> syntax — e.g. <code className="rounded bg-bg-elevated px-1 py-0.5 font-mono">domain:eclipsemanic.me</code>, <code className="rounded bg-bg-elevated px-1 py-0.5 font-mono">ip:1.1.1.1</code>, <code className="rounded bg-bg-elevated px-1 py-0.5 font-mono">cve:CVE-2021-44228</code>, <code className="rounded bg-bg-elevated px-1 py-0.5 font-mono">sha256:abc123…</code></div><div className="mt-2 flex items-center justify-between"><span className={`text-xs font-mono ${overLimit ? "text-verdict-malicious" : "text-text-secondary"}`}>{inputList.length} IOC{inputList.length !== 1 ? "s" : ""}{overLimit ? " (max 100)" : ""}</span><button onClick={handleSubmit} disabled={loading || inputList.length === 0 || overLimit} className="rounded-lg bg-accent px-5 py-2 text-sm font-medium text-[#06070d] transition-colors hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-40">{loading ? "Starting..." : "Analyze Batch"}</button></div></div></div>}

      {status && !result && !pollError && <div className="rounded-lg border border-border bg-bg-card p-6 text-center"><div role="progressbar" aria-label="Batch progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(count(status.progress))} className="mb-4 h-2 w-full rounded-full bg-bg-elevated"><div className="h-2 rounded-full bg-gradient-to-r from-accent to-accent-secondary transition-all duration-500" style={{ width: `${Math.max(0, Math.min(100, count(status.progress)))}%` }} /></div><p className="text-sm text-text-secondary" aria-live="polite">Processing {count(status.completed)}/{count(status.total)} IOCs…</p><p className="mt-1 text-xs text-text-secondary">{count(status.progress) > 0 && count(status.expected_lookups) > 0 ? `${count(status.progress).toFixed(0)}% complete · ${count(status.completed_lookups)}/${count(status.expected_lookups)} provider lookups` : status.active_iocs?.length ? `Analyzing ${status.active_iocs.length} IOC${status.active_iocs.length === 1 ? "" : "s"} · provider plan in progress…` : "Preparing provider plans…"}</p><button onClick={async () => { if (!batchId) return; try { await cancelBatch(batchId); showToast("Batch cancellation requested", "info"); } catch (error) { showToast(errorMessage(error, "Could not cancel batch"), "error"); } }} className="mt-4 rounded-md border border-border bg-bg-elevated px-3 py-1.5 text-xs text-text-secondary transition-colors hover:border-red-400/40 hover:text-red-400">Cancel Batch</button></div>}

      {pollError && !result && <div className="rounded-lg border border-verdict-malicious/30 bg-verdict-malicious/10 p-6 text-center"><p className="mb-2 font-medium text-verdict-malicious">Batch polling interrupted</p><p className="mb-4 text-sm text-text-secondary">{pollError}</p><div className="flex justify-center gap-2"><button onClick={handleRetryPoll} disabled={loading || !batchId} className="rounded-lg bg-accent px-4 py-1.5 text-sm text-[#06070d] transition-colors hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-40">{loading ? "Retrying…" : "Retry"}</button><button onClick={clearBatch} className="rounded-lg border border-border bg-bg-elevated px-4 py-1.5 text-sm text-text-secondary transition-colors hover:text-text-primary">New Batch</button></div></div>}

      {result && <div className="space-y-5"><BatchSummary result={result} groups={groups} /><div className="flex flex-wrap items-center justify-between gap-2"><div><h3 className="text-sm font-semibold uppercase tracking-wider text-text-secondary">IOC assessments</h3><p className="mt-1 text-xs text-text-secondary">Showing {visibleGroups.length} of {groups.length} unique IOCs · each card contains all provider evidence.</p></div><div className="flex gap-2"><button onClick={() => setExpandAll((value) => !value)} className="rounded-md border border-border bg-bg-elevated px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary">{expandAll ? "Collapse all evidence" : "Expand all evidence"}</button><button onClick={() => handleRescanBatch()} disabled={loading} className="rounded-md border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-semibold text-accent hover:bg-accent/20 transition-colors">Re-scan Batch</button><button onClick={() => { const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" }); const url = URL.createObjectURL(blob); const anchor = document.createElement("a"); anchor.href = url; anchor.download = "batch-results.json"; anchor.click(); URL.revokeObjectURL(url); }} className="rounded-md bg-accent px-3 py-1.5 text-xs text-[#06070d] hover:bg-accent/90">Download JSON</button><button onClick={clearBatch} className="rounded-md border border-border bg-bg-elevated px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary">New Batch</button></div></div>

        <section className="rounded-lg border border-border bg-bg-card p-3"><div className="grid grid-cols-1 gap-2 md:grid-cols-2 lg:grid-cols-4"><input aria-label="Search indicators" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search IOC, type, provider, family" className="rounded-md border border-border bg-bg-elevated px-3 py-2 text-xs text-text-primary outline-none focus:border-accent" /><select aria-label="Filter by verdict" value={verdictFilter} onChange={(event) => setVerdictFilter(event.target.value)} className="rounded-md border border-border bg-bg-elevated px-3 py-2 text-xs text-text-primary"><option value="all">All verdicts</option>{verdictOptions.map((bucket) => <option key={bucket} value={bucket}>{verdictLabel(bucket)}</option>)}</select><select aria-label="Filter by assessment domain" value={domainFilter} onChange={(event) => setDomainFilter(event.target.value)} className="rounded-md border border-border bg-bg-elevated px-3 py-2 text-xs text-text-primary"><option value="all">All assessment domains</option>{domainOptions.map((domain) => <option key={domain} value={domain}>{domain.replace(/_/g, " ")}</option>)}</select><select aria-label="Filter by IOC type" value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)} className="rounded-md border border-border bg-bg-elevated px-3 py-2 text-xs text-text-primary"><option value="all">All IOC types</option>{[...new Set(groups.map((group) => group.type))].sort().map((type) => <option key={type} value={type}>{type}</option>)}</select><select aria-label="Filter by provider" value={providerFilter} onChange={(event) => setProviderFilter(event.target.value)} className="rounded-md border border-border bg-bg-elevated px-3 py-2 text-xs text-text-primary"><option value="all">All providers</option>{providerOptions.map((provider) => <option key={provider} value={provider}>{provider}</option>)}</select><select aria-label="Filter by provider issue" value={providerIssueFilter} onChange={(event) => setProviderIssueFilter(event.target.value)} className="rounded-md border border-border bg-bg-elevated px-3 py-2 text-xs text-text-primary"><option value="all">All provider outcomes</option><option value="any">Any provider failed</option><option value="rate_limited">Any provider rate limited</option><option value="unavailable">Any provider unavailable</option><option value="error">Any provider errored</option><option value="none">No provider failed</option></select><select aria-label="Filter by lookup status" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} className="rounded-md border border-border bg-bg-elevated px-3 py-2 text-xs text-text-primary"><option value="all">All lookup status</option><option value="complete">Complete</option><option value="partial">Partial</option><option value="rate_limited">Rate limited</option><option value="not_applicable">Not applicable</option><option value="unavailable">Unavailable</option><option value="error">Error</option><option value="cancelled">Cancelled</option><option value="batch_deadline_exceeded">Deadline exceeded</option></select><select aria-label="Filter by confidence" value={confidenceFilter} onChange={(event) => setConfidenceFilter(event.target.value)} className="rounded-md border border-border bg-bg-elevated px-3 py-2 text-xs text-text-primary"><option value="all">All confidence</option><option value="high">High confidence</option><option value="medium">Medium confidence</option><option value="low">Low confidence</option></select><select aria-label="Filter by freshness" value={freshnessFilter} onChange={(event) => setFreshnessFilter(event.target.value)} className="rounded-md border border-border bg-bg-elevated px-3 py-2 text-xs text-text-primary"><option value="all">All freshness</option><option value="fresh">Fresh</option><option value="cached">Cached</option><option value="historical">Historical</option><option value="unavailable">Unavailable</option></select><select aria-label="Filter by risk band" value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)} className="rounded-md border border-border bg-bg-elevated px-3 py-2 text-xs text-text-primary"><option value="all">All risk scores</option><option value="high">High risk (70+)</option><option value="medium">Medium risk (30-69)</option><option value="low">Low risk (&lt;30)</option></select><select aria-label="Filter by coverage" value={coverageFilter} onChange={(event) => setCoverageFilter(event.target.value)} className="rounded-md border border-border bg-bg-elevated px-3 py-2 text-xs text-text-primary"><option value="all">All coverage</option><option value="low">Low coverage (&lt;50%)</option><option value="adequate">Adequate coverage</option></select><input aria-label="Filter by malware family" value={malwareFilter} onChange={(event) => setMalwareFilter(event.target.value)} placeholder="Malware family" className="rounded-md border border-border bg-bg-elevated px-3 py-2 text-xs text-text-primary outline-none focus:border-accent" /><select aria-label="Sort results by" value={sortBy} onChange={(event) => setSortBy(event.target.value)} className="rounded-md border border-border bg-bg-elevated px-3 py-2 text-xs text-text-primary"><option value="severity">Sort: severity</option><option value="risk">Sort: highest risk</option><option value="evidence">Sort: evidence strength</option><option value="coverage">Sort: lowest coverage</option><option value="confidence">Sort: confidence</option><option value="newest">Sort: newest observation</option><option value="oldest">Sort: oldest observation</option><option value="duration">Sort: slowest provider</option><option value="ioc">Sort: IOC value</option></select><label className="flex items-center gap-2 rounded-md border border-border bg-bg-elevated px-3 py-2 text-xs text-text-secondary"><input type="checkbox" aria-label="Show only indicators needing review" checked={reviewOnly} onChange={(event) => setReviewOnly(event.target.checked)} /> Needs analyst review</label></div></section>

        <div className="space-y-3">{visibleGroups.length === 0 ? <div className="rounded-lg border border-border bg-bg-card p-8 text-center text-sm text-text-secondary">No IOCs match the current filters.</div> : visibleGroups.map((group) => group.assessment ? <div key={group.key} className="relative">{openingKey === group.key && <div className="absolute inset-0 z-10 flex items-center justify-center rounded-xl bg-bg-card/70 backdrop-blur-[1px]" aria-live="polite"><span className="rounded-md border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-semibold text-accent">Loading full analysis…</span></div>}<IocAssessmentCard assessment={group.assessment} results={group.results} forceExpanded={expandAll} onOpen={() => { void handleOpenGroup(group); }} /></div> : <UnassessedGroup key={group.key} group={group} />)}</div>
      </div>}
    </div>
  );
}
