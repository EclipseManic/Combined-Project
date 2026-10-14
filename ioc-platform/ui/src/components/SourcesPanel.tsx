import { useEffect, useMemo, useState } from "react";
import type { LookupResponse, NormalizedResult, SourceInventoryItem } from "../services/api";
import { getSourceInventory } from "../services/api";
import { formatDateTime, formatDuration } from "../lib/format";
import { buildProviderRows, executionState, groupProviderRows, problemReason, type GroupedProviders, type ProviderRow } from "../lib/providerEvidence";
import { buildCredentialAudit, idleKeys, REASON_LABEL, type UnusedReason } from "../lib/credentials";
import { buildPayloadSections, countPayloadFields } from "../lib/rawPayload";
import PayloadFields from "./PayloadFields";
import { TagList } from "./Tag";
import { tidyTags } from "../lib/providerEvidence";

function StatePill({ value }: { value: string }) {
  const state = value.toLowerCase();
  const style =
    state === "success" || state === "found"
      ? "text-verdict-clean border-verdict-clean/30 bg-verdict-clean/10"
      : state === "not_found"
        ? "text-text-secondary border-border bg-bg-elevated"
        : state === "not_applicable"
          ? "text-cyan-300 border-cyan-500/30 bg-cyan-500/10"
          : "text-verdict-malicious border-verdict-malicious/30 bg-verdict-malicious/10";
  return (
    <span className={`text-xs uppercase font-semibold px-1.5 py-0.5 rounded border ${style}`}>
      {value.replace(/_/g, " ")}
    </span>
  );
}

const REASON_STYLE: Record<UnusedReason, string> = {
  key_missing: "border-amber-500/40 bg-amber-500/10 text-amber-200",
  not_queried: "border-sky-500/40 bg-sky-500/10 text-sky-200",
  call_failed: "border-rose-500/40 bg-rose-500/10 text-rose-200",
  not_applicable: "border-border bg-bg-elevated text-text-secondary",
};

/**
 * One provider's complete story: what it was asked, what it answered, and the
 * data it returned — with the raw JSON kept one click away rather than being the
 * only way in.
 */
function ProviderEntry({ row }: { row: ProviderRow }) {
  const [showJson, setShowJson] = useState(false);
  const result = row.result;
  const state = row.state;
  const answered = state === "success" || state === "found" || state === "not_found";
  const fieldCount = countPayloadFields(buildPayloadSections(result?.raw_data));
  const { chips } = tidyTags(result?.tags);

  return (
    // Collapsed by default: this tab is an audit surface with potentially 30
    // providers, so an accordion the analyst opens deliberately beats a wall of
    // pre-expanded cards. The field count in the header says whether it is worth
    // opening.
    <details className="rounded-xl border border-border bg-bg-card">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-xs font-semibold select-none hover:bg-bg-elevated/30 rounded-xl">
        <div className="flex min-w-0 items-center gap-2.5">
          <span className="text-accent font-bold shrink-0">{row.source}</span>
          <StatePill value={state} />
          {answered ? (
            <span className="text-xs font-normal text-text-secondary truncate">
              {row.verdict}
              {result?.confidence ? ` · ${result.confidence} confidence` : ""}
            </span>
          ) : (
            <span className="text-xs font-normal text-amber-200/90 truncate">{row.reason}</span>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-2 text-xs text-text-secondary font-mono">
          {fieldCount > 0 && <span>{fieldCount} fields</span>}
          {result?.latency_ms != null && <span>{formatDuration(result.latency_ms)}</span>}
          {result?.cached && <span>{result.stale ? "stale" : "cached"}</span>}
        </div>
      </summary>

      <div className="space-y-3 border-t border-border px-4 py-3">
        {result?.provider_summary && (
          <p className="text-xs text-text-primary">
            <span className="font-semibold text-accent">Provider finding: </span>
            {result.provider_summary}
          </p>
        )}

        <p className="text-xs text-text-secondary">
          {result?.cached ? `Cached${result.cache_age != null ? ` ${Math.round(result.cache_age / 60)}m old` : ""}` : "Fresh lookup"}
          {result?.latency_ms != null ? ` · ${formatDuration(result.latency_ms)}` : ""}
          {(result?.retry_count ?? 0) > 0 ? ` · ${result?.retry_count} retries` : ""}
          {result?.source_timestamp ? ` · source time: ${formatDateTime(result.source_timestamp)}` : ""}
          {result?.provenance_family ? ` · provenance: ${result.provenance_family}` : ""}
          {result?.assessment_domain ? ` · domain: ${result.assessment_domain}` : ""}
          {result?.reports_count != null ? ` · ${result.reports_count} reports` : ""}
        </p>

        {!answered && <p className="text-xs text-amber-200/90">{problemReason(result ?? undefined, row.observation)}</p>}

        {chips.length > 0 && <TagList labels={chips} max={8} />}

        {fieldCount > 0 ? (
          <div className="rounded-lg border border-border bg-bg-elevated/40 p-3">
            <PayloadFields raw={result?.raw_data} />
          </div>
        ) : (
          <p className="text-xs italic text-text-secondary">
            {answered ? "No structured payload returned." : "No payload — the provider did not answer."}
          </p>
        )}

        {result?.raw_data && Object.keys(result.raw_data).length > 0 && (
          <div>
            <button
              type="button"
              onClick={(event) => {
                event.preventDefault();
                setShowJson((value) => !value);
              }}
              className="rounded-md border border-border bg-bg-elevated px-2.5 py-1.5 text-xs font-semibold text-text-secondary hover:border-accent/50 hover:text-accent transition-colors"
            >
              {showJson ? "Hide raw JSON" : "Raw JSON"}
            </button>
            {showJson && (
              <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-border bg-[#080b12] p-3 font-mono text-xs leading-relaxed text-slate-300">
                {JSON.stringify(result.raw_data, null, 2)}
              </pre>
            )}
          </div>
        )}
      </div>
    </details>
  );
}

function GroupBlock({ title, rows, tone }: { title: string; rows: ProviderRow[]; tone: string }) {
  if (rows.length === 0) return null;
  return (
    <section className="space-y-2">
      <h4 className={`text-xs font-semibold uppercase tracking-wider ${tone}`}>
        {title} ({rows.length})
      </h4>
      {rows.map((row) => (
        <ProviderEntry key={row.source} row={row} />
      ))}
    </section>
  );
}

export default function SourcesPanel({ result }: { result: LookupResponse }) {
  const [inventory, setInventory] = useState<SourceInventoryItem[]>([]);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    getSourceInventory().then((data) => setInventory(data.sources)).catch(() => setInventory([]));
  }, []);

  const results: NormalizedResult[] = useMemo(
    () => (Array.isArray(result.results) ? result.results : []),
    [result.results],
  );
  const grouped: GroupedProviders = useMemo(
    () => groupProviderRows(buildProviderRows(results, result.final_assessment?.provider_breakdown)),
    [results, result.final_assessment?.provider_breakdown],
  );

  const notApplicableNames = useMemo(() => {
    const fromResults = results
      .filter((item) => executionState(item) === "not_applicable")
      .map((item) => item.source);
    if (fromResults.length > 0) return fromResults;
    return (result.final_assessment?.provider_plan ?? [])
      .filter((item) => item.applicable === false)
      .map((item) => String(item.provider ?? ""));
  }, [results, result.final_assessment?.provider_plan]);

  const audit = useMemo(
    () => buildCredentialAudit(inventory, grouped, result.ioc_type, notApplicableNames),
    [inventory, grouped, result.ioc_type, notApplicableNames],
  );

  const idle = idleKeys(audit);
  // call_failed entries are already rendered in their own list above, so they
  // must not be repeated here.
  const actionable = audit.unused.filter((item) => item.reason !== "not_applicable" && item.reason !== "call_failed");
  const answered = grouped.findings.length + grouped.context.length + grouped.notFound.length;
  const coverage = Number(result.final_assessment?.coverage);
  // Sources that cannot handle this IOC type but hold a valid key: not a gap in
  // this result, but still an idle credential the analyst may want to know about.
  const idleNotApplicable = audit.unused.filter(
    (item) => item.reason === "not_applicable" && (inventory.find((entry) => entry.name === item.name)?.configured ?? false),
  );

  const matches = (source: string) => !filter.trim() || source.toLowerCase().includes(filter.trim().toLowerCase());
  const shown = {
    findings: grouped.findings.filter((row) => matches(row.source)),
    context: grouped.context.filter((row) => matches(row.source)),
    notFound: grouped.notFound.filter((row) => matches(row.source)),
    problems: grouped.problems.filter((row) => matches(row.source)),
  };

  return (
    <div className="space-y-5">
      {/* 1. What happened, in one glance. */}
      <section className="rounded-xl border border-border bg-bg-card p-4">
        <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-text-secondary">Sources at a glance</h3>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          {[
            { value: answered, label: "answered" },
            { value: grouped.findings.length, label: "findings" },
            { value: grouped.notFound.length, label: "no record" },
            { value: grouped.problems.length, label: "failed" },
            { value: audit.notApplicable.length, label: "not applicable" },
            { value: audit.missing.length, label: "keys missing" },
          ].map((item) => (
            <div key={item.label}>
              <div className="text-xl font-semibold">{item.value}</div>
              <div className="text-xs text-text-secondary">{item.label}</div>
            </div>
          ))}
        </div>
        {result.final_assessment && (
          <p className="mt-3 text-xs text-text-secondary">
            Coverage: <span className="text-text-primary">{Number.isFinite(coverage) ? `${Math.round(coverage * 100)}%` : "—"}</span>{" "}
            · cache status: <span className="text-text-primary">{result.final_assessment.cache_status}</span>{" "}
            · of <span className="text-text-primary">{inventory.length || audit.keyed.length + audit.notApplicable.length}</span> registered sources
          </p>
        )}
        <p className="mt-2 text-xs text-text-secondary">
          A missing, rate-limited or unavailable result is not proof of safety. Evidence is source-specific and time-sensitive.
        </p>
      </section>

      {/* 2. The audit question: what did we not ask, and why? */}
      {(actionable.length > 0 || audit.failed.length > 0) && (
        <section className="rounded-xl border border-amber-500/30 bg-amber-950/10 p-4" aria-label="Unused credentials">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-amber-200">
            Credentials not used for this lookup ({actionable.length + audit.failed.length})
          </h3>
          <p className="mt-1 text-xs text-amber-200/80">
            These sources did not contribute to this result. A source that silently never ran looks identical to one that
            ran and found nothing, so the difference is listed explicitly.
          </p>
          <div className="mt-3 space-y-2">
            {actionable.map((item) => (
              <div key={`unused-${item.name}`} className="flex flex-wrap items-center gap-2 text-xs">
                <span className="font-semibold text-amber-100">{item.name}</span>
                <span className={`rounded border px-1.5 py-0.5 text-xs uppercase font-semibold ${REASON_STYLE[item.reason]}`}>
                  {REASON_LABEL[item.reason]}
                </span>
                {item.credentialEnv && (
                  <code className="rounded bg-bg-elevated px-1.5 py-0.5 text-xs text-text-secondary">{item.credentialEnv}</code>
                )}
                <span className="text-amber-200/80">{item.detail}</span>
              </div>
            ))}
            {audit.failed.map((source) => (
              <div key={`failed-${source}`} className="flex flex-wrap items-center gap-2 text-xs">
                <span className="font-semibold text-rose-200">{source}</span>
                <span className={`rounded border px-1.5 py-0.5 text-xs uppercase font-semibold ${REASON_STYLE.call_failed}`}>
                  {REASON_LABEL.call_failed}
                </span>
                <span className="text-rose-200/80">Key is configured and was spent, but the lookup did not complete.</span>
              </div>
            ))}
            {actionable.length === 0 && audit.failed.length === 0 && (
              <p className="text-xs text-amber-200/80">No credential gaps for this indicator type.</p>
            )}
          </div>
          {idle.length > 0 && (
            <p className="mt-3 text-xs text-amber-200/90">
              {idle.filter((item) => item.reason === "key_missing").length} source(s) would add coverage if their key were
              set; {idle.filter((item) => item.reason === "not_queried").length} hold a valid key but were not queried.
            </p>
          )}
        </section>
      )}

      {/* 3. Every provider that ran, with the data it returned. */}
      <section className="space-y-2" aria-label="Provider responses">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
            Provider responses ({answered + grouped.problems.length})
          </h3>
          <input
            type="text"
            placeholder="Filter providers..."
            aria-label="Filter providers"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            className="w-56 rounded-lg border border-border bg-bg-elevated px-3 py-1.5 text-xs text-text-primary placeholder:text-text-secondary/60 focus:border-accent focus:outline-none"
          />
        </div>
        {answered + grouped.problems.length === 0 ? (
          <p className="rounded-xl border border-border bg-bg-card p-4 text-sm text-text-secondary">
            No provider produced a response for this indicator.
          </p>
        ) : (
          <div className="space-y-4">
            <GroupBlock title="Findings" rows={shown.findings} tone="text-text-secondary" />
            <GroupBlock title="Context" rows={shown.context} tone="text-sky-300" />
            <GroupBlock title="No record (not evidence of benignness)" rows={shown.notFound} tone="text-text-secondary" />
            <GroupBlock title="Failed / unavailable" rows={shown.problems} tone="text-verdict-malicious" />
          </div>
        )}
      </section>

      {/* 4. Sources ruled out by capability. */}
      {audit.notApplicable.length > 0 && (
        <details className="rounded-xl border border-border bg-bg-card">
          <summary className="cursor-pointer px-4 py-3 text-xs font-semibold uppercase tracking-wider text-cyan-300">
            Not applicable for {result.ioc_type} ({audit.notApplicable.length})
          </summary>
          <div className="space-y-2 border-t border-border p-3">
            {idleNotApplicable.length > 0 && (
              <p className="text-xs text-cyan-200/80">
                {idleNotApplicable.length} of these hold a configured key that was not spent on this lookup, because
                they do not handle {result.ioc_type}: {idleNotApplicable.map((item) => item.name).join(", ")}.
              </p>
            )}
            <div className="flex flex-wrap gap-1">
            {audit.notApplicable
              .filter((name) => matches(name))
              .map((name) => (
                <span key={name} className="rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 text-xs uppercase font-semibold text-cyan-300">
                  {name}
                </span>
              ))}
            </div>
          </div>
        </details>
      )}

      {/* 5. Per-provider request accounting. */}
      {result.provider_health && result.provider_health.length > 0 && (
        <section className="rounded-xl border border-border bg-bg-card p-4">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-text-secondary">Request accounting</h3>
          <div className="space-y-1">
            {result.provider_health.map((item) => (
              <div key={item.source} className="flex flex-wrap items-center justify-between gap-2 text-xs">
                <span>{item.source}</span>
                <span className="text-text-secondary">
                  {item.request_count} attempts · {item.success_count} observations · {item.failure_count} failures
                  {item.rate_limit_count ? ` · ${item.rate_limit_count} rate-limited` : ""}
                  {item.cache_hit_count ? ` · ${item.cache_hit_count} cache hits` : ""}
                </span>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
