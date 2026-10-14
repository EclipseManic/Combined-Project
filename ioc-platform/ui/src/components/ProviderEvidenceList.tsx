import { useMemo, useState } from "react";
import type { GroupedProviders, ProviderRow } from "../lib/providerEvidence";
import { STATE_LABELS } from "../lib/providerEvidence";
import { titleCase } from "../lib/format";
import SourceCard from "./SourceCard";

function matches(row: ProviderRow, query: string): boolean {
  if (!query) return true;
  const haystack = [row.source, row.result?.provider_summary ?? "", row.reason ?? "", row.verdict].join(" ").toLowerCase();
  return haystack.includes(query);
}

function SectionHeading({ title, count, hint }: { title: string; count: number; hint: string }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-2 px-1">
      <h4 className="text-xs font-bold uppercase tracking-[0.14em] text-text-primary">
        {title} <span className="ml-1 font-mono text-text-secondary">{count}</span>
      </h4>
      <span className="text-xs text-text-secondary">{hint}</span>
    </div>
  );
}

function CompactRow({ row, tone }: { row: ProviderRow; tone: "neutral" | "problem" }) {
  const summary = tone === "problem"
    ? row.reason ?? titleCase(row.state)
    : row.result?.provider_summary?.trim() || "No matching record";
  return (
    <li className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-xs">
      <span className="font-semibold text-text-primary">{row.source}</span>
      <span className={`min-w-0 flex-1 text-right ${tone === "problem" ? "text-amber-200/90" : "text-text-secondary"}`}>
        {summary}
      </span>
      {row.result?.cached && <span className="text-xs uppercase tracking-wider text-text-secondary">cached</span>}
    </li>
  );
}

/**
 * Provider evidence in analyst reading order: findings, context, not found,
 * then provider problems (collapsed). Not-applicable providers are never listed.
 */
export default function ProviderEvidenceList({
  grouped,
  emptyFindingsText,
}: {
  grouped: GroupedProviders;
  emptyFindingsText: string;
}) {
  const [query, setQuery] = useState("");
  const normalizedQuery = query.trim().toLowerCase();
  const view = useMemo(() => ({
    findings: grouped.findings.filter((row) => matches(row, normalizedQuery)),
    context: grouped.context.filter((row) => matches(row, normalizedQuery)),
    notFound: grouped.notFound.filter((row) => matches(row, normalizedQuery)),
    problems: grouped.problems.filter((row) => matches(row, normalizedQuery)),
  }), [grouped, normalizedQuery]);
  const total = grouped.findings.length + grouped.context.length + grouped.notFound.length + grouped.problems.length;
  const problemSummary = useMemo(() => {
    const counts = new Map<string, number>();
    for (const row of grouped.problems) {
      const label = STATE_LABELS[row.state] ?? titleCase(row.state);
      counts.set(label, (counts.get(label) ?? 0) + 1);
    }
    return [...counts.entries()].map(([label, count]) => `${count} ${label.toLowerCase()}`).join(" · ");
  }, [grouped.problems]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-bg-card px-3 py-2.5">
        <div>
          <h3 className="text-xs font-bold uppercase tracking-[0.14em] text-text-primary">Provider evidence</h3>
          <p className="mt-0.5 text-xs text-text-secondary">
            {grouped.findings.length} with findings · {grouped.context.length} context · {grouped.notFound.length} not found · {grouped.problems.length} could not answer
          </p>
        </div>
        {total > 6 && (
          <input
            type="search"
            placeholder="Filter providers…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            aria-label="Filter providers"
            className="w-40 rounded-lg border border-border bg-bg-elevated px-2.5 py-1 text-xs text-text-primary placeholder:text-text-secondary/60 focus:border-accent focus:outline-none sm:w-48"
          />
        )}
      </div>

      <section className="space-y-1.5" aria-label="Provider findings">
        <SectionHeading title="Findings" count={view.findings.length} hint="positive and negative provider verdicts" />
        {view.findings.length > 0 ? (
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2 2xl:grid-cols-3">
            {view.findings.map((row) =>
              row.result ? (
                <SourceCard key={row.source} result={row.result} observation={row.observation} group="finding" />
              ) : (
                <div key={row.source} className="rounded-xl border border-border bg-bg-card p-3 text-xs">
                  <span className="font-semibold">{row.source}</span>
                  <span className="ml-2 text-text-secondary">{row.observation?.reason || titleCase(row.verdict)}</span>
                </div>
              ),
            )}
          </div>
        ) : (
          <p className="rounded-xl border border-border bg-bg-card px-4 py-3 text-xs text-text-secondary">
            {normalizedQuery ? "No provider findings match the filter." : emptyFindingsText}
          </p>
        )}
      </section>

      {view.context.length > 0 && (
        <section className="space-y-1.5" aria-label="Context providers">
          <SectionHeading title="Context" count={view.context.length} hint="infrastructure and enrichment; does not score" />
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2 2xl:grid-cols-3">
            {view.context.map((row) =>
              row.result ? (
                <SourceCard key={row.source} result={row.result} observation={row.observation} group="context" />
              ) : null,
            )}
          </div>
        </section>
      )}

      {view.notFound.length > 0 && (
        <section className="space-y-1.5" aria-label="Providers without a record">
          <SectionHeading title="Not found" count={view.notFound.length} hint="no record — not evidence of benignness" />
          <ul className="divide-y divide-border/60 rounded-xl border border-border bg-bg-card">
            {view.notFound.map((row) => <CompactRow key={row.source} row={row} tone="neutral" />)}
          </ul>
        </section>
      )}

      {view.problems.length > 0 && (
        <details className="rounded-xl border border-amber-500/30 bg-amber-500/5" aria-label="Provider problems">
          <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-2 px-4 py-3">
            <span className="text-xs font-bold uppercase tracking-[0.14em] text-amber-200">
              Provider problems <span className="ml-1 font-mono">{view.problems.length}</span>
            </span>
            <span className="text-xs text-text-secondary">{problemSummary} — excluded from the verdict</span>
          </summary>
          <ul className="divide-y divide-border/60 border-t border-amber-500/20">
            {view.problems.map((row) => <CompactRow key={row.source} row={row} tone="problem" />)}
          </ul>
        </details>
      )}
    </div>
  );
}
