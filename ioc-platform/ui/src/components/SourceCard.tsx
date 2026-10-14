import { useState } from "react";
import type { EvidenceObservation, NormalizedResult } from "../services/api";
import { formatDate, formatDuration, formatValue, titleCase } from "../lib/format";
import { EVIDENCE_CLASS_LABELS, tidyTags, type ProviderGroup } from "../lib/providerEvidence";
import { getVerdictBand } from "../lib/verdictColors";
import { TagList } from "./Tag";
import { buildPayloadSections, countPayloadFields } from "../lib/rawPayload";
import VerdictBadge from "./VerdictBadge";


function cardTone(group: ProviderGroup, verdict: string, evidenceClass?: string): { border: string; dot: string } {
  if (group === "context") return { border: "border-sky-500/50", dot: "bg-sky-400" };
  if (group !== "finding") return { border: "border-slate-700", dot: "bg-slate-500" };
  if (evidenceClass === "test_artifact") return { border: "border-blue-500/50", dot: "bg-blue-400" };
  if (evidenceClass === "conflicting") return { border: "border-amber-500/70", dot: "bg-amber-400" };
  if (evidenceClass === "related_indicator" || evidenceClass === "anonymization" || evidenceClass === "exposure_context") {
    return { border: "border-sky-500/50", dot: "bg-sky-400" };
  }
  if (evidenceClass === "credential_exposure") return { border: "border-rose-500/70", dot: "bg-rose-400" };
  const band = getVerdictBand(verdict);
  if (band === "malicious") return { border: "border-red-500/70", dot: "bg-red-400" };
  if (band === "suspicious") return { border: "border-amber-500/70", dot: "bg-amber-400" };
  if (band === "benign") return { border: "border-emerald-500/60", dot: "bg-emerald-400" };
  return { border: "border-slate-600", dot: "bg-slate-400" };
}

function summaryLine(result: NormalizedResult, verdict: string): string {
  if (result.provider_summary?.trim()) return result.provider_summary.trim();
  if (result.detection_count != null && result.total_engines) return `${result.detection_count}/${result.total_engines} engines flagged`;
  if (result.reports_count != null) return `${result.reports_count} report${result.reports_count === 1 ? "" : "s"} returned`;
  return verdict === "unknown" ? "Provider returned context" : `Provider verdict: ${titleCase(verdict)}`;
}

function rawValue(result: NormalizedResult, keys: string[]): string | null {
  for (const key of keys) {
    const value = result.raw_data?.[key];
    if (value !== null && value !== undefined && value !== "" && typeof value !== "object") return String(value);
  }
  return null;
}

export default function SourceCard({
  result,
  observation,
  group = "finding",
}: {
  result: NormalizedResult;
  observation?: EvidenceObservation;
  group?: ProviderGroup;
}) {
  const [expanded, setExpanded] = useState(false);
  const [showJson, setShowJson] = useState(false);
  const verdict = (observation?.normalized_verdict || result.normalized_verdict || result.verdict || "unknown").toLowerCase();
  const evidenceClass = observation?.evidence_class;
  const tone = cardTone(group, verdict, evidenceClass);
  const family = result.malware_family || rawValue(result, ["family", "malware_family", "threat_name"]);
  const details = [
    result.detection_count != null && result.total_engines ? `${result.detection_count}/${result.total_engines} engines` : null,
    family ? `Family: ${family}` : null,
    result.reports_count != null ? `${result.reports_count} reports` : null,
    result.first_seen ? `First seen ${formatDate(result.first_seen)}` : null,
    result.last_seen ? `Last seen ${formatDate(result.last_seen)}` : null,
  ].filter((item): item is string => Boolean(item) && !String(item).includes("—"));
  const { chips, attributes } = tidyTags(result.tags);
  const hasRaw = Object.keys(result.raw_data ?? {}).length > 0;
  const badgeVerdict = group === "context" ? "context_only" : verdict;
  const badgeLabel = group === "context" ? "context" : undefined;
  const evidenceLabel = evidenceClass ? EVIDENCE_CLASS_LABELS[evidenceClass] : undefined;
  const fieldCount = countPayloadFields(buildPayloadSections(result.raw_data));

  return (
    <article className={`flex h-full flex-col overflow-hidden rounded-lg border-l-2 border-y border-r bg-bg-card transition-colors ${tone.border}`}>
      <div className="p-2.5">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-1.5">
              <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${tone.dot}`} />
              <h3 className="truncate text-sm font-semibold leading-tight text-text-primary">{result.source}</h3>
              {evidenceLabel && group === "finding" && (
                <span className="text-xs uppercase tracking-wider text-text-secondary">{evidenceLabel}</span>
              )}
            </div>
            <p className="mt-1 text-xs leading-snug text-text-primary">{summaryLine(result, verdict)}</p>
            {details.length > 0 && <p className="mt-0.5 line-clamp-1 text-xs text-text-secondary">{details.join(" · ")}</p>}
          </div>
          <div className="flex shrink-0 flex-col items-end gap-0.5">
            <VerdictBadge verdict={badgeVerdict} label={badgeLabel} />
            {result.cached && (
              <span className="text-xs uppercase tracking-wider text-text-secondary">
                {result.stale ? "stale cache" : "cached"}
              </span>
            )}
          </div>
        </div>

        <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-text-secondary">
          {result.confidence && <span>{result.confidence} confidence</span>}
          {result.latency_ms != null && <span>{formatDuration(result.latency_ms)}</span>}
          {result.source_timestamp && formatDate(result.source_timestamp) !== "—" && <span>source time {formatDate(result.source_timestamp)}</span>}
          {result.provider_verdict && result.provider_verdict !== result.verdict && result.provider_verdict !== "unknown" && (
            <span>provider label: {titleCase(result.provider_verdict)}</span>
          )}
        </div>

        {chips.length > 0 && (
          <div className="mt-1.5">
            <TagList labels={chips} max={6} />
          </div>
        )}

        {/* Deliberately NOT the full provider payload. Dumping every returned
            field here made each card a wall of text and buried the verdict it
            was supposed to support; the card carries the finding only. The
            structured fields live on the Sources tab and the raw JSON is one
            click away on either. */}
        {hasRaw && fieldCount > 0 && (
          <div className="mt-1.5 text-xs text-text-secondary">
            {fieldCount} field{fieldCount === 1 ? "" : "s"} returned · full payload on the Sources tab
          </div>
        )}
      </div>

      <div className="mt-auto border-t border-border bg-bg-card/60 px-2.5 py-1.5">
        <div className="flex items-center gap-1.5">
          {hasRaw && (
            <button
              type="button"
              onClick={() => setShowJson((value) => !value)}
              aria-expanded={showJson}
              className="rounded border border-border bg-bg-elevated px-2 py-1 text-xs font-semibold text-text-secondary hover:border-accent/50 hover:text-accent transition-colors"
            >
              {showJson ? "Hide raw JSON" : "Raw JSON"}
            </button>
          )}
          {(attributes.length > 0) && (
            <button
              type="button"
              onClick={() => setExpanded((value) => !value)}
              aria-expanded={expanded}
              className="rounded border border-border bg-bg-elevated px-2 py-1 text-xs font-semibold text-text-secondary hover:border-accent/50 hover:text-accent transition-colors"
            >
              {expanded ? "Hide tags" : "Tags"}
            </button>
          )}
          {result.source_link && (
            <a
              href={result.source_link}
              target="_blank"
              rel="noopener noreferrer"
              className="rounded border border-border px-2 py-1 text-xs font-semibold text-text-secondary hover:border-accent/50 hover:text-accent transition-colors"
            >
              Open source â†—
            </a>
          )}
        </div>

        {expanded && attributes.length > 0 && (
          <div className="mt-2 space-y-2 border-t border-border pt-2">
            <dl className="grid grid-cols-[minmax(0,8rem)_minmax(0,1fr)] gap-x-2 gap-y-0.5 text-xs">
              {attributes.map(([key, value]) => (
                <div key={key} className="contents">
                  <dt className="truncate text-text-secondary">{key}</dt>
                  <dd className="break-words text-text-primary">{formatValue(value)}</dd>
                </div>
              ))}
            </dl>
          </div>
        )}

        {showJson && hasRaw && (
          <div className="mt-2 space-y-2 border-t border-border pt-2">
            <div>
              <div className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-text-secondary">Raw provider payload</div>
              <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded border border-border bg-[#080b12] p-2 font-mono text-xs leading-relaxed text-slate-300">
                {JSON.stringify(result.raw_data, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </article>
  );
}
