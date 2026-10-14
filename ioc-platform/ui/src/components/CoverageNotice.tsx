import type { LookupResponse } from "../services/api";
import { titleCase } from "../lib/format";

const COMPLETENESS_PROBLEMS = new Set(["error", "not_configured", "unavailable", "timeout", "rate_limited"]);

export default function CoverageNotice({ result }: { result: LookupResponse }) {
  const notes = (result.enrichment?.analysis_notes ?? []).filter((note): note is string => typeof note === "string" && note.trim() !== "");
  const errors = Object.entries(result.enrichment?.completeness ?? {})
    .filter(([, status]) => typeof status === "string" && (COMPLETENESS_PROBLEMS.has(status) || status.startsWith("http_")));
  const assessment = result.final_assessment;
  const failedProviders = assessment
    ? new Set([
      ...(assessment.rate_limited_sources ?? []),
      ...(assessment.unavailable_sources ?? []),
      ...(assessment.error_sources ?? []),
    ])
    : new Set<string>();
  const domain = assessment?.assessment_domain ?? "ioc_reputation";
  const results = Array.isArray(result.results) ? result.results : [];
  const hasSuccessfulData = results.some((r) => r.execution_state === "success" && r.status !== "not_found");
  const evaluated = Number(assessment?.evidence_summary?.evaluated_providers ?? 0) || 0;
  const noCoverage =
    domain === "ioc_reputation" &&
    (result.composite?.sources_contributing ?? 0) === 0 &&
    evaluated === 0 &&
    !hasSuccessfulData;
  if (notes.length === 0 && errors.length === 0 && failedProviders.size === 0 && !noCoverage) return null;

  return (
    <div className="bg-bg-card border border-border rounded-lg p-4 text-sm">
      {noCoverage && (
        <div className="mb-3 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-amber-300">
          <p className="font-semibold mb-1">NO COVERAGE — 0 sources contributed a result</p>
          <p className="text-xs text-text-secondary">
            This verdict is <span className="text-text-primary">unknown, not a clean signal</span>. The IOC type
            may not be covered by the configured sources, or none of them had data. Verify against an alternate
            source before trusting it.
          </p>
        </div>
      )}
      <h3 className="font-semibold text-text-secondary uppercase tracking-wider text-xs mb-2">Coverage & Limitations</h3>
      {notes.map((note) => <p key={note} className="text-text-primary mb-1">{note}</p>)}
      {errors.length > 0 && (
        <p className="text-text-secondary">
          Enrichment incomplete: {errors.map(([name, status]) => `${titleCase(name)} (${status.replace(/_/g, " ")})`).join(", ")}. Missing enrichment is not a malicious or clean signal.
        </p>
      )}
      {assessment && failedProviders.size > 0 && (
        <p className="text-text-secondary mt-2">
          {failedProviders.size} provider{failedProviders.size === 1 ? "" : "s"} could not answer ({[...failedProviders].join(", ")}); see
          Provider problems below. They are excluded from scoring, so coverage is {Math.round((Number(assessment.coverage) || 0) * 100)}%.
        </p>
      )}
    </div>
  );
}
