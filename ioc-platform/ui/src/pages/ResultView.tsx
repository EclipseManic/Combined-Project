import { useMemo, useState } from "react";
import type { EthereumContext, LookupResponse } from "../services/api";
import { buildHeadline, isCredentialDomain, type HeadlineMetric, type MetricTone } from "../lib/assessmentView";
import { formatDateTime } from "../lib/format";
import { buildProviderRows, groupProviderRows } from "../lib/providerEvidence";
import { getVerdictBand } from "../lib/verdictColors";
import type { ResultSourceMeta } from "../hooks/useLookup";
import type { NavigateEvent } from "../App";
import ConsensusBar from "../components/ConsensusBar";
import BitcoinWalletCard from "../components/BitcoinWalletCard";
import PhoneIntelligenceCard from "../components/PhoneIntelligenceCard";
import EthereumWalletCard from "../components/EthereumWalletCard";
import CoverageNotice from "../components/CoverageNotice";
import EnrichmentPanel from "../components/EnrichmentPanel";
import SourcesPanel from "../components/SourcesPanel";
import ExportMenu, { ExportTab } from "../components/ExportMenu";
import PanelBoundary from "../components/PanelBoundary";
import FeedbackWidget from "../components/FeedbackWidget";
import RelationshipGraph from "../components/RelationshipGraph";
import ScoreRing from "../components/ScoreRing";
import ProviderEvidenceList from "../components/ProviderEvidenceList";
import TabBar, { type TabName } from "../components/TabBar";
import VerdictBadge from "../components/VerdictBadge";


function defangValue(text: string): string {
  return text
    .replace(/https?:\/\//gi, (m) => (m.toLowerCase().startsWith("https") ? "hxxps://" : "hxxp://"))
    .replace(/\./g, "[.]");
}

const METRIC_TONES: Record<MetricTone, string> = {
  danger: "text-red-400",
  warn: "text-amber-400",
  ok: "text-emerald-400",
  info: "text-sky-300",
  neutral: "text-text-primary",
};

function StatCard({ metric }: { metric: HeadlineMetric }) {
  return (
    <div className="rounded-xl border border-border/80 bg-bg-card/70 p-3.5 flex flex-col justify-between transition-colors hover:border-border">
      <div>
        <div className="text-xs font-bold uppercase tracking-wider text-text-secondary">{metric.label}</div>
        <div className={`mt-1 text-lg font-extrabold tracking-tight ${METRIC_TONES[metric.tone ?? "neutral"]}`}>{metric.value}</div>
      </div>
      {metric.detail && (
        <div className="mt-2 border-t border-border/40 pt-1.5 text-xs text-text-secondary">{metric.detail}</div>
      )}
    </div>
  );
}

export default function ResultView({
  result,
  onNewSearch,
  meta,
}: {
  result: LookupResponse;
  onNewSearch: (v: string, type?: string, refresh?: boolean) => void;
  meta?: ResultSourceMeta;
}) {
  const [tab, setTab] = useState<TabName>("Investigation");
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [copiedDefanged, setCopiedDefanged] = useState(false);

  const assessment = result.final_assessment ?? null;
  const results = useMemo(() => (Array.isArray(result.results) ? result.results : []), [result.results]);
  const rescanType = result.password_prehashed ? "password_sha1" : result.ioc_type;
  const grouped = useMemo(
    () => groupProviderRows(buildProviderRows(results, assessment?.provider_breakdown)),
    [results, assessment?.provider_breakdown],
  );
  const headline = useMemo(() => buildHeadline(result, grouped), [result, grouped]);
  const { verdict, domain } = headline;
  const verdictBand = getVerdictBand(verdict);
  const visibleResults = useMemo(
    () => results.filter((item) => (item.execution_state || item.status) !== "not_applicable"),
    [results],
  );
  const emptyFindingsText = isCredentialDomain(domain)
    ? "No provider reported an exposure record. Absence from the queried breach sources is not proof the credential is safe."
    : domain === "vulnerability"
    ? "No vulnerability record was returned by the CVE providers."
    : "No provider returned a verdict for this indicator. Not-found and failed providers are not evidence of benignness.";

  const handleCopyRaw = () => {
    void navigator.clipboard?.writeText(result.normalized);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const handleCopyDefanged = () => {
    void navigator.clipboard?.writeText(defangValue(result.normalized));
    setCopiedDefanged(true);
    setTimeout(() => setCopiedDefanged(false), 2000);
  };

  const handleNodeClick = (value: string) => onNewSearch(value);
  // Counterparties, funders and creators on the wallet card are always ETH addresses.
  const handleEthPivot = (value: string) => onNewSearch(value, "eth");

  // Every enrichment card used to be mounted here as well as on the Enrichment
  // tab, so the same data appeared in both. This tab is now the verdict, the
  // indicator's own dashboard and provider evidence. The per-type flags that
  // selected the old enrichment cards are gone with them.
  const enrichment = result.enrichment;
  const bitcoinContext =
    result.ioc_type === "btc" && enrichment?.extra?.bitcoin && typeof enrichment.extra.bitcoin === "object"
      ? enrichment.extra.bitcoin
      : null;
  // Both chain wallets get the same treatment: a dashboard on Investigation,
  // full field depth on Enrichment. Keeping one on each tab was an oversight
  // when the duplicated enrichment cards were moved out.
  const ethereumContext =
    result.ioc_type === "eth" && enrichment?.extra?.ethereum && typeof enrichment.extra.ethereum === "object"
      ? (enrichment.extra.ethereum as EthereumContext)
      : null;

  return (
    <div className="space-y-6">
      {/* 1. Header Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent opacity-75" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-accent" />
            </span>
            <span className="text-xs font-bold uppercase tracking-[0.2em] text-accent">
              Threat Intelligence Console
            </span>
          </div>
          <span className="text-text-secondary/40">/</span>
          <span className="text-xs font-semibold text-text-secondary">Investigation Active</span>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => onNewSearch(result.normalized, rescanType, true)}
            className="flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-semibold text-accent hover:bg-accent/20 transition-colors shadow-sm"
          >
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="23 4 23 10 17 10" />
              <polyline points="1 20 1 14 7 14" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
            </svg>
            <span>Run Live Re-Scan</span>
          </button>
          <ExportMenu result={result} />
        </div>
      </div>

      {/* Historical Snapshot Notice */}
      {meta?.isHistorical && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-sky-500/30 bg-sky-950/20 px-4 py-3 text-xs text-sky-200 shadow-sm">
          <div className="flex items-center gap-2.5">
            <span className="flex h-2.5 w-2.5 rounded-full bg-sky-400 shadow-[0_0_8px_rgba(56,189,248,0.6)]" />
            <div>
              <span className="font-bold text-sky-100">Historical Snapshot: </span>
              <span className="text-sky-300/80">
                Loaded instant pre-calculated analysis {meta.scannedAt ? `(originally scanned ${formatDateTime(meta.scannedAt)})` : ""}. No external API keys were billed.
              </span>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onNewSearch(result.normalized, rescanType, true)}
            className="flex items-center gap-1.5 rounded-lg border border-accent bg-accent/20 px-3 py-1.5 text-xs font-bold text-accent hover:bg-accent/30 transition-all shadow-sm"
          >
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="23 4 23 10 17 10" />
              <polyline points="1 20 1 14 7 14" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
            </svg>
            <span>Run Live Re-Scan</span>
          </button>
        </div>
      )}

      {/* Batch Inspection Notice */}
      {meta?.fromBatch && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-indigo-500/30 bg-indigo-950/20 px-4 py-3 text-xs text-indigo-200 shadow-sm">
          <div className="flex items-center gap-2.5">
            <span className="flex h-2.5 w-2.5 rounded-full bg-indigo-400 shadow-[0_0_8px_rgba(129,140,248,0.6)]" />
            <div>
              <span className="font-bold text-indigo-100">Batch Inspection Record: </span>
              <span className="text-indigo-300/80">
                Loaded multi-provider assessment directly from batch {meta.batchId ? `#${meta.batchId}` : ""}. 0 external API calls made.
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {meta.batchId && (
              <button
                type="button"
                onClick={() =>
                  window.dispatchEvent(
                    new CustomEvent<NavigateEvent>("navigate", {
                      detail: { page: "lookup", tool: "batch", batchId: meta.batchId },
                    })
                  )
                }
                className="flex items-center gap-1.5 rounded-lg border border-indigo-500/40 bg-indigo-500/15 px-3 py-1.5 text-xs font-semibold text-indigo-200 hover:bg-indigo-500/25 transition-all shadow-sm"
              >
                <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="19" y1="12" x2="5" y2="12" />
                  <polyline points="12 19 5 12 12 5" />
                </svg>
                <span>Back to Batch #{meta.batchId}</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => onNewSearch(result.normalized, rescanType, true)}
              className="flex items-center gap-1.5 rounded-lg border border-accent bg-accent/20 px-3 py-1.5 text-xs font-bold text-accent hover:bg-accent/30 transition-all shadow-sm"
            >
              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="23 4 23 10 17 10" />
                <polyline points="1 20 1 14 7 14" />
                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
              </svg>
              <span>Run Live Re-Scan</span>
            </button>
          </div>
        </div>
      )}

      {/* 2. Primary Hero Threat Assessment Banner */}
      <section className="overflow-hidden rounded-2xl border border-border bg-gradient-to-b from-bg-card to-bg-card/90 shadow-[0_20px_50px_rgba(0,0,0,0.35)]">
        {/* Top Indicator Header Bar */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border bg-bg-secondary/60 px-6 py-4">
          <div className="flex min-w-0 flex-1 flex-wrap items-center gap-3">
            <span className="rounded-lg border border-accent/40 bg-accent/10 px-2.5 py-1 font-mono text-xs font-bold uppercase tracking-wider text-accent shadow-sm">
              {result.ioc_type}
            </span>
            <code className="min-w-0 break-all font-mono text-base font-bold text-text-primary sm:text-xl selection:bg-accent selection:text-black">
              {result.normalized}
            </code>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={handleCopyRaw}
                className="rounded border border-border/80 bg-bg-elevated px-2 py-1 text-xs font-medium text-text-secondary hover:border-accent hover:text-accent transition-colors"
                title="Copy raw indicator"
              >
                {copiedRaw ? "Copied!" : "Copy"}
              </button>
              <button
                type="button"
                onClick={handleCopyDefanged}
                className="rounded border border-border/80 bg-bg-elevated px-2 py-1 text-xs font-medium text-text-secondary hover:border-accent hover:text-accent transition-colors"
                title="Copy defanged (safe for tickets & chats)"
              >
                {copiedDefanged ? "Defanged Copied!" : "Defang"}
              </button>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <VerdictBadge verdict={verdict} size="md" label={headline.verdictLabel} />
          </div>
        </div>

        {/* Hero Metrics & Score Ring: every value comes from final_assessment */}
        <div className="grid grid-cols-1 gap-6 p-6 lg:grid-cols-12 items-center">
          <div className="flex items-center gap-5 lg:col-span-4 border-b border-border/60 pb-5 lg:border-b-0 lg:border-r lg:pb-0 lg:pr-6">
            <div className="shrink-0">
              <ScoreRing score={headline.score} verdict={verdict} size={86} />
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-xs font-bold uppercase tracking-wider text-text-secondary">
                {headline.domainLabel} verdict
              </div>
              <div
                data-testid="headline-verdict"
                className={`mt-0.5 text-2xl font-black uppercase tracking-tight ${
                  verdictBand === "malicious" ? "text-rose-400" : verdictBand === "suspicious" ? "text-amber-400" : verdictBand === "benign" ? "text-emerald-400" : "text-slate-300"
                }`}
              >
                {headline.verdictLabel}
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-x-2 text-xs text-text-secondary">
                <span className="font-semibold text-text-primary" data-testid="headline-score">{headline.scoreText}</span>
                {headline.score !== null && <span>· {headline.scoreCaption}</span>}
              </div>
              {headline.needsReview && (
                <div className="mt-1.5 inline-flex rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wider text-amber-300">
                  Analyst review recommended
                </div>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:col-span-8">
            {headline.metrics.map((metric) => <StatCard key={metric.label} metric={metric} />)}
          </div>
        </div>

        {/* Why this verdict: the assessment reason, then the narrative summary */}
        {(headline.reason || result.executive_summary) && (
          <div className="border-t border-border/80 bg-bg-secondary/40 px-6 py-3.5 text-xs leading-relaxed text-text-secondary space-y-1.5">
            {headline.reason && (
              <p className="flex items-start gap-3">
                <span className="shrink-0 rounded bg-accent/15 px-2 py-0.5 text-xs font-bold uppercase tracking-wider text-accent border border-accent/30 mt-0.5">
                  Why
                </span>
                <span className="text-text-primary/90 font-medium" data-testid="headline-reason">{headline.reason}</span>
              </p>
            )}
            {headline.reviewReasons.length > 0 && (
              <ul className="list-disc space-y-0.5 pl-16 text-amber-200/90">
                {headline.reviewReasons.map((item) => <li key={item}>{item}</li>)}
              </ul>
            )}
            {result.executive_summary && result.executive_summary.trim() !== headline.reason.trim() && (
              <details className="pl-12">
                <summary className="cursor-pointer text-xs font-semibold text-text-secondary hover:text-text-primary">Analyst brief</summary>
                <p className="mt-1 text-text-primary/80">{result.executive_summary}</p>
              </details>
            )}
          </div>
        )}
      </section>

      {/* Coverage Limitations / Health Alerts */}
      <CoverageNotice result={result} />

      {/* 3. Global Tab Navigation Bar */}
      <TabBar
        active={tab}
        onChange={setTab}
        badges={{
          Relationships: result.relationships?.length || 0,
          Sources: visibleResults.length,
        }}
      />

      {/* 4. Tab Content Panels */}
      <div id="result-panel" role="tabpanel" aria-label={`${tab} results`}>
        {tab === "Investigation" && (
          <div className="space-y-4">
            {domain === "ioc_reputation" && grouped.findings.length > 1 && (
              <ConsensusBar results={grouped.findings.flatMap((row) => (row.result ? [row.result] : []))} />
            )}

            {/* The indicator's own dashboard, above the evidence. Chain wallets
                have on-chain context worth leading with; a single figure for an
                IP or domain does not. BTC and ETH are treated identically. */}
            {bitcoinContext && (
              <PanelBoundary label="Bitcoin wallet">
                <BitcoinWalletCard context={bitcoinContext} onPivot={onNewSearch} />
              </PanelBoundary>
            )}
            {ethereumContext && (
              <PanelBoundary label="Ethereum wallet">
                <EthereumWalletCard wallet={ethereumContext} onPivot={handleEthPivot} />
              </PanelBoundary>
            )}
            {result.ioc_type === "phone" && visibleResults.length > 0 && (
              <PanelBoundary label="Phone intelligence">
                <PhoneIntelligenceCard results={visibleResults} />
              </PanelBoundary>
            )}

            {/* Full width. Every enrichment card used to be mounted here as well
                as on the Enrichment tab, so the same data appeared twice. This
                tab is the verdict, the indicator dashboard and provider evidence;
                the Enrichment tab owns every enrichment module at full depth. */}
            <ProviderEvidenceList grouped={grouped} emptyFindingsText={emptyFindingsText} />
          </div>
        )}

        {/* Dedicated Deep-Dive Tabs */}
        {tab === "Enrichment" && (
          <PanelBoundary label="Enrichment">
            <EnrichmentPanel
              enrichment={result.enrichment}
              iocType={result.ioc_type}
            />
          </PanelBoundary>
        )}

        {tab === "Sources" && (
          <PanelBoundary label="Sources">
            <SourcesPanel result={result} />
          </PanelBoundary>
        )}

        {tab === "Relationships" && (
          result.relationships && result.relationships.length > 0 ? (
            <PanelBoundary label="Relationship graph">
              <RelationshipGraph
                mainIoc={result.normalized}
                relationships={result.relationships}
                onNodeClick={handleNodeClick}
              />
            </PanelBoundary>
          ) : (
            <div className="rounded-xl border border-border bg-bg-card p-12 text-center text-xs text-text-secondary">
              No graph relationships discovered for this indicator.
            </div>
          )
        )}

        {tab === "Export" && (
          <PanelBoundary label="Export">
            <ExportTab result={result} />
          </PanelBoundary>
        )}
      </div>

      {/* Analyst Feedback Loop (Ground Truth Reporting) */}
      <div className="border-t border-border/80 pt-5">
        <FeedbackWidget ioc={result.normalized} />
      </div>
    </div>
  );
}
