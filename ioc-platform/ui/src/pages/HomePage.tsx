import { useCallback, useEffect, useRef, useState } from "react";
import { useLookup } from "../hooks/useLookup";
import PipelineProgress from "../components/PipelineProgress";
import SearchBar from "../components/SearchBar";
import { SkeletonHeader, SkeletonSourceGrid } from "../components/LoadingSkeleton";
import { getKeyHealth, type BatchResult, type KeyHealthResponse, type LookupResponse } from "../services/api";
import type { Tool } from "../App";
import ResultView from "./ResultView";
import SourceCoveragePanel from "../components/SourceCoveragePanel";
import PrivacyNotice from "../components/PrivacyNotice";
import History from "./History";
import Investigations from "./Investigations";
import Batch from "./Batch";

export default function HomePage({
  initialValue = "",
  initialType = "",
  tool = null,
  initialBatchId = "",
  batchResult,
  historyId,
  isHistorical = false,
  batchResultItem,
  fromBatch = false,
  autoRescan = false,
  createdAt,
}: {
  initialValue?: string;
  initialType?: string;
  tool?: Tool | null;
  initialBatchId?: string;
  batchResult?: BatchResult;
  historyId?: number;
  isHistorical?: boolean;
  batchResultItem?: LookupResponse;
  fromBatch?: boolean;
  autoRescan?: boolean;
  createdAt?: string;
}) {
  const { state, submit, reset, cancel, loadResult, loadStored } = useLookup();
  const submittedRef = useRef<string | null>(null);
  const [keyHealth, setKeyHealth] = useState<KeyHealthResponse | null>(null);
  const routeSubmissionKey = `${initialType}\u0000${initialValue}`;

  useEffect(() => {
    if (tool) return;
    getKeyHealth().then(setKeyHealth).catch(() => undefined);
  }, [tool]);

  useEffect(() => {
    if (tool) return;
    if (batchResultItem) {
       submittedRef.current = `${initialType}\u0000${batchResultItem.normalized || batchResultItem.input}`;
      loadResult(batchResultItem, { fromBatch: Boolean(fromBatch), batchId: initialBatchId });
      return;
    }
    if (isHistorical || historyId) {
      submittedRef.current = routeSubmissionKey;
      // A missing stored copy is reported with a "Run live lookup" action rather
      // than silently spending provider quota on a fresh analysis.
      void loadStored(historyId, initialValue, { isHistorical: true, historyId, scannedAt: createdAt }, initialType || undefined);
      return;
    }
     if (initialValue && submittedRef.current !== routeSubmissionKey) {
       submittedRef.current = routeSubmissionKey;
       submit(initialValue, initialType || undefined);
    }
  }, [initialValue, initialType, routeSubmissionKey, tool, historyId, isHistorical, batchResultItem, createdAt, initialBatchId, fromBatch, loadResult, loadStored, submit]);

   const handleSearch = useCallback((value: string, iocType?: string, refresh = false) => {
     submittedRef.current = `${iocType ?? ""}\u0000${value}`;
    submit(value, iocType, refresh);
    window.dispatchEvent(new CustomEvent("ioc-sync", { detail: { value, iocType } }));
  }, [submit]);

  const panelId = tool ? `panel-${tool}` : "panel-lookup";

  if (tool) {
    return (
      <div id={panelId} role="tabpanel" aria-labelledby={`tab-tool-${tool}`} tabIndex={-1} className="page-enter outline-none">
        {tool === "investigations" && <Investigations />}
        {tool === "batch" && <Batch initialBatchId={initialBatchId} initialResult={batchResult} autoRescan={autoRescan} />}
        {tool === "history" && <History />}
      </div>
    );
  }

  return (
    <div id={panelId} role="tabpanel" aria-labelledby="tab-tool-lookup" tabIndex={-1} className="page-enter outline-none">
      <div className="flex items-center justify-between gap-4 pb-5 border-b border-border">
        <div>
          <h2 className="text-2xl font-extrabold tracking-tight text-text-primary">Indicator Lookup</h2>
          <p className="text-sm text-text-secondary mt-0.5">Search IPs, domains, URLs, hashes, emails, or CVEs — 20+ sources in one pass</p>
        </div>
        <div className="hidden items-center gap-3 md:flex">
          <div className="flex items-center gap-2 rounded-lg border border-border bg-bg-card px-3 py-2 text-xs font-medium text-text-secondary"><span className="status-dot" aria-hidden="true" /><span>Systems online</span></div>
          {keyHealth && <div className="rounded-lg border border-sky-500/25 bg-sky-500/5 px-3 py-2 text-xs text-sky-200" title={keyHealth.missing_keys?.length ? `Missing: ${keyHealth.missing_keys.join(", ")}` : "All configured providers are active"}><span className="font-semibold">API coverage</span><span className="ml-2 font-mono">{keyHealth.active_providers}/{keyHealth.total_providers}</span></div>}
        </div>
      </div>

      <div className="max-w-3xl mx-auto mt-8 mb-8">
         <SearchBar onSearch={handleSearch} initialValue={initialValue} initialType={initialType} disabled={state.status === "loading"} />
      </div>

      <div className="max-w-[1400px] mx-auto" aria-live="polite" aria-label="Lookup results">
        {state.status === "idle" && (
          <div className="flex flex-col items-center justify-center py-16 text-center text-text-secondary">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-12 h-12 mb-4" aria-hidden="true">
              <circle cx="11" cy="11" r="7" />
              <path d="M21 21l-4.3-4.3" strokeLinecap="round" />
            </svg>
            <h3 className="text-lg font-bold text-text-secondary mb-1.5">No indicators analyzed yet</h3>
            <p className="text-sm">Enter an IOC above to begin triage across 20+ threat-intel sources.</p>
          </div>
        )}

        {state.status === "loading" && (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-bg-card px-4 py-3" role="status">
              <p className="text-sm text-text-secondary">
                {state.message ?? (state.stages.length ? "Analysis running…" : "Preparing provider plan…")}
              </p>
              {state.taskId && (
                <button
                  type="button"
                  onClick={cancel}
                  className="rounded-md border border-border bg-bg-elevated px-3 py-1.5 text-xs text-text-secondary transition-colors hover:border-red-400/40 hover:text-red-400"
                >
                  Cancel lookup
                </button>
              )}
            </div>
            {state.stages.length > 0 && <PipelineProgress stages={state.stages} progress={state.progress} />}
            <SkeletonHeader />
            <SkeletonSourceGrid />
          </div>
        )}

        {state.status === "error" && (
          <div role="alert" className="bg-verdict-malicious/10 border border-verdict-malicious/30 rounded-lg p-4 text-center">
            <p className="text-verdict-malicious font-medium mb-2">{state.storedOnly ? "Stored analysis unavailable" : "Lookup failed"}</p>
            <p className="text-sm text-text-secondary">{state.error}</p>
            <div className="mt-3 flex flex-wrap justify-center gap-2">
              {state.request && (
                <button
                  type="button"
                  onClick={() => { if (state.request) submit(state.request.value, state.request.iocType, state.request.refresh); }}
                  className="px-4 py-1.5 text-sm bg-accent text-[#06070d] rounded-lg hover:bg-accent/90 transition-colors"
                >
                  {state.storedOnly ? "Run live lookup" : "Retry lookup"}
                </button>
              )}
              <button
                type="button"
                onClick={reset}
                className="px-4 py-1.5 text-sm border border-border bg-bg-elevated text-text-secondary rounded-lg hover:text-text-primary transition-colors"
              >
                Dismiss
              </button>
            </div>
          </div>
        )}

        {state.status === "done" && (
          <ResultView
            result={state.result as LookupResponse}
            meta={state.meta}
            onNewSearch={(v, type, refresh) => { handleSearch(v, type, refresh); }}
          />
        )}
      </div>

      <div className="max-w-6xl mx-auto mt-8 space-y-4">
        <PrivacyNotice />
        <SourceCoveragePanel />
      </div>
    </div>
  );
}
