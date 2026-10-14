import { useCallback, useEffect, useState } from "react";
import { deleteRecentIOC, getRecentIOCs, getBatchesFromServer, deleteBatchFromServer, getSavedBatches, deleteSavedBatch, type RecentIOC, type SavedBatch } from "../services/api";
import { showToast } from "../components/Toast";
import type { NavigateEvent } from "../App";
import { timeAgo } from "../lib/timeAgo";
import { formatVerdictLabel, getVerdictBucket, getVerdictColor } from "../lib/verdictColors";
import { formatDateTime } from "../lib/format";

const SCORELESS = new Set(["context_only", "malicious_test_artifact", "unknown", "error"]);

/** A stored score of 0 on a verdict that carries no score means "not scored", not "clean". */
function displayScore(item: RecentIOC): string | null {
  const verdict = item.final_verdict ?? item.verdict;
  const score = item.final_score ?? item.score;
  if (score === null || score === undefined || !Number.isFinite(score)) return null;
  if (SCORELESS.has(getVerdictBucket(verdict)) && score === 0) return null;
  return `${Math.round(score)}/100`;
}
import Modal from "../components/Modal";

function VerdictBadge({ label, count }: { label: string; count: number }) {
  if (count === 0) return null;
  const color = getVerdictColor(label).badge;
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-semibold px-1.5 py-0.5 rounded border ${color}`}>
      {count} {label}
    </span>
  );
}

export default function History() {
  const [items, setItems] = useState<RecentIOC[]>([]);
  const [batches, setBatches] = useState<SavedBatch[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const [iocs, serverBatches] = await Promise.all([
        getRecentIOCs(),
        getBatchesFromServer(),
      ]);
      const localBatches = getSavedBatches();
      const map = new Map<string, SavedBatch>();
      for (const b of localBatches) {
        if (b && b.batch_id) {
          const raw = b as unknown as Record<string, unknown>;
          const legacyResult = (raw.result ?? b.result) as SavedBatch["result"];
          const summary = b.summary || (legacyResult?.summary as Record<string, number> | undefined) || {};
          map.set(b.batch_id, { ...b, summary, result: legacyResult });
        }
      }
      for (const b of serverBatches) {
        if (b && b.batch_id) {
          map.set(b.batch_id, b);
        }
      }
      setItems(iocs);
      setBatches(Array.from(map.values()));
    } catch (e: unknown) {
      setLoadError(e instanceof Error ? e.message : String(e));
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  function clearAll() {
    setConfirmOpen(false);
    Promise.all(items.map((i) => deleteRecentIOC(i.id)))
      .then(load)
      .catch((e: Error) => showToast(e.message, "error"));
  }

  function deleteItem(id: number, e: React.MouseEvent) {
    e.stopPropagation();
    deleteRecentIOC(id)
      .then(load)
      .catch((err: Error) => showToast(err.message, "error"));
  }

  async function removeBatch(batchId: string) {
    try {
      await deleteBatchFromServer(batchId);
      deleteSavedBatch(batchId);
      setBatches((prev) => prev.filter((b) => b.batch_id !== batchId));
      showToast("Batch removed", "success");
    } catch (error: unknown) {
      showToast(error instanceof Error ? error.message : "Failed to remove batch", "error");
    }
  }

  function copyValue(value: string, e: React.MouseEvent) {
    e.stopPropagation();
    navigator.clipboard.writeText(value);
    showToast("IOC copied", "success");
  }

  const types = [...new Set(items.map(i => i.ioc_type))].sort();
  const filtered = items.filter(i => {
    if (filter && !i.value.toLowerCase().includes(filter.toLowerCase())) return false;
    if (typeFilter && i.ioc_type !== typeFilter) return false;
    return true;
  });

  if (loading) {
    return (
      <div className="page-enter" aria-busy="true" role="status">
        <h2 className="text-lg font-bold mb-4">Lookup History</h2>
        <div className="space-y-2">
          {[0, 1, 2, 3].map((n) => (
            <div key={n} className="h-14 bg-bg-card border border-border rounded-lg animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="page-enter">
        <h2 className="text-lg font-bold mb-4">Lookup History</h2>
        <div className="bg-verdict-malicious/10 border border-verdict-malicious/30 rounded-lg p-6 text-center">
          <p className="text-verdict-malicious font-medium mb-2">Failed to load history</p>
          <p className="text-sm text-text-secondary mb-4">{loadError}</p>
          <button onClick={load} className="px-4 py-1.5 text-sm bg-accent text-[#06070d] rounded-lg hover:bg-accent/90 transition-colors">
            Try Again
          </button>
        </div>
      </div>
    );
  }

  if (items.length === 0 && batches.length === 0) {
    return (
      <div className="page-enter">
        <h2 className="text-lg font-bold mb-4">Lookup History</h2>
        <div className="flex flex-col items-center justify-center py-16 text-center text-text-secondary">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-12 h-12 mb-4" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        <h3 className="text-lg font-bold text-text-secondary mb-1.5">No lookup history yet</h3>
          <p className="text-sm">Search for an IOC to get started.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page-enter">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-bold">Lookup History</h2>
        <button
          onClick={() => setConfirmOpen(true)}
          className="text-xs px-3 py-1.5 bg-bg-elevated border border-border rounded-md text-text-secondary hover:text-text-primary hover:border-red-400/40 hover:text-red-400 transition-colors"
        >
          Clear All
        </button>
      </div>

      <div className="flex gap-3 mb-4">
        <input
          type="text"
          placeholder="Filter by IOC value..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          className="flex-1 px-3 py-1.5 bg-bg-card border border-border rounded-lg text-sm text-text-primary placeholder:text-text-secondary/50 focus:outline-none focus:border-accent"
          aria-label="Filter by IOC value"
        />
        <select
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
          className="px-3 py-1.5 bg-bg-card border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent"
          aria-label="Filter by IOC type"
        >
          <option value="">All types</option>
          {types.map(t => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </div>

      {batches.length > 0 && (
        <section className="mb-6 rounded-xl border border-accent/20 bg-accent/5 p-4">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold">Batch Scans</h3>
              <p className="mt-0.5 text-xs text-text-secondary">
                Historical batch scans persisted on the server. Select one to reopen its full report.
              </p>
            </div>
            <span className="rounded-full bg-accent/10 px-2 py-1 text-xs font-semibold text-accent">
              {batches.length}
            </span>
          </div>
          <div className="space-y-2">
            {batches.map((batch) => {
              const summary = batch.summary || {};
              return (
                <div
                  key={batch.batch_id}
                  className="flex items-center gap-3 rounded-lg border border-border bg-bg-card px-3 py-3"
                >
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-semibold">
                      Batch scan{" "}
                      <span className="font-mono text-xs text-text-secondary">
                        #{batch.batch_id}
                      </span>
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-1.5">
                      <span className="text-xs text-text-secondary">
                        {batch.completed}/{batch.total} IOCs
                      </span>
        <VerdictBadge label="malicious" count={summary.malicious ?? 0} />
        <VerdictBadge label="breached" count={summary.breached ?? 0} />
        <VerdictBadge label="suspicious" count={summary.suspicious ?? 0} />
        <VerdictBadge label="clean" count={summary.clean ?? 0} />
        <VerdictBadge label="unknown" count={summary.unknown ?? 0} />
        <VerdictBadge label="error" count={summary.error ?? 0} />

                    </div>
                    <div className="mt-1 text-xs text-text-secondary">
                      {formatDateTime(batch.created_at)}
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() =>
                      window.dispatchEvent(
                        new CustomEvent<NavigateEvent>("navigate", {
                          detail: { page: "lookup", tool: "batch", batchId: batch.batch_id, batchResult: batch.result ?? undefined },
                        })
                      )
                    }
                    className="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-[#06070d] hover:bg-accent/90"
                  >
                    Open scan
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      window.dispatchEvent(
                        new CustomEvent<NavigateEvent>("navigate", {
                          detail: {
                            page: "lookup",
                            tool: "batch",
                            batchId: batch.batch_id,
                            autoRescan: true,
                          },
                        })
                      )
                    }
                    className="rounded-md border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-semibold text-accent hover:bg-accent/20"
                  >
                    Re-scan
                  </button>
                  <button
                    type="button"
                    onClick={() => removeBatch(batch.batch_id)}
                    className="rounded-md border border-border px-2 py-1.5 text-xs text-text-secondary hover:border-red-400/50 hover:text-red-300"
                    aria-label={`Delete batch ${batch.batch_id}`}
                  >
                    Remove
                  </button>
                </div>
              );
            })}
          </div>
        </section>
      )}

      <div className="space-y-2">
        {filtered.map(item => (
          <div
            key={item.id}
            role="button"
            tabIndex={0}
            onClick={() => {
              window.dispatchEvent(new CustomEvent<NavigateEvent>("navigate", {
                detail: {
                  page: "lookup",
                  ioc: item.value,
                  iocType: item.ioc_type === "password" ? "password_sha1" : item.ioc_type,
                  historyId: item.id,
                  isHistorical: true,
                  createdAt: item.created_at ?? undefined,
                },
              }));
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                window.dispatchEvent(new CustomEvent<NavigateEvent>("navigate", {
                  detail: {
                    page: "lookup",
                    ioc: item.value,
                    iocType: item.ioc_type === "password" ? "password_sha1" : item.ioc_type,
                    historyId: item.id,
                    isHistorical: true,
                    createdAt: item.created_at ?? undefined,
                  },
                }));
              }
            }}
            className="flex items-center gap-3 px-4 py-2.5 bg-bg-card border border-border rounded-lg hover:bg-bg-elevated transition-colors cursor-pointer focus:outline-none focus:border-accent"
          >
            <div className="flex-1 min-w-0">
              <div className="font-mono text-xs truncate">{item.value}</div>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-xs font-mono px-1.5 py-0.5 bg-bg-elevated rounded text-text-secondary uppercase">
                  {item.ioc_type}
                </span>
                {displayScore(item) && (
                  <span className="text-xs text-text-secondary">Score: {displayScore(item)}</span>
                )}
              </div>
            </div>

            <div className="flex items-center gap-3">
              {(item.final_verdict ?? item.verdict) && (
                <span className={`text-xs font-medium px-2 py-0.5 rounded border ${getVerdictColor(item.final_verdict ?? item.verdict).badge}`}>
                  {formatVerdictLabel(item.final_verdict ?? item.verdict)}
                </span>
              )}
              <button
                onClick={e => copyValue(item.value, e)}
                className="text-text-secondary hover:text-accent transition-colors p-1"
                title="Copy IOC"
                aria-label={`Copy ${item.value}`}
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
              </button>
              {item.created_at && (
                <span className="text-xs text-text-secondary hidden sm:block whitespace-nowrap" title={formatDateTime(item.created_at)}>
                  {timeAgo(item.created_at)}
                </span>
              )}
              <button
                onClick={e => deleteItem(item.id, e)}
                className="text-text-secondary hover:text-red-400 transition-colors p-1"
                title="Delete"
                aria-label={`Delete ${item.value}`}
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </button>
            </div>
          </div>
        ))}
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-12 text-text-secondary">No matching entries.</div>
      )}

      <Modal open={confirmOpen} onClose={() => setConfirmOpen(false)} title="Clear lookup history">
        <p className="text-sm text-text-secondary mb-4">Delete all {items.length} saved lookups? This cannot be undone.</p>
        <div className="flex gap-2 justify-end">
          <button onClick={() => setConfirmOpen(false)} className="px-4 py-2 text-xs bg-bg-elevated border border-border rounded-lg text-text-secondary hover:text-text-primary transition-colors">
            Cancel
          </button>
          <button onClick={clearAll} className="px-4 py-2 text-xs bg-verdict-malicious text-white rounded-lg hover:bg-verdict-malicious/90 transition-colors">
            Delete All
          </button>
        </div>
      </Modal>
    </div>
  );
}
