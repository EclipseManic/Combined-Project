import { useCallback, useEffect, useState } from "react";
import Modal from "../components/Modal";
import Tag from "../components/Tag";
import { showToast } from "../components/Toast";
import { timeAgo } from "../lib/timeAgo";
import { formatDateTime } from "../lib/format";
import { formatVerdictLabel, getVerdictColor } from "../lib/verdictColors";
import type { InvestigationDetail, InvestigationSummary } from "../services/api";
import {
  addIOCToInvestigation,
  errorMessage,
  createInvestigation,
  deleteInvestigation,
  getInvestigation,
  listInvestigations,
  removeIOCFromInvestigation,
  updateIOCNotes,
} from "../services/api";

type View = "list" | "detail";

function InvestigationCard({ inv, onClick }: { inv: InvestigationSummary; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full bg-bg-card border border-border rounded-lg p-4 text-left hover:border-accent/50 transition-colors"
    >
      <div className="flex items-start justify-between mb-1">
        <h3 className="font-semibold text-sm truncate">{inv.name}</h3>
        <span className="text-xs font-mono text-text-secondary shrink-0 ml-2">{inv.ioc_count} IOCs</span>
      </div>
      {inv.description && (
        <p className="text-xs text-text-secondary line-clamp-2 mb-2">{inv.description}</p>
      )}
      <p className="text-xs text-text-secondary">
        Updated {timeAgo(inv.updated_at)}
      </p>
    </button>
  );
}

function NoteEditor({
  value,
  onSave,
  onCancel,
}: {
  value: string;
  onSave: (v: string) => void;
  onCancel: () => void;
}) {
  const [text, setText] = useState(value);
  return (
    <div className="space-y-2">
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        className="w-full h-20 px-3 py-2 bg-bg-elevated border border-border rounded text-xs font-mono text-text-primary outline-none focus:border-accent resize-none"
        placeholder="Add notes..."
        aria-label="Investigation notes"
      />
      <div className="flex gap-2">
        <button onClick={() => onSave(text)} className="px-3 py-1 text-xs bg-accent text-[#06070d] rounded hover:bg-accent/90 transition-colors">Save</button>
        <button onClick={onCancel} className="px-3 py-1 text-xs bg-bg-elevated border border-border rounded text-text-secondary hover:text-text-primary transition-colors">Cancel</button>
      </div>
    </div>
  );
}

export default function Investigations() {
  const [view, setView] = useState<View>("list");
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [detail, setDetail] = useState<InvestigationDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createDesc, setCreateDesc] = useState("");
  const [addIOCValue, setAddIOCValue] = useState("");
  const [editingNotes, setEditingNotes] = useState<number | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const loadList = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listInvestigations();
      setInvestigations(data);
    } catch (e: unknown) {
      showToast(errorMessage(e), "error");
    }
    setLoading(false);
  }, []);

  useEffect(() => { loadList(); }, [loadList]);

  async function handleCreate() {
    if (!createName.trim()) return;
    try {
      await createInvestigation(createName.trim(), createDesc.trim());
      setShowCreate(false);
      setCreateName("");
      setCreateDesc("");
      await loadList();
      showToast("Investigation created", "success");
    } catch (e: unknown) {
      showToast(errorMessage(e), "error");
    }
  }

  async function openDetail(id: number) {
    setDetailLoading(true);
    try {
      const data = await getInvestigation(id);
      setDetail(data);
      setView("detail");
    } catch (e: unknown) {
      showToast(errorMessage(e), "error");
    }
    setDetailLoading(false);
  }

  async function handleDelete(id: number) {
    try {
      await deleteInvestigation(id);
      setDetail(null);
      setView("list");
      await loadList();
      showToast("Investigation deleted", "success");
    } catch (e: unknown) {
      showToast(errorMessage(e), "error");
    }
  }

  async function handleAddIOC() {
    if (!detail || !addIOCValue.trim()) return;
    try {
      await addIOCToInvestigation(detail.id, addIOCValue.trim());
      setAddIOCValue("");
      const updated = await getInvestigation(detail.id);
      setDetail(updated);
      showToast("IOC added", "success");
    } catch (e: unknown) {
      showToast(errorMessage(e), "error");
    }
  }

  async function handleRemoveIOC(iiId: number) {
    if (!detail) return;
    try {
      await removeIOCFromInvestigation(detail.id, iiId);
      const updated = await getInvestigation(detail.id);
      setDetail(updated);
      showToast("IOC removed", "success");
    } catch (e: unknown) {
      showToast(errorMessage(e), "error");
    }
  }

  async function handleSaveNotes(iiId: number, notes: string) {
    if (!detail) return;
    try {
      await updateIOCNotes(detail.id, iiId, notes);
      setEditingNotes(null);
      const updated = await getInvestigation(detail.id);
      setDetail(updated);
      showToast("Notes saved", "success");
    } catch (e: unknown) {
      showToast(errorMessage(e), "error");
    }
  }

  if (detailLoading) {
    return (
      <div className="page-enter">
        <div className="h-4 w-24 bg-bg-elevated rounded animate-pulse mb-4" />
        <div className="h-20 bg-bg-card border border-border rounded-lg animate-pulse mb-4" />
        <div className="h-10 bg-bg-card border border-border rounded-lg animate-pulse mb-4" />
        <div className="space-y-2">
          {[0, 1, 2].map((n) => (
            <div key={n} className="h-16 bg-bg-card border border-border rounded-lg animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  if (view === "detail" && detail) {
    return (
      <div className="page-enter">
        <button
          onClick={() => { setView("list"); setDetail(null); }}
          className="flex items-center gap-1 text-xs text-text-secondary hover:text-text-primary mb-4 transition-colors"
        >
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
          Back to Investigations
        </button>

        <div className="bg-bg-card border border-border rounded-lg p-5 mb-4">
          <div className="flex items-start justify-between mb-2">
            <div>
              <h2 className="text-lg font-bold">{detail.name}</h2>
              {detail.description && <p className="text-sm text-text-secondary mt-0.5">{detail.description}</p>}
            </div>
            <div className="flex gap-2">
              <span className="text-xs font-mono text-text-secondary">{detail.iocs.length} IOCs</span>
              <button onClick={() => setConfirmDelete(true)} className="text-xs text-verdict-malicious hover:underline">Delete</button>
            </div>
          </div>
          <p className="text-xs text-text-secondary">
            Created {timeAgo(detail.created_at)} · Updated {timeAgo(detail.updated_at)}
          </p>
        </div>

        <div className="flex gap-2 mb-4">
          <input
            type="text"
            value={addIOCValue}
            onChange={(e) => setAddIOCValue(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleAddIOC()}
            placeholder="Add IOC (IP, domain, hash, URL, email, CVE)..."
            aria-label="IOC value to add"
            className="flex-1 px-3 py-2 bg-bg-card border border-border rounded-lg text-text-primary placeholder-text-secondary outline-none focus:border-accent focus:ring-1 focus:ring-accent text-sm font-mono"
          />
          <button
            onClick={handleAddIOC}
            disabled={!addIOCValue.trim()}
            className="px-4 py-2 bg-accent text-[#06070d] text-sm rounded-lg hover:bg-accent/90 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Add
          </button>
        </div>

        {detail.iocs.length === 0 ? (
          <div className="text-center py-12 text-text-secondary text-sm">
            No IOCs yet. Add one above.
          </div>
        ) : (
          <div className="space-y-2">
            {detail.iocs.map((entry) => (
              <div key={entry.id} className="bg-bg-card border border-border rounded-lg overflow-hidden">
                <div className="p-3 flex items-center gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="font-mono text-sm truncate">{entry.value}</span>
                      <Tag label={entry.ioc_type} />
                    </div>
                    <div className="flex items-center gap-3 text-xs">
                      {entry.verdict && (
                        <span className={getVerdictColor(entry.verdict).text}>
                          {formatVerdictLabel(entry.verdict)}
                          {entry.score != null && Number.isFinite(entry.score) && !(entry.score === 0 && getVerdictColor(entry.verdict).band === "unknown")
                            ? ` (${Math.round(entry.score)}/100)`
                            : ""}
                        </span>
                      )}
                      {entry.looked_up_at && (
                        <span className="text-text-secondary" title={formatDateTime(entry.looked_up_at)}>{timeAgo(entry.looked_up_at)}</span>
                      )}
                    </div>
                  </div>
                  <button
                    onClick={() => handleRemoveIOC(entry.id)}
                    className="text-xs text-text-secondary hover:text-verdict-malicious transition-colors shrink-0"
                  >
                    Remove
                  </button>
                </div>
                {editingNotes === entry.id ? (
                  <div className="px-3 pb-3">
                    <NoteEditor
                      value={entry.notes}
                      onSave={(v) => handleSaveNotes(entry.id, v)}
                      onCancel={() => setEditingNotes(null)}
                    />
                  </div>
                ) : (
                  <button
                    onClick={() => setEditingNotes(entry.id)}
                    className="w-full text-left px-3 pb-3 text-xs text-text-secondary hover:text-text-primary transition-colors"
                  >
                    {entry.notes ? (
                      <span className="font-mono text-xs">{entry.notes}</span>
                    ) : (
                      <span className="italic">Add notes...</span>
                    )}
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
        <Modal open={confirmDelete} onClose={() => setConfirmDelete(false)} title="Delete investigation">
          <p className="text-sm text-text-secondary mb-4">Delete "{detail.name}" and its {detail.iocs.length} IOCs? This cannot be undone.</p>
          <div className="flex justify-end gap-2">
            <button onClick={() => setConfirmDelete(false)} className="px-4 py-2 text-xs bg-bg-elevated border border-border rounded-lg text-text-secondary hover:text-text-primary transition-colors">
              Cancel
            </button>
            <button onClick={() => { setConfirmDelete(false); handleDelete(detail.id); }} className="px-4 py-2 text-xs bg-verdict-malicious text-white rounded-lg hover:bg-verdict-malicious/90 transition-colors">
              Delete
            </button>
          </div>
        </Modal>
      </div>
    );
  }

  return (
    <div className="page-enter">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-lg font-bold">Investigations</h2>
          <p className="text-sm text-text-secondary">Group related IOCs into investigation cases.</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="px-4 py-2 bg-accent text-[#06070d] text-sm rounded-lg hover:bg-accent/90 transition-colors font-medium"
        >
          New Investigation
        </button>
      </div>

      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="bg-bg-card border border-border rounded-lg p-4 animate-pulse space-y-2">
              <div className="h-4 bg-bg-elevated rounded w-2/3" />
              <div className="h-3 bg-bg-elevated rounded w-1/2" />
              <div className="h-3 bg-bg-elevated rounded w-1/4" />
            </div>
          ))}
        </div>
      ) : investigations.length === 0 ? (
        <div className="text-center py-16 text-text-secondary">
          <svg className="w-12 h-12 mx-auto mb-4 opacity-40" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <p className="font-medium mb-1">No investigations yet</p>
          <p className="text-sm">Create one to start grouping IOCs.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {investigations.map((inv) => (
            <InvestigationCard key={inv.id} inv={inv} onClick={() => openDetail(inv.id)} />
          ))}
        </div>
      )}

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="New Investigation">
        <div className="space-y-4">
          <div>
            <label className="text-xs text-text-secondary block mb-1">Name</label>
            <input
              type="text"
              value={createName}
              onChange={(e) => setCreateName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleCreate()}
              className="w-full px-3 py-2 bg-bg-elevated border border-border rounded text-sm text-text-primary outline-none focus:border-accent"
              placeholder="Investigation name"
              autoFocus
            />
          </div>
          <div>
            <label className="text-xs text-text-secondary block mb-1">Description (optional)</label>
            <textarea
              value={createDesc}
              onChange={(e) => setCreateDesc(e.target.value)}
              className="w-full h-20 px-3 py-2 bg-bg-elevated border border-border rounded text-sm text-text-primary outline-none focus:border-accent resize-none"
              placeholder="What is this investigation about?"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button onClick={() => setShowCreate(false)} className="px-4 py-2 text-sm text-text-secondary hover:text-text-primary transition-colors">Cancel</button>
            <button onClick={handleCreate} disabled={!createName.trim()} className="px-4 py-2 bg-accent text-[#06070d] text-sm rounded-lg hover:bg-accent/90 disabled:opacity-40 transition-colors">Create</button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
