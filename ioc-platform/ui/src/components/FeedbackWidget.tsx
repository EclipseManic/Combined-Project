import { useEffect, useState } from "react";
import { getFeedback, submitFeedback, type FeedbackValue } from "../services/api";
import { showToast } from "./Toast";

const OPTIONS: { value: FeedbackValue; label: string; activeClass: string }[] = [
  { value: "false_positive", label: "False Positive", activeClass: "bg-amber-500/20 text-amber-400 border-amber-500/50" },
  { value: "confirmed", label: "Confirm Malicious", activeClass: "bg-green-500/20 text-green-400 border-green-500/50" },
];

export default function FeedbackWidget({ ioc }: { ioc: string }) {
  const [selected, setSelected] = useState<FeedbackValue | null>(null);
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getFeedback(ioc)
      .then((existing) => {
        if (cancelled || !existing) return;
        setSelected(existing.feedback);
        setNote(existing.note ?? "");
      })
      .catch(() => {
        // Feedback lookup is best-effort; ignore failures.
      });
    return () => { cancelled = true; };
  }, [ioc]);

  const handleSubmit = async () => {
    if (!selected) return;
    setSaving(true);
    try {
      await submitFeedback(ioc, selected, note || undefined);
      showToast(`Feedback saved: ${selected.replace("_", " ")}`, "success");
    } catch (e: any) {
      showToast(e.message, "error");
    }
    setSaving(false);
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      {OPTIONS.map((opt) => (
        <button
          key={opt.value}
          type="button"
          onClick={() => setSelected(opt.value)}
          className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${
            selected === opt.value
              ? opt.activeClass
              : "bg-bg-elevated text-text-secondary border-border hover:border-accent/40"
          }`}
        >
          {opt.label}
        </button>
      ))}
      <input
        type="text"
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="Optional note"
        aria-label="Optional feedback note"
        className="flex-1 min-w-40 px-3 py-1.5 text-xs rounded-lg bg-bg-elevated border border-border text-text-primary placeholder-text-secondary/60 focus:outline-none focus:border-accent/50"
      />
      <button
        type="button"
        onClick={handleSubmit}
        disabled={!selected || saving}
        aria-label="Save feedback"
        className="px-3 py-1.5 bg-accent text-[#06070d] text-xs rounded-lg hover:bg-accent/90 disabled:opacity-50 transition-colors"
      >
        {saving ? "Saving..." : "Save Feedback"}
      </button>
    </div>
  );
}
