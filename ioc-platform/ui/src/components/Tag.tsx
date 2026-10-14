import { useState } from "react";

export default function Tag({ label, variant = "default" }: { label: string; variant?: "default" | "accent" | "cached" }) {
  const cls =
    variant === "accent" ? "bg-accent/10 text-accent border-accent/30" :
    variant === "cached" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" :
    "bg-bg-elevated text-text-secondary border-border";
  const trimmed = typeof label === "string" ? label.trim() : "";
  if (!trimmed) return null;
  return (
    <span
      className={`inline-flex max-w-full items-center truncate px-2 py-0.5 text-xs rounded-full border font-mono ${cls}`}
      title={trimmed.length > 40 ? trimmed : undefined}
    >
      {trimmed.length > 40 ? `${trimmed.slice(0, 39)}…` : trimmed}
    </span>
  );
}

/** A row of chips capped at `max`, with a "+N more" toggle for the rest. */
export function TagList({ labels, max = 6 }: { labels: string[]; max?: number }) {
  const [expanded, setExpanded] = useState(false);
  if (labels.length === 0) return null;
  const visible = expanded ? labels : labels.slice(0, max);
  const hidden = labels.length - max;
  return (
    <div className="flex flex-wrap items-center gap-1">
      {visible.map((label) => <Tag key={label} label={label} />)}
      {hidden > 0 && (
        <button
          type="button"
          onClick={() => setExpanded((value) => !value)}
          className="rounded-full border border-border/80 bg-bg-secondary px-2 py-0.5 text-xs font-semibold text-accent hover:border-accent transition-colors"
        >
          {expanded ? "Show less" : `+${hidden} more`}
        </button>
      )}
    </div>
  );
}
