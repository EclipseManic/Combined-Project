import type { StageInfo } from "../services/api";

const STATUS_COLORS: Record<string, string> = {
  pending: "bg-border",
  running: "bg-accent animate-pulse",
  done: "bg-green-500",
  skipped: "bg-gray-600",
  error: "bg-red-500",
};

export default function PipelineProgress({
  stages = [],
  progress = 0,
}: {
  stages?: StageInfo[];
  progress?: number;
}) {
  const active = stages.find((s) => s.status === "running");
  const done = stages.filter((s) => s.status === "done").length;
  const total = stages.length;

  return (
    <div className="bg-bg-card border border-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-semibold text-text-secondary">Pipeline Progress</span>
        <span className="text-xs text-text-secondary">{done}/{total} stages · {progress.toFixed(0)}%</span>
      </div>
      <div
        role="progressbar"
        aria-label="Pipeline progress"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(progress)}
        className="w-full bg-bg-elevated rounded-full h-1.5 mb-3"
      >
        <div
          className="h-1.5 rounded-full bg-gradient-to-r from-accent to-accent-secondary transition-all duration-500"
          style={{ width: `${progress}%` }}
        />
      </div>
      <div className="flex flex-wrap gap-1.5">
        {stages.map((s) => (
          <div
            key={s.name}
            className="flex items-center gap-1 text-xs"
            title={s.message || s.name}
          >
            <span className={`w-1.5 h-1.5 rounded-full ${STATUS_COLORS[s.status] || STATUS_COLORS.pending}`} />
            <span className={
              s.status === "done" ? "text-green-400" :
              s.status === "running" ? "text-accent" :
              s.status === "error" ? "text-red-400" :
              s.status === "skipped" ? "text-gray-500" :
              "text-text-secondary"
            }>
              {s.name}
            </span>
          </div>
        ))}
      </div>
      {active && (
        <p className="text-xs text-text-secondary mt-2">{active.message}</p>
      )}
    </div>
  );
}
