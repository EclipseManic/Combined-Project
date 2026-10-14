import { getScoreColor, getScoreLabel } from "../lib/verdictColors";

/**
 * Circular 0-100 score gauge. Colours come from the canonical banding in
 * lib/verdictColors (the backend verdict thresholds), and the verdict is passed
 * so a score-less verdict (unknown, context only, test artifact) renders as a
 * neutral "not scored" ring rather than a green 0.
 */
export default function ScoreRing({
  score,
  size = 80,
  verdict,
}: {
  score: number | null | undefined;
  size?: number;
  verdict?: string | null;
}) {
  const numeric = score != null && Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : null;
  const radius = 15.5;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - ((numeric ?? 0) / 100) * circumference;
  const color = getScoreColor(numeric, verdict).hex;
  const label = numeric === null ? "not scored" : getScoreLabel(numeric, verdict);

  return (
    <div
      className="relative"
      style={{ width: size, height: size }}
      role="meter"
      aria-valuenow={numeric ?? undefined}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={numeric === null ? "Score: not scored" : `Score: ${numeric.toFixed(0)} out of 100, ${label}`}
    >
      <svg className="-rotate-90" width={size} height={size} viewBox="0 0 36 36" aria-hidden="true">
        <circle cx="18" cy="18" r={radius} fill="none" stroke="#1e293b" strokeWidth="3" />
        {numeric !== null && (
          <circle
            cx="18" cy="18" r={radius}
            fill="none" stroke={color} strokeWidth="3"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className="transition-all duration-700 ease-out"
          />
        )}
      </svg>
      <span className="absolute inset-0 flex items-center justify-center font-mono font-bold" style={{ fontSize: size * 0.28 }} aria-hidden="true">
        {numeric === null ? "—" : numeric.toFixed(0)}
      </span>
    </div>
  );
}
