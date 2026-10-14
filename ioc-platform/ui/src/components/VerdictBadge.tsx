import { formatVerdictLabel, getVerdictColor } from "../lib/verdictColors";

export default function VerdictBadge({
  verdict,
  size = "sm",
  label,
}: {
  verdict: string | null | undefined;
  size?: "sm" | "md";
  label?: string;
}) {
  const cls = getVerdictColor(verdict).badge;
  const textSize = size === "sm" ? "text-xs" : "text-sm";
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full border font-semibold ${cls} ${textSize}`}>
      {label ?? formatVerdictLabel(verdict)}
    </span>
  );
}
