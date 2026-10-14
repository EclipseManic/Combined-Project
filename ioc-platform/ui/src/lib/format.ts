// Defensive display formatters. Backend payloads are loosely typed (provider
// raw_data, optional enrichment blocks), so every value rendered in the result
// view goes through one of these instead of raw String()/toFixed()/new Date(),
// which is how "NaN", "undefined", "Invalid Date" and "[object Object]" leaked
// into the UI.

export const EMPTY = "—";

export function toFiniteNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === "" || typeof value === "boolean") return null;
  const numeric = typeof value === "number" ? value : Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

/** Locale number with optional unit; em dash for missing / non-numeric values. */
export function formatNumber(value: unknown, options: { unit?: string; maxFractionDigits?: number } = {}): string {
  const numeric = toFiniteNumber(value);
  if (numeric === null) return EMPTY;
  const formatted = numeric.toLocaleString(undefined, { maximumFractionDigits: options.maxFractionDigits ?? 2 });
  return options.unit ? `${formatted} ${options.unit}` : formatted;
}

/** Ratio (0-1) as a percentage, e.g. 0.97432 -> "97.4%". */
export function formatPercent(ratio: unknown, digits = 1): string {
  const numeric = toFiniteNumber(ratio);
  if (numeric === null) return EMPTY;
  return `${(numeric * 100).toFixed(digits)}%`;
}

/** Milliseconds as "850 ms" / "3.2 s". */
export function formatDuration(ms: unknown): string {
  const numeric = toFiniteNumber(ms);
  if (numeric === null || numeric < 0) return EMPTY;
  if (numeric < 1000) return `${Math.round(numeric)} ms`;
  return `${(numeric / 1000).toFixed(1)} s`;
}

function parseDate(value: unknown): Date | null {
  if (value === null || value === undefined || value === "") return null;
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null;
  if (typeof value === "number") {
    // Epoch seconds (blockchain APIs) vs milliseconds.
    const date = new Date(value < 1e12 ? value * 1000 : value);
    return Number.isFinite(date.getTime()) ? date : null;
  }
  if (typeof value !== "string") return null;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date : null;
}

/** Local date + time, or em dash when missing/unparseable. */
export function formatDateTime(value: unknown): string {
  const date = parseDate(value);
  return date ? date.toLocaleString() : EMPTY;
}

/** Local date only, or em dash. */
export function formatDate(value: unknown): string {
  const date = parseDate(value);
  return date ? date.toLocaleDateString() : EMPTY;
}

/** snake_case / kebab-case vocabulary -> "Title Case". */
export function titleCase(value: unknown): string {
  if (value === null || value === undefined) return EMPTY;
  const text = String(value).trim();
  if (!text) return EMPTY;
  return text.replace(/[_-]+/g, " ").replace(/\s+/g, " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

/** Render any scalar / list / object compactly without "[object Object]". */
export function formatValue(value: unknown, maxItems = 8): string {
  if (value === null || value === undefined || value === "") return EMPTY;
  if (typeof value === "number") return Number.isFinite(value) ? value.toLocaleString(undefined, { maximumFractionDigits: 4 }) : EMPTY;
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    const items = value.filter((item) => item !== null && item !== undefined && item !== "").map((item) => formatValue(item, maxItems));
    if (items.length === 0) return EMPTY;
    const shown = items.slice(0, maxItems).join(", ");
    return items.length > maxItems ? `${shown} +${items.length - maxItems} more` : shown;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).filter(([, item]) => item !== null && item !== undefined && item !== "");
    if (entries.length === 0) return EMPTY;
    return entries.slice(0, maxItems).map(([key, item]) => `${key}: ${formatValue(item, 3)}`).join("; ");
  }
  return String(value);
}
