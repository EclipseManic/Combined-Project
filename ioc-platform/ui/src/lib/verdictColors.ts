// Canonical verdict/score -> color mapping — the SINGLE SOURCE OF TRUTH for how
// verdicts and composite scores are colored across the UI. This consolidates what
// used to be several divergent maps (components/VerdictBadge, ConsensusBar,
// ScoreRing's private hex table, History's local badge).
//
// ────────────────────────────────────────────────────────────────────────────────
// CANONICAL SCORE BANDING (display scale 0-100)
//
//   score >= 40   ->  "malicious"   red    (#ef4444, --color-verdict-malicious)
//   15 <= s < 40  ->  "suspicious"  amber  (#f59e0b, --color-verdict-suspicious)
//    0 <= s < 15  ->  "benign"      green  (#22c55e, --color-verdict-clean)
//   no score      ->  "unknown"     gray   (#6b7280, --color-verdict-unknown)
//
// These cut-points are not invented here: they are the backend's own verdict
// boundaries (app/backend/scorer.py composite banding, via app/backend/thresholds.py,
// mirrored into ui/src/lib/thresholds.ts):
//
//   final_score >= MALICIOUS_HIGH   (0.70 -> 70) -> "malicious", high confidence
//   final_score >= MALICIOUS_MEDIUM (0.40 -> 40) -> "malicious", medium confidence
//   final_score >= SUSPICIOUS       (0.15 -> 15) -> "suspicious"
//   otherwise                                    -> "clean"
//
// So 40 — not 70 — is where the backend starts calling an indicator MALICIOUS, and
// 40+ therefore renders RED everywhere. 70 is only a *confidence* step inside the
// malicious band: it is surfaced in labels/ARIA via isHighConfidenceScore(), never
// as a different hue, so a single score can never read as two different severities.
// ────────────────────────────────────────────────────────────────────────────────
//
// Per-verdict styling keeps its established design tokens (rose for credential
// exposure, emerald for "not breached", cyan for context, violet for MITRE
// technique metadata, blue for the test sentinel). Those hues are *identity*, not
// severity; `band` is what carries severity, and band is the only thing that drives
// score coloring. Every Tailwind class below is written out as a complete literal
// string — never assembled with template literals — so the Tailwind scanner sees it.

import { DISPLAY_CLEAN, DISPLAY_MALICIOUS, DISPLAY_SUSPICIOUS } from "./thresholds";

/** The four-way severity banding that drives all score -> color decisions. */
export type VerdictBand = "malicious" | "suspicious" | "benign" | "unknown";

/**
 * Canonical grouping of the backend verdict vocabulary, used by aggregate displays
 * (consensus bar, batch donut, legends). Every bucket id is itself a valid key of
 * VERDICT_COLORS, so getVerdictColor(bucket) always resolves.
 */
export type VerdictBucket =
  | "malicious"
  | "breached"
  | "suspicious"
  | "benign"
  | "not_breached"
  | "context_only"
  | "malicious_test_artifact"
  | "unknown"
  | "error";

/** Render order for aggregate displays: worst -> best -> unresolved -> health. */
export const VERDICT_BUCKET_ORDER: readonly VerdictBucket[] = [
  "malicious",
  "breached",
  "suspicious",
  "benign",
  "not_breached",
  "context_only",
  "malicious_test_artifact",
  "unknown",
  "error",
];

/** Colors for one severity band, in every form the UI needs. */
export interface BandColor {
  band: VerdictBand;
  /** Raw hex — for SVG stroke/fill and inline styles. */
  hex: string;
  /** CSS custom property reference for the matching design token. */
  cssVar: string;
  /** Solid background Tailwind class. */
  solid: string;
  /** Pill classes: tinted background + text + border. */
  badge: string;
  /** Text-only Tailwind class. */
  text: string;
  /** Human-readable band name. */
  label: string;
}

export const BAND_COLORS: Record<VerdictBand, BandColor> = {
  malicious: {
    band: "malicious",
    hex: "#ef4444",
    cssVar: "var(--color-verdict-malicious)",
    solid: "bg-red-500",
    badge: "bg-red-500/10 text-red-400 border-red-500/30",
    text: "text-red-400",
    label: "malicious",
  },
  suspicious: {
    band: "suspicious",
    hex: "#f59e0b",
    cssVar: "var(--color-verdict-suspicious)",
    solid: "bg-amber-500",
    badge: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    text: "text-amber-400",
    label: "suspicious",
  },
  benign: {
    band: "benign",
    hex: "#22c55e",
    cssVar: "var(--color-verdict-clean)",
    solid: "bg-green-500",
    badge: "bg-green-500/10 text-green-400 border-green-500/30",
    text: "text-green-400",
    label: "benign",
  },
  unknown: {
    band: "unknown",
    hex: "#6b7280",
    cssVar: "var(--color-verdict-unknown)",
    solid: "bg-gray-500",
    badge: "bg-gray-500/10 text-gray-400 border-gray-500/30",
    text: "text-gray-400",
    label: "unknown",
  },
};

/**
 * The canonical score cut-points, highest first. Exported so legends (for example
 * the Landing page banding table) can render the same numbers the widgets use
 * instead of restating them. `min` is inclusive, on the 0-100 display scale.
 */
export const SCORE_BANDS: readonly { band: VerdictBand; min: number }[] = [
  { band: "malicious", min: DISPLAY_SUSPICIOUS }, // 40
  { band: "suspicious", min: DISPLAY_CLEAN }, //     15
  { band: "benign", min: 0 },
];

/** Inside the malicious band, >= 70 is the backend high-confidence step. */
export const HIGH_CONFIDENCE_SCORE = DISPLAY_MALICIOUS; // 70

export interface VerdictColor {
  /** Pill classes: tinted background + text + border. */
  badge: string;
  /** Solid background color (e.g. consensus-bar segments, legend dots). */
  solid: string;
  /** Human-readable label (underscores rendered as spaces). */
  label: string;
  /** Text-only Tailwind class. */
  text: string;
  /** Raw hex matching `solid` — for SVG stroke/fill and inline styles. */
  hex: string;
  /** Canonical severity band. This — not the hue — is what severity means. */
  band: VerdictBand;
  /** Canonical bucket for aggregate displays. */
  bucket: VerdictBucket;
}

export const VERDICT_COLORS: Record<string, VerdictColor> = {
  // ── Malicious family ──────────────────────────────────────────────
  malicious: { badge: "bg-red-500/10 text-red-400 border-red-500/30", solid: "bg-red-500", text: "text-red-400", hex: "#ef4444", label: "malicious", band: "malicious", bucket: "malicious" },
  compromised: { badge: "bg-red-500/10 text-red-400 border-red-500/30", solid: "bg-red-500", text: "text-red-400", hex: "#ef4444", label: "compromised", band: "malicious", bucket: "malicious" },
  breached: { badge: "bg-rose-500/15 text-rose-400 border-rose-500/40 shadow-[0_0_8px_rgba(244,63,94,0.2)]", solid: "bg-rose-500", text: "text-rose-400", hex: "#f43f5e", label: "breached", band: "malicious", bucket: "breached" },
  pwned: { badge: "bg-rose-500/15 text-rose-400 border-rose-500/40 shadow-[0_0_8px_rgba(244,63,94,0.2)]", solid: "bg-rose-500", text: "text-rose-400", hex: "#f43f5e", label: "pwned", band: "malicious", bucket: "breached" },

  // ── Test sentinel ─────────────────────────────────────────────────
  // EICAR-style artifacts. The string contains "malicious", but this is NOT live
  // malware: band is `unknown` so it never renders as a real detection (the backend
  // also reports normalized_score 0 for it).
  malicious_test_artifact: { badge: "bg-blue-500/10 text-blue-300 border-blue-500/30", solid: "bg-blue-500", text: "text-blue-300", hex: "#3b82f6", label: "malicious test artifact", band: "unknown", bucket: "malicious_test_artifact" },
  known_security_test_artifact: { badge: "bg-blue-500/10 text-blue-300 border-blue-500/30", solid: "bg-blue-500", text: "text-blue-300", hex: "#3b82f6", label: "known security test artifact", band: "unknown", bucket: "malicious_test_artifact" },

  // ── Suspicious family ─────────────────────────────────────────────
  suspicious: { badge: "bg-amber-500/10 text-amber-400 border-amber-500/30", solid: "bg-amber-500", text: "text-amber-400", hex: "#f59e0b", label: "suspicious", band: "suspicious", bucket: "suspicious" },

  // ── Clean / benign family ─────────────────────────────────────────
  // `benign` is the backend authoritative spelling; `clean` is the legacy alias.
  benign: { badge: "bg-green-500/10 text-green-400 border-green-500/30", solid: "bg-green-500", text: "text-green-400", hex: "#22c55e", label: "benign", band: "benign", bucket: "benign" },
  clean: { badge: "bg-green-500/10 text-green-400 border-green-500/30", solid: "bg-green-500", text: "text-green-400", hex: "#22c55e", label: "clean", band: "benign", bucket: "benign" },
  harmless: { badge: "bg-green-500/10 text-green-400 border-green-500/30", solid: "bg-green-500", text: "text-green-400", hex: "#22c55e", label: "harmless", band: "benign", bucket: "benign" },
  whitelisted: { badge: "bg-green-500/10 text-green-400 border-green-500/30", solid: "bg-green-500", text: "text-green-400", hex: "#22c55e", label: "whitelisted", band: "benign", bucket: "benign" },
  undetected: { badge: "bg-green-500/10 text-green-400 border-green-500/30", solid: "bg-green-500", text: "text-green-400", hex: "#22c55e", label: "undetected", band: "benign", bucket: "benign" },
  not_pwned: { badge: "bg-green-500/10 text-green-400 border-green-500/30", solid: "bg-green-500", text: "text-green-400", hex: "#22c55e", label: "not pwned", band: "benign", bucket: "not_breached" },
  not_breached: { badge: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40 shadow-[0_0_8px_rgba(16,185,129,0.2)]", solid: "bg-emerald-500", text: "text-emerald-400", hex: "#10b981", label: "not breached", band: "benign", bucket: "not_breached" },
  uncompromised: { badge: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40 shadow-[0_0_8px_rgba(16,185,129,0.2)]", solid: "bg-emerald-500", text: "text-emerald-400", hex: "#10b981", label: "uncompromised", band: "benign", bucket: "not_breached" },

  // ── Severity ladder (CVE / typed assessments) ─────────────────────
  // The `vulnerability` assessment domain emits its severity as the final verdict,
  // so these must band consistently with the reputation vocabulary.
  critical: { badge: "bg-red-500/10 text-red-300 border-red-500/40", solid: "bg-red-500", text: "text-red-300", hex: "#ef4444", label: "critical", band: "malicious", bucket: "malicious" },
  high: { badge: "bg-orange-500/10 text-orange-300 border-orange-500/40", solid: "bg-orange-500", text: "text-orange-300", hex: "#f97316", label: "high", band: "malicious", bucket: "malicious" },
  medium: { badge: "bg-amber-500/10 text-amber-300 border-amber-500/30", solid: "bg-amber-500", text: "text-amber-300", hex: "#f59e0b", label: "medium", band: "suspicious", bucket: "suspicious" },
  low: { badge: "bg-lime-500/10 text-lime-300 border-lime-500/30", solid: "bg-lime-500", text: "text-lime-300", hex: "#84cc16", label: "low", band: "benign", bucket: "benign" },
  informational: { badge: "bg-sky-500/10 text-sky-300 border-sky-500/30", solid: "bg-sky-500", text: "text-sky-300", hex: "#0ea5e9", label: "informational", band: "unknown", bucket: "context_only" },

  // ── Context / metadata (never raise maliciousness) ────────────────
  context_only: { badge: "bg-cyan-500/10 text-cyan-300 border-cyan-500/30", solid: "bg-cyan-500", text: "text-cyan-300", hex: "#06b6d4", label: "context only", band: "unknown", bucket: "context_only" },
  not_applicable: { badge: "bg-cyan-500/10 text-cyan-300 border-cyan-500/30", solid: "bg-cyan-500", text: "text-cyan-300", hex: "#06b6d4", label: "not applicable", band: "unknown", bucket: "context_only" },
  // Assessment-domain names occasionally surface where a verdict is expected
  // (domain chips, grouped filters). Band them as context so they can never fall
  // through to a severity color by accident.
  vulnerability: { badge: "bg-sky-500/10 text-sky-300 border-sky-500/30", solid: "bg-sky-500", text: "text-sky-300", hex: "#0ea5e9", label: "vulnerability", band: "unknown", bucket: "context_only" },
  attack_technique: { badge: "bg-violet-500/10 text-violet-300 border-violet-500/30", solid: "bg-violet-500", text: "text-violet-300", hex: "#8b5cf6", label: "attack technique", band: "unknown", bucket: "context_only" },
  technique_metadata: { badge: "bg-violet-500/10 text-violet-300 border-violet-500/30", solid: "bg-violet-500", text: "text-violet-300", hex: "#8b5cf6", label: "technique metadata", band: "unknown", bucket: "context_only" },
  technique_metadata_unavailable: { badge: "bg-violet-500/10 text-violet-300 border-violet-500/30", solid: "bg-violet-500", text: "text-violet-300", hex: "#8b5cf6", label: "technique metadata unavailable", band: "unknown", bucket: "context_only" },

  // ── Neutral / unresolved ──────────────────────────────────────────
  unknown: { badge: "bg-gray-500/10 text-gray-400 border-gray-500/30", solid: "bg-gray-500", text: "text-gray-400", hex: "#6b7280", label: "unknown", band: "unknown", bucket: "unknown" },
  unrated: { badge: "bg-gray-500/10 text-gray-400 border-gray-500/30", solid: "bg-gray-500", text: "text-gray-400", hex: "#6b7280", label: "unrated", band: "unknown", bucket: "unknown" },
  not_found: { badge: "bg-slate-500/10 text-slate-400 border-slate-500/30", solid: "bg-slate-500", text: "text-slate-400", hex: "#64748b", label: "not found", band: "unknown", bucket: "unknown" },
  not_configured: { badge: "bg-slate-500/10 text-slate-400 border-slate-500/30", solid: "bg-slate-500", text: "text-slate-400", hex: "#64748b", label: "not configured", band: "unknown", bucket: "unknown" },
  // Provider health, not a threat signal: amber draws the eye without implying the
  // indicator itself is suspicious, so the band stays neutral.
  rate_limited: { badge: "bg-amber-500/10 text-amber-300 border-amber-500/30", solid: "bg-amber-500", text: "text-amber-300", hex: "#f59e0b", label: "rate limited", band: "unknown", bucket: "unknown" },

  // ── Error states ──────────────────────────────────────────────────
  error: { badge: "bg-rose-950/40 text-rose-300 border-rose-400/50", solid: "bg-rose-500", text: "text-rose-300", hex: "#f43f5e", label: "error", band: "unknown", bucket: "error" },
  unavailable: { badge: "bg-rose-950/40 text-rose-300 border-rose-400/50", solid: "bg-rose-500", text: "text-rose-300", hex: "#f43f5e", label: "unavailable", band: "unknown", bucket: "error" },
};

/**
 * Buckets whose members carry no meaningful reputation score. A score of 0 on one
 * of these means "not assessed", not "clean", so score-driven widgets fall back to
 * the verdict band instead of painting them green.
 */
const SCORELESS_BUCKETS: readonly VerdictBucket[] = [
  "context_only",
  "malicious_test_artifact",
  "unknown",
  "error",
];

function normalizeVerdictKey(verdict: string | null | undefined): string {
  return (verdict ?? "").trim().toLowerCase().replace(/[\s-]+/g, "_");
}

/**
 * Resolve the canonical colors/label/band for a verdict string. Normalizes case,
 * whitespace and hyphens (to underscores) and falls back to `unknown` for
 * unrecognized verdicts.
 */
export function getVerdictColor(verdict: string | null | undefined): VerdictColor {
  const key = normalizeVerdictKey(verdict);
  return VERDICT_COLORS[key] ?? VERDICT_COLORS.unknown;
}

/** The canonical severity band for a verdict string. */
export function getVerdictBand(verdict: string | null | undefined): VerdictBand {
  return getVerdictColor(verdict).band;
}

/** The canonical aggregate bucket for a verdict string. */
export function getVerdictBucket(verdict: string | null | undefined): VerdictBucket {
  return getVerdictColor(verdict).bucket;
}

/**
 * True only for verdicts that really mean "this indicator is malicious". Use this
 * instead of verdict.includes("malicious"), which wrongly matches the
 * malicious_test_artifact sentinel.
 */
export function isMaliciousVerdict(verdict: string | null | undefined): boolean {
  return getVerdictBand(verdict) === "malicious";
}

/**
 * Display text for a verdict: the curated label when the verdict is known, else the
 * raw string with underscores rendered as spaces (so new backend vocabulary still
 * reads correctly instead of silently showing "unknown").
 */
export function formatVerdictLabel(verdict: string | null | undefined): string {
  const key = normalizeVerdictKey(verdict);
  if (!key) return VERDICT_COLORS.unknown.label;
  return VERDICT_COLORS[key]?.label ?? key.replace(/_/g, " ");
}

/** Colors for a band. */
export function getBandColor(band: VerdictBand): BandColor {
  return BAND_COLORS[band] ?? BAND_COLORS.unknown;
}

/**
 * The canonical band for a composite/threat score on the 0-100 display scale.
 * Missing, non-finite or negative scores are `unknown` — never `benign` — because
 * "we have no score" must not read as "this is clean".
 */
export function getScoreBand(score: number | null | undefined): VerdictBand {
  if (score == null || !Number.isFinite(score) || score < 0) return "unknown";
  for (const entry of SCORE_BANDS) {
    if (score >= entry.min) return entry.band;
  }
  return "unknown";
}

/**
 * Colors for a composite score. Pass the verdict too whenever it is available: for
 * verdicts that carry no reputation score (context only, the test sentinel,
 * unknown, provider errors) the verdict band wins, so a score of 0 on an
 * un-assessed indicator does not render as green "clean".
 */
export function getScoreColor(score: number | null | undefined, verdict?: string | null): BandColor {
  if (verdict != null && verdict !== "") {
    const resolved = getVerdictColor(verdict);
    if (SCORELESS_BUCKETS.includes(resolved.bucket)) return getBandColor(resolved.band);
  }
  return getBandColor(getScoreBand(score));
}

/** Inside the malicious band, is this the backend high-confidence step (>= 70)? */
export function isHighConfidenceScore(score: number | null | undefined): boolean {
  return score != null && Number.isFinite(score) && score >= HIGH_CONFIDENCE_SCORE;
}

/**
 * Screen-reader / tooltip wording for a score. Same banding as getScoreColor, with
 * the >= 70 confidence step spelled out in words rather than encoded as a hue.
 */
export function getScoreLabel(score: number | null | undefined, verdict?: string | null): string {
  const color = getScoreColor(score, verdict);
  if (color.band === "malicious" && isHighConfidenceScore(score)) return "malicious, high confidence";
  if (color.band === "unknown") return "not assessed";
  return color.label;
}
