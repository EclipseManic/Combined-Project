// Enrichment module bookkeeping.
//
// Two problems this solves, both observed in the real API output:
//
// 1. The backend always returns the same ~23 enrichment keys for every IOC type,
//    most of them empty. The panel filtered on truthiness, so a phone lookup —
//    where the backend reports `completeness: {enrichment: "skipped"}` and
//    nothing else — rendered a near-blank tab with no explanation. An empty tab
//    must say *why* it is empty; "skipped" and "unavailable" are very different
//    answers for an analyst.
//
// 2. Sections rendered nested objects with JSON.stringify, so a deep module like
//    host_intel or whois was a wall of braces. Depth is what this tab is for.

import type { EnrichmentData } from "../services/api";

/** Stable, analyst-facing titles for every enrichment module. */
export const ENRICHMENT_MODULES: { key: string; title: string }[] = [
  { key: "geoip", title: "IP geolocation" },
  { key: "whois", title: "Registration record" },
  { key: "dns", title: "DNS records" },
  { key: "reverse_dns", title: "Reverse DNS" },
  { key: "ssl", title: "TLS certificate" },
  { key: "subdomains", title: "Subdomains" },
  { key: "favicon", title: "Favicon" },
  { key: "passive_dns", title: "Passive DNS" },
  { key: "redirect_chain", title: "Redirect chain" },
  { key: "url_preview", title: "URL preview" },
  { key: "web_preview", title: "Web preview" },
  { key: "host_intel", title: "Host attack surface" },
  { key: "open_ports", title: "Open ports" },
  { key: "hosting_ip_intel", title: "Hosting IP intelligence" },
  { key: "open_ports_scan", title: "Port scan" },
  { key: "abuse_reports", title: "Abuse reports" },
  { key: "infostealer", title: "Infostealer exposure" },
  { key: "breach", title: "Breach exposure" },
  { key: "email_security", title: "Email security" },
  { key: "cve", title: "CVE context" },
  { key: "malware_urls", title: "Malicious URLs" },
  { key: "associated_hashes", title: "Associated hashes" },
  { key: "extra", title: "Indicator context" },
  { key: "relationships", title: "Relationships" },
  { key: "analysis_notes", title: "Analyst notes" },
];

export type ModuleState = "ok" | "not_found" | "unavailable" | "skipped" | "error";

export interface CollectionStatus {
  /** Per-module state, in module declaration order. */
  modules: { module: string; title: string; state: ModuleState }[];
  ok: number;
  notFound: number;
  unavailable: number;
  skipped: number;
  error: number;
  /** One-sentence explanation of the overall outcome. */
  summary: string;
}

const STATE_LABEL: Record<ModuleState, string> = {
  ok: "collected",
  not_found: "no data",
  unavailable: "source unavailable",
  skipped: "not applicable",
  error: "failed",
};

export const MODULE_STATE_LABEL = STATE_LABEL;

function normaliseState(value: unknown): ModuleState | null {
  if (typeof value !== "string") return null;
  const text = value.trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (["ok", "success", "found", "complete", "completed"].includes(text)) return "ok";
  if (["not_found", "none", "empty", "no_data", "no_results"].includes(text)) return "not_found";
  if (["unavailable", "disabled", "off", "unsupported"].includes(text)) return "unavailable";
  if (["skipped", "not_applicable", "skipped_type"].includes(text)) return "skipped";
  if (["error", "failed", "timeout", "rate_limited"].includes(text)) return "error";
  return null;
}

export function parseCollectionStatus(enrichment: EnrichmentData | undefined): CollectionStatus {
  const completeness = enrichment?.completeness ?? {};
  const modules: { module: string; title: string; state: ModuleState }[] = [];

  for (const { key, title } of ENRICHMENT_MODULES) {
    // `completeness` is keyed by module name, occasionally by an alias
    // (port_scan for open_ports, host_intel for the Shodan block).
    const raw =
      completeness[key] ??
      (key === "open_ports" ? completeness.port_scan : undefined) ??
      (key === "extra" ? completeness.enrichment : undefined);
    const state = normaliseState(raw);
    if (state) modules.push({ module: key, title, state });
  }

  const count = (state: ModuleState) => modules.filter((item) => item.state === state).length;
  const ok = count("ok");
  const notFound = count("not_found");
  const unavailable = count("unavailable");
  const skipped = count("skipped");
  const error = count("error");

  let summary: string;
  if (modules.length === 0) summary = "No collection audit was reported for this lookup.";
  else if (ok === 0 && skipped > 0)
    summary = `Enrichment was skipped for this indicator type — ${skipped} module(s) do not apply. Provider results are unaffected.`;
  else if (ok === 0)
    summary = `No enrichment module returned data. ${notFound} found nothing, ${unavailable} unavailable, ${error} failed.`;
  else summary = `${ok} module(s) collected; ${notFound} found nothing; ${unavailable} unavailable; ${skipped} not applicable${error ? `; ${error} failed` : ""}.`;

  return { modules, ok, notFound, unavailable, skipped, error, summary };
}

/** True when every collected module came back empty. */
export function isEnrichmentEmpty(enrichment: EnrichmentData | undefined): boolean {
  if (!enrichment) return true;
  // `completeness` describes collection, it is not collected data, so it must be
  // excluded before testing — returning false for it inside `every` would mark
  // the whole payload as non-empty.
  const modules = Object.entries(enrichment).filter(([key]) => key !== "completeness");
  if (modules.length === 0) return true;
  return modules.every(([, value]) => {
    if (value === null || value === undefined || value === "") return true;
    if (Array.isArray(value)) return value.length === 0;
    if (typeof value === "object") return Object.keys(value as object).length === 0;
    return false;
  });
}

/**
 * Why the tab looks the way it does. Distinguishes "the backend never tried"
 * from "it tried and found nothing", which are different operational facts.
 */
export function describeEmptyState(enrichment: EnrichmentData | undefined, iocType?: string): string {
  const status = parseCollectionStatus(enrichment);
  if (status.skipped > 0 && status.ok === 0) {
    return `Enrichment is not collected for ${iocType ?? "this indicator type"} — the backend skipped every module. The provider results on the Investigation and Sources tabs are unaffected.`;
  }
  if (status.unavailable > 0 && status.ok === 0) {
    return `Every enrichment source was unavailable for this lookup. This is a collection failure, not an absence of intelligence.`;
  }
  if (status.notFound > 0 && status.ok === 0) {
    return `Every enrichment module ran and found nothing for this indicator. That is a real negative result, not a collection failure.`;
  }
  return `No enrichment data was returned for this indicator.`;
}

/**
 * Keys already rendered by a hand-written card. Used to keep the generic deep
 * dump from repeating what a purpose-built card has already shown.
 */
export function keysRenderedByCards(enrichment: EnrichmentData | undefined): Set<string> {
  const rendered = new Set<string>();
  const has = (key: keyof EnrichmentData) => {
    const value = enrichment?.[key] as unknown;
    if (value === null || value === undefined || value === "") return false;
    if (Array.isArray(value)) return value.length > 0;
    if (typeof value === "object") return Object.keys(value as object).length > 0;
    return true;
  };
  if (has("geoip")) rendered.add("geoip");
  if (has("web_preview")) rendered.add("web_preview");
  if (has("infostealer")) rendered.add("infostealer");
  if (has("host_intel") || has("open_ports")) {
    rendered.add("host_intel");
    rendered.add("open_ports");
  }
  if (has("abuse_reports")) rendered.add("abuse_reports");
  if (has("hosting_ip_intel")) rendered.add("hosting_ip_intel");
  if (has("malware_urls")) rendered.add("malware_urls");
  if (has("associated_hashes")) rendered.add("associated_hashes");
  if (has("whois")) rendered.add("whois");
  if (has("breach")) rendered.add("breach");
  if (has("email_security")) rendered.add("email_security");
  for (const key of ["dns", "ssl", "reverse_dns", "subdomains", "cve", "passive_dns", "favicon"] as const) {
    if (has(key)) rendered.add(key);
  }
  if (has("url_preview")) rendered.add("url_preview");
  if (has("redirect_chain")) rendered.add("redirect_chain");
  if (has("relationships")) rendered.add("relationships");
  if (has("analysis_notes")) rendered.add("analysis_notes");
  return rendered;
}
