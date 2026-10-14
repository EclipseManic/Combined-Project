// Generic renderer input for provider payloads.
//
// Why this exists: SourceCard only knows how to display a fixed handful of
// well-known fields (detection_count, malware_family, first_seen, …). Anything a
// provider returns outside that whitelist lands in `raw_data` and used to be
// shown as a JSON blob behind a "Details" disclosure, so a perfectly good answer
// (carrier name, line type, ASN, MX status) was effectively hidden from the
// analyst. `enrichment.extra.*` was the only other route, and that requires a
// hand-written card per data shape.
//
// This module flattens an arbitrary JSON payload into labelled sections and
// rows so ANY provider's response can be displayed as fields. It is purely
// structural: it never special-cases a provider or a field name, so a new
// adapter gets readable output with no UI change.

import { titleCase } from "./format";

/** Words that must not be title-cased into the wrong initialism. */
const ACRONYMS: Record<string, string> = {
  ip: "IP", ipv4: "IPv4", ipv6: "IPv6", vpn: "VPN", tor: "TOR", asn: "ASN",
  mcc: "MCC", mnc: "MNC", sms: "SMS", hlr: "HLR", voip: "VoIP", mx: "MX",
  spf: "SPF", dmarc: "DMARC", dkim: "DKIM", url: "URL", api: "API", id: "ID",
  e164: "E.164", osint: "OSINT", cve: "CVE", cpe: "CPE", tld: "TLD",
  utc: "UTC", iso: "ISO", sha: "SHA", md: "MD", ttl: "TTL", bgp: "BGP",
  rdns: "rDNS", sso: "SSO", mfa: "MFA", otp: "OTP", tld2: "TLD",
};

/** Rows rendered per section before the remainder is summarised. */
const MAX_ROWS_PER_SECTION = 14;
/** Nesting levels walked before a sub-object is summarised instead of expanded. */
const MAX_DEPTH = 3;
/** Items listed from an array before the remainder is summarised. */
const MAX_ITEMS = 10;

export interface PayloadRow {
  label: string;
  /** Rendered text for a scalar. */
  value?: string;
  /** Entries for an array of scalars or objects. */
  items?: string[];
  /** Nested rows for an object. */
  children?: PayloadRow[];
  /** Set when the scalar is the boolean `true`, so it can be emphasised. */
  flag?: boolean;
  /** Set when the scalar is the boolean `false`. */
  muted?: boolean;
  /** Set when a sub-value was dropped for being too deep or too long. */
  truncated?: boolean;
}

export interface PayloadSection {
  label: string;
  rows: PayloadRow[];
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** snake_case / kebab-case key -> "Is VPN" rather than "Is Vpn". */
export function humanizeKey(key: string): string {
  const titled = titleCase(key);
  if (titled === "—" || !titled) return String(key);
  return titled
    .split(" ")
    .map((word) => ACRONYMS[word.toLowerCase()] ?? word)
    .join(" ");
}

function isEmpty(value: unknown): boolean {
  if (value === null || value === undefined || value === "") return true;
  if (Array.isArray(value)) return value.filter((item) => !isEmpty(item)).length === 0;
  if (isPlainObject(value)) return Object.values(value).filter((item) => !isEmpty(item)).length === 0;
  return false;
}

/**
 * Renders a number without locale digit grouping.
 *
 * `formatValue` (used for tag attributes) groups thousands, which is right for
 * a detection count but actively corrupts the identifiers that dominate
 * provider payloads: an ASN of 136787 was being displayed as "1,36,787" under
 * some locales, and geoname IDs and postal codes are likewise identifiers
 * rather than quantities.
 */
function plainNumber(value: number): string {
  if (!Number.isFinite(value)) return "—";
  if (Number.isInteger(value)) return String(value);
  // Avoid float artefacts such as 25.761700000000003.
  return String(Number(value.toFixed(6)));
}

function scalarText(value: unknown, maxItems = MAX_ITEMS): string {
  if (typeof value === "number") return plainNumber(value);
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "string") return value;
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) {
    const items = value.filter((item) => !isEmpty(item)).map((item) => scalarText(item, 3));
    if (items.length === 0) return "—";
    const shown = items.slice(0, maxItems).join(", ");
    return items.length > maxItems ? `${shown} +${items.length - maxItems} more` : shown;
  }
  if (isPlainObject(value)) {
    const entries = Object.entries(value).filter(([, item]) => !isEmpty(item));
    if (entries.length === 0) return "—";
    return entries.slice(0, maxItems).map(([key, item]) => `${key}: ${scalarText(item, 3)}`).join("; ");
  }
  return String(value);
}

function scalarRow(key: string, value: unknown): PayloadRow {
  if (typeof value === "boolean") {
    return { label: humanizeKey(key), value: value ? "Yes" : "No", flag: value, muted: !value };
  }
  return { label: humanizeKey(key), value: scalarText(value) };
}

/** Render one value into one or more rows (a list expands to a single row). */
function rowsForValue(key: string, value: unknown, depth: number): PayloadRow[] {
  if (isEmpty(value)) return [];

  if (Array.isArray(value)) {
    return [rowsForArray(key, value, depth)];
  }

  if (isPlainObject(value)) {
    if (depth >= MAX_DEPTH) {
      return [{ label: humanizeKey(key), value: scalarText(value, 3), truncated: true }];
    }
    return [{ label: humanizeKey(key), children: rowsForObject(value, depth + 1) }];
  }

  return [scalarRow(key, value)];
}

/** Keys that usefully name an object inside a list. */
const NAME_KEYS = ["name", "title", "id", "domain", "value", "ip_address", "phone_number", "email_address", "cve_id", "carrier", "type"];

function firstUsefulKey(item: Record<string, unknown>): string | undefined {
  return NAME_KEYS.find((key) => typeof item[key] === "string" && item[key] !== "");
}

function rowsForObject(value: Record<string, unknown>, depth: number): PayloadRow[] {
  const rows: PayloadRow[] = [];
  for (const [key, child] of Object.entries(value)) {
    rows.push(...rowsForValue(key, child, depth));
  }
  return rows;
}

/**
 * One row per array item, each labelled by a descriptive field from the item
 * (its ``name``/``domain``/``id``…) with the remaining fields nested beneath.
 */
function rowsForArrayItems(items: unknown[], depth: number): PayloadRow[] {
  return items.slice(0, MAX_ITEMS).map((item, index) => {
    if (isPlainObject(item)) {
      const nameKey = firstUsefulKey(item);
      return {
        label: nameKey ? String(item[nameKey]) : `#${index + 1}`,
        children: rowsForObject(item, depth + 1),
      };
    }
    return scalarRow(`#${index + 1}`, item);
  });
}

function rowsForArray(key: string, value: unknown[], depth: number): PayloadRow {
  const items = value.filter((item) => !isEmpty(item));
  if (items.every((item) => !isPlainObject(item) && !Array.isArray(item))) {
    return {
      label: humanizeKey(key),
      items: items.slice(0, MAX_ITEMS).map((item) => scalarText(item, 3)),
      truncated: items.length > MAX_ITEMS,
    };
  }
  if (depth >= MAX_DEPTH) {
    return { label: humanizeKey(key), value: scalarText(value, 3), truncated: true };
  }
  return {
    label: humanizeKey(key),
    children: rowsForArrayItems(items, depth + 1),
    truncated: items.length > MAX_ITEMS,
  };
}

/**
 * Split a provider payload into displayable sections.
 *
 * Each top-level key becomes its own section so a response like
 * `{security: {...}, asn: {...}}` reads as two labelled blocks rather than one
 * wall. Top-level scalars are collected into a single "Response" section.
 * Returns an empty array when there is nothing worth showing.
 */
export function buildPayloadSections(raw: unknown): PayloadSection[] {
  if (!isPlainObject(raw)) return [];
  const sections: PayloadSection[] = [];
  const looseRows: PayloadRow[] = [];

  for (const [key, value] of Object.entries(raw)) {
    if (isEmpty(value)) continue;
    if (isPlainObject(value)) {
      // The section label is the key, so its rows are the object's own fields
      // rather than one row that wraps them a second time.
      const rows = rowsForObject(value, 1);
      if (rows.length > 0) sections.push({ label: humanizeKey(key), rows });
    } else if (Array.isArray(value) && value.some((item) => isPlainObject(item))) {
      const items = value.filter((item) => !isEmpty(item));
      const rows = items.length > MAX_ITEMS
        ? rowsForArrayItems(items, 1).concat([{ label: `+${items.length - MAX_ITEMS} more`, value: "not shown" }])
        : rowsForArrayItems(items, 1);
      if (rows.length > 0) sections.push({ label: humanizeKey(key), rows });
    } else {
      looseRows.push(...rowsForValue(key, value, 1));
    }
  }

  if (looseRows.length > 0) {
    sections.unshift({ label: "Response", rows: looseRows });
  }
  return sections;
}

/** Total scalar+list leaves across all sections; drives the "shown / total" note. */
export function countPayloadFields(sections: PayloadSection[]): number {
  const walk = (rows: PayloadRow[]): number =>
    rows.reduce((total, row) => total + 1 + (row.children ? walk(row.children) : 0), 0);
  return sections.reduce((total, section) => total + walk(section.rows), 0);
}

/** Sections trimmed to the per-section row budget, reporting what was hidden. */
export function limitPayloadSections(sections: PayloadSection[]): { sections: PayloadSection[]; hidden: number } {
  let hidden = 0;
  const limited = sections.map((section) => {
    if (section.rows.length <= MAX_ROWS_PER_SECTION) return section;
    hidden += section.rows.length - MAX_ROWS_PER_SECTION;
    return { ...section, rows: section.rows.slice(0, MAX_ROWS_PER_SECTION) };
  });
  return { sections: limited, hidden };
}
