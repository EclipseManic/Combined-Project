import { describe, expect, it } from "vitest";
import {
  describeEmptyState,
  isEnrichmentEmpty,
  keysRenderedByCards,
  parseCollectionStatus,
} from "../enrichment";
import type { EnrichmentData } from "../../services/api";

const EMPTY_SHAPES = {
  open_ports: [],
  redirect_chain: [],
  url_preview: {},
  relationships: [],
  extra: {},
  breach: {},
  email_security: {},
  host_intel: {},
  whois: {},
  geoip: {},
  abuse_reports: [],
  malware_urls: [],
  associated_hashes: [],
  infostealer: {},
  hosting_ip_intel: {},
  analysis_notes: [],
};

describe("parseCollectionStatus", () => {
  it("reads a domain collection audit", () => {
    const status = parseCollectionStatus({
      completeness: { whois: "ok", dns: "ok", ssl: "ok", subdomains: "ok", favicon: "not_found" },
    } as unknown as EnrichmentData);
    expect(status.ok).toBe(4);
    expect(status.notFound).toBe(1);
    expect(status.modules.find((m) => m.module === "favicon")?.state).toBe("not_found");
    expect(status.summary).toContain("4 module(s) collected");
  });

  it("reads an IP collection audit including the port_scan alias", () => {
    const status = parseCollectionStatus({
      completeness: { geoip: "unavailable", reverse_dns: "ok", whois: "unavailable", host_intel: "ok", port_scan: "ok" },
    } as unknown as EnrichmentData);
    expect(status.ok).toBe(3);
    expect(status.unavailable).toBe(2);
  });

  it("maps a phone lookup's skipped enrichment", () => {
    const status = parseCollectionStatus({ completeness: { enrichment: "skipped" } } as unknown as EnrichmentData);
    expect(status.skipped).toBe(1);
    expect(status.ok).toBe(0);
    expect(status.summary).toContain("skipped");
  });

  it("normalises synonyms and unknown words", () => {
    const status = parseCollectionStatus({
      completeness: { whois: "success", dns: "no_data", ssl: "unsupported", subdomains: "timeout", favicon: "weird" },
    } as unknown as EnrichmentData);
    expect(status.modules.map((m) => m.state)).toEqual(["ok", "not_found", "unavailable", "error"]);
    // An unrecognised word is not reported rather than guessed at.
    expect(status.modules).toHaveLength(4);
  });

  it("reports no audit rather than inventing one", () => {
    const status = parseCollectionStatus({} as unknown as EnrichmentData);
    expect(status.modules).toHaveLength(0);
    expect(status.summary).toContain("No collection audit");
  });
});

describe("isEnrichmentEmpty", () => {
  it("treats a fully empty phone payload as empty", () => {
    // Regression: `completeness` describes collection rather than being
    // collected data, and treating it as a non-empty entry made every payload
    // look populated, so the empty state never rendered.
    expect(isEnrichmentEmpty({ ...EMPTY_SHAPES, completeness: { enrichment: "skipped" } } as unknown as EnrichmentData)).toBe(true);
  });

  it("is not fooled by the completeness audit alone", () => {
    expect(isEnrichmentEmpty({ completeness: { whois: "ok" } } as unknown as EnrichmentData)).toBe(true);
  });

  it("is false when any module has data", () => {
    expect(isEnrichmentEmpty({ ...EMPTY_SHAPES, whois: { registrar: "x" } } as unknown as EnrichmentData)).toBe(false);
  });

  it("is false when a nested object is non-empty", () => {
    expect(isEnrichmentEmpty({ ...EMPTY_SHAPES, host_intel: { open_ports: [53] } } as unknown as EnrichmentData)).toBe(false);
  });

  it("handles a missing payload", () => {
    expect(isEnrichmentEmpty(undefined)).toBe(true);
  });
});

describe("describeEmptyState", () => {
  it("distinguishes skipped from found-nothing", () => {
    const skipped = describeEmptyState({ completeness: { enrichment: "skipped" } } as unknown as EnrichmentData, "phone");
    const notFound = describeEmptyState(
      { ...EMPTY_SHAPES, completeness: { whois: "not_found", dns: "not_found" } } as unknown as EnrichmentData,
      "domain",
    );
    expect(skipped).toMatch(/not collected for phone/i);
    expect(skipped).toMatch(/unaffected/i);
    expect(notFound).toMatch(/real negative result/i);
  });

  it("distinguishes a collection failure from absence of data", () => {
    const message = describeEmptyState(
      { ...EMPTY_SHAPES, completeness: { whois: "unavailable", dns: "error" } } as unknown as EnrichmentData,
      "domain",
    );
    expect(message).toMatch(/collection failure/i);
  });
});

describe("keysRenderedByCards", () => {
  it("claims keys a purpose-built card will show", () => {
    const rendered = keysRenderedByCards({
      ...EMPTY_SHAPES,
      whois: { registrar: "x" },
      open_ports: [53, 443],
      abuse_reports: [{ reporter_country: "US" }],
    } as unknown as EnrichmentData);
    expect(rendered.has("whois")).toBe(true);
    // host_intel is empty but the legacy open_ports list is not, so the matrix
    // card will render and both keys are claimed.
    expect(rendered.has("open_ports")).toBe(true);
    expect(rendered.has("host_intel")).toBe(true);
    expect(rendered.has("abuse_reports")).toBe(true);
  });

  it("does not claim keys with no data", () => {
    const rendered = keysRenderedByCards({ ...EMPTY_SHAPES } as unknown as EnrichmentData);
    expect(rendered.size).toBe(0);
  });

  it("does not claim a key for an empty object", () => {
    const rendered = keysRenderedByCards({ ...EMPTY_SHAPES, whois: {} } as unknown as EnrichmentData);
    expect(rendered.has("whois")).toBe(false);
  });
});
