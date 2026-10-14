import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import EnrichmentPanel from "../EnrichmentPanel";
import type { EnrichmentData } from "../../services/api";

const BASE = { open_ports: [], redirect_chain: [], url_preview: {}, relationships: [], extra: {} };

describe("EnrichmentPanel", () => {
  it("shows per-module collection status", () => {
    const enrichment = {
      ...BASE,
      completeness: { whois: "ok", passive_dns: "error" },
      whois: { registrar: "1API GmbH" },
    } as unknown as EnrichmentData;

    render(<EnrichmentPanel enrichment={enrichment} />);

    expect(screen.getByText("Collection status")).toBeTruthy();
    expect(screen.getByText(/Registration record: collected/)).toBeTruthy();
    expect(screen.getByText(/Passive DNS: failed/)).toBeTruthy();
  });

  it("preserves nested evidence as fields, not a JSON blob", () => {
    const enrichment = {
      ...BASE,
      completeness: { passive_dns: "ok" },
      passive_dns: { records: [{ hostname: "eclipsemanic.me", address: "185.199.109.153" }] },
      extra: { provider: { detail: "response available" } },
    } as unknown as EnrichmentData;

    render(<EnrichmentPanel enrichment={enrichment} />);

    // Values are visible without opening a disclosure.
    expect(screen.getByText(/185\.199\.109\.153/)).toBeTruthy();
    expect(screen.getAllByText("response available").length).toBeGreaterThan(0);
  });

  it("keeps raw JSON one click away", () => {
    const enrichment = {
      ...BASE,
      completeness: { whois: "ok" },
      whois: { registrar: "1API GmbH", creation_date: "2012-12-01T15:08:39Z" },
    } as unknown as EnrichmentData;

    render(<EnrichmentPanel enrichment={enrichment} iocType="domain" />);
    expect(screen.queryByText(/"1API GmbH"/)).toBeNull();
    fireEvent.click(screen.getAllByRole("button", { name: /raw json/i })[0]);
    expect(screen.getByText(/"1API GmbH"/)).toBeTruthy();
  });

  it("explains an empty tab when the backend skipped enrichment (phone)", () => {
    // Real output for a phone lookup: every module empty, completeness skipped.
    const enrichment = {
      ...BASE,
      breach: {}, email_security: {}, host_intel: {}, whois: {}, geoip: {},
      abuse_reports: [], malware_urls: [], associated_hashes: [], infostealer: {},
      host_ing_intel: {}, hosting_ip_intel: {}, analysis_notes: [],
      completeness: { enrichment: "skipped" },
    } as unknown as EnrichmentData;

    render(<EnrichmentPanel enrichment={enrichment} iocType="phone" />);

    expect(screen.getByText(/No enrichment data for this indicator/)).toBeTruthy();
    expect(screen.getByText(/not collected for phone/i)).toBeTruthy();
    // The point of the message: provider results are unaffected.
    expect(screen.getByText(/Investigation and Sources tabs are unaffected/)).toBeTruthy();
  });

  it("does not fabricate an identity-exposure panel when there is no breach data", () => {
    // Regression: the panel used to fire on iocType alone, rendering an all-zero
    // "Breach Count 0 / Source None / SPF Unavailable" block for phone lookups,
    // which reads as a finding rather than an absence.
    const enrichment = {
      ...BASE,
      completeness: { enrichment: "skipped" },
    } as unknown as EnrichmentData;

    render(<EnrichmentPanel enrichment={enrichment} iocType="phone" />);

    expect(screen.queryByText("Identity & Credential Exposure Summary")).toBeNull();
    expect(screen.queryByText("Breach Count")).toBeNull();
  });

  it("still shows the identity panel when breach data actually exists", () => {
    const enrichment = {
      ...BASE,
      breach: { breach_count: 7, source: "LeakCheck.io", exposed_data_types: ["password", "ip"] },
      email_security: { spf: "v=spf1 -all" },
      completeness: { breach: "ok" },
    } as unknown as EnrichmentData;

    render(<EnrichmentPanel enrichment={enrichment} iocType="email" />);

    expect(screen.getByText("Identity & Credential Exposure Summary")).toBeTruthy();
    // Breach count shows in the summary tile and again in the deep breach section.
    expect(screen.getAllByText("7").length).toBeGreaterThan(0);
    expect(screen.getAllByText("LeakCheck.io").length).toBeGreaterThan(0);
  });

  it("renders a module no purpose-built card claims, so backend additions stay visible", () => {
    const enrichment = {
      ...BASE,
      brand_new_module: { alpha: 1, beta: "two" },
      completeness: { brand_new_module: "ok" },
    } as unknown as EnrichmentData;

    render(<EnrichmentPanel enrichment={enrichment} iocType="domain" />);

    expect(screen.getByText("All Other Collected Data")).toBeTruthy();
    expect(screen.getByText("two")).toBeTruthy();
  });
});
