import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import SourcesPanel from "../SourcesPanel";
import type { LookupResponse } from "../../services/api";

const mockGetSourceInventory = vi.fn();
vi.mock("../../services/api", async () => {
  const actual = await vi.importActual<typeof import("../../services/api")>("../../services/api");
  return { ...actual, getSourceInventory: (...args: unknown[]) => mockGetSourceInventory(...args) };
});

const INVENTORY = {
  count: 5,
  available_count: 3,
  sources: [
    { name: "AbstractAPI", supported_types: ["email"], public_without_key: false, configured: true, available: true, credential_env: "ABSTRACTAPI_EMAIL_KEY", credential_source: ".env" },
    { name: "AbstractAPI IP", supported_types: ["ipv4", "ipv6"], public_without_key: false, configured: true, available: true, credential_env: "ABSTRACTAPI_IP_KEY", credential_source: ".env" },
    { name: "AbstractAPI Phone", supported_types: ["phone"], public_without_key: false, configured: true, available: true, credential_env: "ABSTRACTAPI_No_KEY", credential_source: ".env" },
    { name: "GreyNoise", supported_types: ["ipv4", "ipv6"], public_without_key: false, configured: false, available: false, credential_env: "GREYNOISE_API_KEY", credential_source: "" },
    { name: "VirusTotal", supported_types: ["domain", "ipv4"], public_without_key: false, configured: true, available: true, credential_env: "VT_API_KEY", credential_source: "env" },
  ],
};

function makeResult(overrides: Partial<LookupResponse> = {}): LookupResponse {
  return {
    ioc: "8.8.8.8",
    input: "8.8.8.8",
    normalized: "8.8.8.8",
    ioc_type: "ipv4",
    composite: { verdict: "suspicious", score: 55 },
    results: [
      {
        ioc: "8.8.8.8",
        ioc_type: "ipv4",
        source: "AbstractAPI IP",
        verdict: "suspicious",
        normalized_verdict: "suspicious",
        status: "found",
        execution_state: "success",
        raw_score: 0.4,
        confidence: "medium",
        tags: ["abstractip:vpn:true"],
        latency_ms: 420,
        raw_data: { security: { is_vpn: true, is_proxy: false }, asn: { asn: 136787, name: "PacketHub S.A." } },
      },
      {
        ioc: "8.8.8.8",
        ioc_type: "ipv4",
        source: "VirusTotal",
        verdict: "unknown",
        status: "rate_limited",
        execution_state: "rate_limited",
        raw_score: 0,
        confidence: "low",
        tags: ["rate_limited"],
        retry_after_seconds: 60,
      },
    ],
    provider_health: [
      { source: "AbstractAPI IP", request_count: 1, success_count: 1, failure_count: 0, rate_limit_count: 0, cache_hit_count: 0 },
    ],
    final_assessment: {
      verdict: "suspicious",
      confidence: "medium",
      normalized_score: 55,
      coverage: 0.5,
      cache_status: "miss",
      assessment_domain: "ioc_reputation",
      provider_health: [],
      provider_plan: [{ provider: "AbstractAPI", applicable: false }],
    },
    ...overrides,
  } as unknown as LookupResponse;
}

beforeEach(() => {
  mockGetSourceInventory.mockReset();
  mockGetSourceInventory.mockResolvedValue(INVENTORY);
});

describe("SourcesPanel (merged Evidence + Raw Data)", () => {
  it("shows the payload fields of a provider next to its verdict", async () => {
    render(<SourcesPanel result={makeResult()} />);
    await waitFor(() => expect(screen.getByText("PacketHub S.A.")).toBeTruthy());
    expect(screen.getByText("Is VPN")).toBeTruthy();
    // A field count is surfaced so an analyst knows there is something to read.
    expect(screen.getAllByText(/\d+ fields/).length).toBeGreaterThan(0);
  });
  it("reports a provider that failed instead of pretending it found nothing", async () => {
    render(<SourcesPanel result={makeResult()} />);
    await waitFor(() => expect(screen.getAllByText("VirusTotal").length).toBeGreaterThan(0));
    expect(screen.getAllByText(/Rate Limited/i).length).toBeGreaterThan(0);
  });
  it("notifies about an API key that was never used", async () => {
    render(<SourcesPanel result={makeResult()} />);
    await waitFor(() => expect(screen.getByText(/Credentials not used for this lookup/i)).toBeTruthy());
    // Supports ipv4 but has no key configured, so it was never called.
    expect(screen.getByText("GreyNoise")).toBeTruthy();
    expect(screen.getByText("Key missing")).toBeTruthy();
    expect(screen.getByText("GREYNOISE_API_KEY")).toBeTruthy();
  });
  it("separates a spent-but-failed key from an idle one", async () => {
    render(<SourcesPanel result={makeResult()} />);
    await waitFor(() => expect(screen.getByText(/Credentials not used for this lookup/i)).toBeTruthy());
    const block = screen.getByLabelText("Unused credentials");
    // A spent-and-failed key is listed once, and not also as an idle key.
    expect(within(block).getAllByText("Call failed")).toHaveLength(1);
    expect(within(block).getByText(/Key is configured and was spent/)).toBeTruthy();
    expect(within(block).getAllByText("Key missing")).toHaveLength(1);
  });
  it("does not report an applicable source that answered as unused", async () => {
    render(<SourcesPanel result={makeResult()} />);
    await waitFor(() => expect(screen.getByText(/Credentials not used for this lookup/i)).toBeTruthy());
    const block = screen.getByLabelText("Unused credentials");
    // AbstractAPI IP answered, so it must not appear as an unused credential.
    expect(within(block).queryByText("AbstractAPI IP")).toBeNull();
  });
  it("lists sources ruled out by capability and notes their idle keys", async () => {
    render(<SourcesPanel result={makeResult()} />);
    await waitFor(() => expect(screen.getByText(/Not applicable for ipv4/i)).toBeTruthy());
    expect(screen.getByText("AbstractAPI")).toBeTruthy();
    // A configured key that went unspent because the type does not apply.
    expect(screen.getByText(/hold a configured key that was not spent/)).toBeTruthy();
    expect(screen.getByText(/AbstractAPI Phone/)).toBeTruthy();
  });
  it("keeps the raw JSON one click away rather than the only view", async () => {
    render(<SourcesPanel result={makeResult()} />);
    await waitFor(() => expect(screen.getByText("PacketHub S.A.")).toBeTruthy());
    expect(screen.queryByText(/"PacketHub S.A."|asn/)).toBeNull();
    fireEvent.click(screen.getAllByRole("button", { name: /raw json/i })[0]);
    expect(screen.getByText(/"PacketHub S.A."/)).toBeTruthy();
  });

  it("filters the provider list", async () => {
    render(<SourcesPanel result={makeResult()} />);
    await waitFor(() => expect(screen.getAllByText("VirusTotal").length).toBeGreaterThan(0));
    fireEvent.change(screen.getByLabelText("Filter providers"), { target: { value: "abstractapi" } });
    const list = within(screen.getByLabelText("Provider responses"));
    expect(list.getByText("PacketHub S.A.")).toBeTruthy();
    expect(list.queryByText("VirusTotal")).toBeNull();
  });
  it("shows the at-a-glance counters", async () => {
    render(<SourcesPanel result={makeResult()} />);
    await waitFor(() => expect(screen.getByText("answered")).toBeTruthy());
    expect(screen.getByText("keys missing")).toBeTruthy();
    expect(screen.getByText("failed")).toBeTruthy();
  });

  it("survives a result with no provider responses", async () => {
    mockGetSourceInventory.mockResolvedValue({ count: 0, available_count: 0, sources: [] });
    render(<SourcesPanel result={makeResult({ results: [], provider_health: [] })} />);
    await waitFor(() => expect(screen.getByText(/No provider produced a response/i)).toBeTruthy());
  });
});
