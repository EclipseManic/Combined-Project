import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Every batch filter, verified against a dummy dataset built so each filter has
 * exactly one discriminating row.
 *
 * Coverage boundaries are tested on purpose: risk uses score < 30 / < 70 and
 * coverage uses < 0.5, so rows sitting exactly on 30, 70 and 0.5 prove which
 * side of the boundary they land on.
 */

const mocks = vi.hoisted(() => ({
  getBatchStatus: vi.fn(),
  getBatchResult: vi.fn(),
  showToast: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number;
    constructor(message: string, status: number) {
      super(message);
      this.status = status;
    }
  },
}));

vi.mock("../../services/api", () => ({
  ApiError: mocks.ApiError,
  errorMessage: (e: unknown, f = "Request failed") => (e instanceof Error && e.message ? e.message : f),
  startBatch: vi.fn(),
  getBatchStatus: mocks.getBatchStatus,
  getBatchResult: mocks.getBatchResult,
  cancelBatch: vi.fn(),
  uploadBatchFile: vi.fn(),
  saveBatchHistory: vi.fn(),
  buildLookupResponseFromBatch: vi.fn(() => ({}) as never),
}));

vi.mock("../../components/Toast", () => ({ showToast: mocks.showToast }));

vi.mock("../../components/IocAssessmentCard", () => ({
  default: ({ assessment }: { assessment: { ioc: string } }) => (
    <div data-testid="card">{assessment.ioc}</div>
  ),
}));

import Batch from "../Batch";

interface Row {
  ioc: string;
  type?: string;
  verdict: string;
  domain?: string;
  confidence?: string;
  score?: number;
  coverage?: number;
  freshness?: string;
  review?: boolean;
  malware?: string[];
  status?: string;
  provider?: string;
  expected?: number;
  evaluated?: number;
  rateLimited?: string[];
  unavailable?: string[];
  errors?: string[];
}

/**
 * 13 rows, chosen so every filter has an unambiguous answer.
 *
 * Boundary rows: risk30, risk70, coverage0.5 -- riskMatches uses `score < 30`,
 * `score >= 70` and coverage `>= 0.5`.
 */
const ROWS: Row[] = [
  // verdict: malicious / breached / suspicious / clean / context_only / unknown
  { ioc: "mal-domain", type: "domain", verdict: "malicious", confidence: "high", score: 90, coverage: 1.0, freshness: "fresh", review: true, malware: ["Emotet"], provider: "VirusTotal" },
  { ioc: "pwned-mail", type: "email", verdict: "breached", domain: "credential_exposure", confidence: "medium", score: 60, coverage: 1.0, freshness: "cached", provider: "HIBP" },
  { ioc: "susp-ip", type: "ipv4", verdict: "suspicious", confidence: "low", score: 45, coverage: 0.4, freshness: "fresh", provider: "GreyNoise", rateLimited: ["VirusTotal"] },
  { ioc: "cve-critical", type: "cve", verdict: "critical", domain: "vulnerability", confidence: "high", score: 95, coverage: 0.9, freshness: "fresh", review: true, provider: "NVD" },
  { ioc: "cve-medium", type: "cve", verdict: "medium", domain: "vulnerability", confidence: "medium", score: 50, coverage: 0.8, freshness: "fresh", provider: "NVD" },
  { ioc: "clean-host", type: "domain", verdict: "clean", confidence: "high", score: 5, coverage: 1.0, freshness: "fresh", provider: "VirusTotal" },
  { ioc: "ctx-ip", type: "ipv4", verdict: "context_only", confidence: "low", score: 10, coverage: 1.0, freshness: "fresh", provider: "IPinfo" },
  // risk boundary rows
  { ioc: "risk-29", type: "ipv4", verdict: "suspicious", confidence: "low", score: 29, coverage: 1.0, freshness: "fresh", provider: "Shodan" },
  { ioc: "risk-30", type: "ipv4", verdict: "suspicious", confidence: "low", score: 30, coverage: 1.0, freshness: "fresh", provider: "Shodan" },
  { ioc: "risk-69", type: "ipv4", verdict: "suspicious", confidence: "low", score: 69, coverage: 1.0, freshness: "fresh", provider: "Shodan" },
  { ioc: "risk-70", type: "ipv4", verdict: "suspicious", confidence: "low", score: 70, coverage: 1.0, freshness: "fresh", provider: "Shodan" },
  // coverage boundary rows
  { ioc: "cov-049", type: "domain", verdict: "unknown", confidence: "low", score: 0, coverage: 0.49, freshness: "fresh", provider: "VirusTotal" },
  { ioc: "cov-050", type: "domain", verdict: "unknown", confidence: "low", score: 0, coverage: 0.5, freshness: "fresh", provider: "VirusTotal" },
  // freshness + review + malware
  { ioc: "stale-ip", type: "ipv4", verdict: "malicious", confidence: "high", score: 75, coverage: 0.2, freshness: "historical", review: true, malware: ["TrickBot"], provider: "AbuseIPDB" },
  // provider-level failures, each in a different bucket
  { ioc: "prov-unavail", type: "domain", verdict: "unknown", confidence: "low", score: 0, coverage: 0.9, freshness: "fresh", provider: "Censys", unavailable: ["Censys"] },
  { ioc: "prov-error", type: "domain", verdict: "unknown", confidence: "low", score: 0, coverage: 0.9, freshness: "fresh", provider: "Shodan", errors: ["Shodan"] },
  // whole-lookup outcomes that had no dropdown entry at all
  { ioc: "lookup-error", type: "ipv4", verdict: "unknown", confidence: "low", score: 0, coverage: 0, freshness: "unavailable", provider: "GreyNoise", status: "error" },
  { ioc: "lookup-cancelled", type: "ipv4", verdict: "unknown", confidence: "low", score: 0, coverage: 0, freshness: "unavailable", provider: "GreyNoise", status: "cancelled" },
  { ioc: "lookup-notapplicable", type: "ipv4", verdict: "context_only", confidence: "low", score: 0, coverage: 0, freshness: "unavailable", provider: "GreyNoise", status: "not_applicable" },
];

function makeResult() {
  const base = {
    assessment_domain: "ioc_reputation",
    evidence_strength: 0.5,
    needs_review: false,
    cache_status: "fresh",
    provider_breakdown: [],
    provider_health: [],
    malicious_sources: [],
    suspicious_sources: [],
    clean_sources: [],
    unknown_sources: [],
    not_found_sources: [],
    rate_limited_sources: [],
    unavailable_sources: [],
    error_sources: [],
    strongest_evidence: [],
    supporting_evidence: [],
    conflicting_evidence: [],
    context: [],
    mitre_attck: [],
    vulnerabilities: [],
    reason: "",
    analyst_review_recommended: false,
  };
  return {
    batch_id: "b1",
    status: "done",
    progress: 100,
    total: ROWS.length,
    completed: ROWS.length,
    summary: { malicious: 3, breached: 1, suspicious: 6, clean: 1, unknown: 2, error: 0 },
    results: ROWS.map((r) => ({
      ioc: r.ioc,
      ioc_type: r.type ?? "domain",
      source: r.provider ?? "VirusTotal",
      verdict: r.verdict,
      status: "success",
      execution_state: "success",
    })),
    assessments: ROWS.map((r) => ({
      ...base,
      ioc: r.ioc,
      normalized_ioc: r.ioc,
      ioc_type: r.type ?? "domain",
      assessment_domain: r.domain ?? "ioc_reputation",
      final_verdict: r.verdict,
      confidence: r.confidence ?? "low",
      normalized_score: r.score ?? 0,
      coverage: r.coverage ?? 1,
      freshness: r.freshness ?? "fresh",
      needs_review: r.review ?? false,
      assessment_status: r.status ?? "complete",
      malware_families: r.malware ?? [],
      rate_limited_sources: r.rateLimited ?? [],
      unavailable_sources: r.unavailable ?? [],
      error_sources: r.errors ?? [],
      evidence_summary: { expected_providers: r.expected ?? 8, evaluated_providers: r.evaluated ?? 8 },
      provider_plan: [{ provider: r.provider ?? "VirusTotal" }],
    })),
  };
}

function shown(): string[] {
  return screen.queryAllByTestId("card").map((n) => n.textContent ?? "");
}

function counter(): string {
  const m = /Showing (\d+) of (\d+) unique IOCs/.exec(document.body.textContent ?? "");
  return m ? `${m[1]}/${m[2]}` : "?";
}

function setSelect(label: RegExp, value: string) {
  fireEvent.change(screen.getByRole("combobox", { name: label }), { target: { value } });
}

async function renderBatch() {
  sessionStorage.setItem("ioc-platform.active-batch", "b1");
  render(<Batch />);
  await waitFor(() => expect(screen.getAllByTestId("card").length).toBe(ROWS.length));
}

beforeEach(() => {
  sessionStorage.clear();
  mocks.showToast.mockReset();
  mocks.getBatchStatus.mockResolvedValue({
    batch_id: "b1", status: "done", progress: 100, total: ROWS.length, completed: ROWS.length, subtasks: [],
  });
  mocks.getBatchResult.mockResolvedValue(makeResult());
});

describe("every batch filter, against a dummy dataset", () => {
  it("shows the whole dataset with no filter applied", async () => {
    await renderBatch();
    expect(shown()).toHaveLength(ROWS.length);
    expect(counter()).toBe(`${ROWS.length}/${ROWS.length}`);
  });

  it("FILTER: verdict", async () => {
    await renderBatch();
    setSelect(/filter by verdict/i, "malicious");
    // malicious + the CVE severity verdicts that resolve to the malicious bucket
    expect(shown().sort()).toEqual(["cve-critical", "mal-domain", "stale-ip"]);
  });

  it("FILTER: verdict = breached is not malicious", async () => {
    await renderBatch();
    setSelect(/filter by verdict/i, "breached");
    expect(shown()).toEqual(["pwned-mail"]);
  });

  it("FILTER: verdict = benign", async () => {
    await renderBatch();
    setSelect(/filter by verdict/i, "benign");
    expect(shown()).toEqual(["clean-host"]);
  });

  it("FILTER: verdict options only offer buckets present in the data", async () => {
    await renderBatch();
    const options = screen.getByRole("combobox", { name: /filter by verdict/i })
      .querySelectorAll("option");
    const values = [...options].map((o) => (o as HTMLOptionElement).value);
    expect(values[0]).toBe("all");
    // not_breached never occurs in this dataset, so it must not be offered.
    expect(values).not.toContain("not_breached");
    expect(values).toContain("malicious");
    expect(values).toContain("breached");
  });

  it("FILTER: assessment domain", async () => {
    await renderBatch();
    setSelect(/assessment domain/i, "vulnerability");
    expect(shown().sort()).toEqual(["cve-critical", "cve-medium"]);
  });

  it("FILTER: IOC type", async () => {
    await renderBatch();
    setSelect(/filter by ioc type/i, "cve");
    expect(shown().sort()).toEqual(["cve-critical", "cve-medium"]);
    setSelect(/filter by ioc type/i, "email");
    expect(shown()).toEqual(["pwned-mail"]);
  });

  it("FILTER: provider", async () => {
    await renderBatch();
    setSelect(/^filter by provider$/i, "HIBP");
    expect(shown()).toEqual(["pwned-mail"]);
  });

  it("FILTER: confidence", async () => {
    await renderBatch();
    setSelect(/filter by confidence/i, "high");
    expect(shown().sort()).toEqual(["clean-host", "cve-critical", "mal-domain", "stale-ip"]);
    setSelect(/filter by confidence/i, "low");
    expect(shown().length).toBe(ROWS.length - 4 - 2);
  });

  it("FILTER: freshness", async () => {
    await renderBatch();
    setSelect(/filter by freshness/i, "historical");
    expect(shown()).toEqual(["stale-ip"]);
    setSelect(/filter by freshness/i, "cached");
    expect(shown()).toEqual(["pwned-mail"]);
    setSelect(/filter by freshness/i, "fresh");
    expect(shown().length).toBeGreaterThan(1);
  });

  it("FILTER: risk band honours its boundaries", async () => {
    await renderBatch();
    // riskMatches: low is score < 30, medium is >= 30 and < 70, high is >= 70
    setSelect(/risk band/i, "low");
    expect(shown()).toContain("risk-29");
    expect(shown()).not.toContain("risk-30");

    setSelect(/risk band/i, "medium");
    expect(shown()).toContain("risk-30");
    expect(shown()).toContain("risk-69");
    expect(shown()).not.toContain("risk-29");
    expect(shown()).not.toContain("risk-70");

    setSelect(/risk band/i, "high");
    expect(shown()).toContain("risk-70");
    expect(shown()).not.toContain("risk-69");
  });

  it("FILTER: coverage honours its boundary", async () => {
    await renderBatch();
    // coverage: low is < 0.5, high is >= 0.5
    setSelect(/filter by coverage/i, "low");
    expect(shown()).toContain("cov-049");
    expect(shown()).not.toContain("cov-050");
    setSelect(/filter by coverage/i, "high");
    expect(shown()).toContain("cov-050");
    expect(shown()).not.toContain("cov-049");
  });

  it("FILTER: malware family", async () => {
    await renderBatch();
    fireEvent.change(screen.getByLabelText(/malware family/i), { target: { value: "emotet" } });
    expect(shown()).toEqual(["mal-domain"]);
    fireEvent.change(screen.getByLabelText(/malware family/i), { target: { value: "trickbot" } });
    expect(shown()).toEqual(["stale-ip"]);
    // Case-insensitive substring.
    fireEvent.change(screen.getByLabelText(/malware family/i), { target: { value: "EMOT" } });
    expect(shown()).toEqual(["mal-domain"]);
  });

  it("FILTER: review only", async () => {
    await renderBatch();
    fireEvent.click(screen.getByLabelText(/needing review/i));
    expect(shown().sort()).toEqual(["cve-critical", "mal-domain", "stale-ip"]);
  });

  it("FILTER: free text search", async () => {
    await renderBatch();
    fireEvent.change(screen.getByLabelText(/search indicators/i), { target: { value: "cve" } });
    expect(shown().sort()).toEqual(["cve-critical", "cve-medium"]);
    fireEvent.change(screen.getByLabelText(/search indicators/i), { target: { value: "HIBP" } });
    expect(shown()).toEqual(["pwned-mail"]);
  });

  it("FILTER: lookup status = complete", async () => {
    await renderBatch();
    setSelect(/lookup status/i, "complete");
    // susp-ip has a rate-limited source and less than full coverage -> partial
    expect(shown()).not.toContain("susp-ip");
    expect(shown()).toContain("mal-domain");
  });

  it("FILTER: lookup status = partial, which is where a single failed provider lands", async () => {
    await renderBatch();
    setSelect(/lookup status/i, "partial");
    expect(shown().sort()).toEqual(["prov-error", "prov-unavail", "susp-ip"]);
  });

  it("FILTER: lookup status = error is now selectable", async () => {
    // statusFor() could always return "error"; the dropdown had no such option,
    // so an indicator that failed outright was unreachable.
    await renderBatch();
    setSelect(/lookup status/i, "error");
    expect(shown()).toEqual(["lookup-error"]);
  });

  it("FILTER: lookup status = cancelled is now selectable", async () => {
    await renderBatch();
    setSelect(/lookup status/i, "cancelled");
    expect(shown()).toEqual(["lookup-cancelled"]);
  });

  it("FILTER: lookup status = not_applicable", async () => {
    await renderBatch();
    setSelect(/lookup status/i, "not_applicable");
    expect(shown()).toEqual(["lookup-notapplicable"]);
  });

  it("FILTER: provider issue finds a single rate-limited provider that statusFor folds into partial", async () => {
    // The whole point: susp-ip is "partial" as a status, but one of its
    // providers was rate limited, and that is only visible here.
    await renderBatch();
    setSelect(/provider issue/i, "rate_limited");
    expect(shown()).toEqual(["susp-ip"]);
  });

  it("FILTER: provider issue = unavailable", async () => {
    await renderBatch();
    setSelect(/provider issue/i, "unavailable");
    expect(shown()).toEqual(["prov-unavail"]);
  });

  it("FILTER: provider issue = error", async () => {
    await renderBatch();
    setSelect(/provider issue/i, "error");
    expect(shown()).toEqual(["prov-error"]);
  });

  it("FILTER: provider issue = any failure", async () => {
    await renderBatch();
    setSelect(/provider issue/i, "any");
    expect(shown().sort()).toEqual(["prov-error", "prov-unavail", "susp-ip"]);
  });

  it("FILTER: provider issue = none, the complement", async () => {
    await renderBatch();
    setSelect(/provider issue/i, "any");
    const failed = shown().length;
    setSelect(/provider issue/i, "none");
    expect(shown().length).toBe(ROWS.length - failed);
    expect(shown()).not.toContain("susp-ip");
  });

  it("provider issue and lookup status combine rather than conflict", async () => {
    await renderBatch();
    setSelect(/provider issue/i, "rate_limited");
    setSelect(/lookup status/i, "partial");
    expect(shown()).toEqual(["susp-ip"]);
    // Same provider issue, but a status that rules it out.
    setSelect(/lookup status/i, "cancelled");
    expect(shown()).toEqual([]);
  });

  it("FILTERS combine with AND rather than replacing each other", async () => {
    await renderBatch();
    setSelect(/filter by ioc type/i, "ipv4");
    setSelect(/filter by confidence/i, "low");
    setSelect(/risk band/i, "medium");
    expect(shown().sort()).toEqual(["risk-30", "risk-69", "susp-ip"]);
  });

  it("reports an empty result set rather than failing silently", async () => {
    await renderBatch();
    setSelect(/filter by ioc type/i, "ipv6");
    expect(shown()).toEqual([]);
    expect(counter()).toBe(`0/${ROWS.length}`);
    expect(screen.getByText(/No IOCs match the current filters/i)).toBeTruthy();
  });

  it("SORT: severity puts malicious before clean", async () => {
    await renderBatch();
    setSelect(/sort results by/i, "severity");
    const order = shown();
    expect(order.indexOf("mal-domain")).toBeLessThan(order.indexOf("clean-host"));
  });

  it("SORT: risk orders descending", async () => {
    await renderBatch();
    setSelect(/sort results by/i, "risk");
    expect(shown()[0]).toBe("cve-critical");
  });

  it("SORT: IOC orders alphabetically", async () => {
    await renderBatch();
    setSelect(/sort results by/i, "ioc");
    const order = shown();
    expect(order).toEqual([...order].sort());
  });

  it("SORT: coverage orders ascending", async () => {
    await renderBatch();
    setSelect(/sort results by/i, "coverage");
    // Three rows tie at the lowest coverage of 0, and sort is stable, so the
    // first row must be one of them rather than a specific one.
    expect(["lookup-error", "lookup-cancelled", "lookup-notapplicable"]).toContain(shown()[0]);
    expect(shown()).toContain("stale-ip");
  });});