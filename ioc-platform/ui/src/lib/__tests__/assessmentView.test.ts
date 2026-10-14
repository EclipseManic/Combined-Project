import { describe, expect, it } from "vitest";
import btcFixture from "../../__fixtures__/btc-address.json";
import cveFixture from "../../__fixtures__/cve-2021-44228.json";
import emailFixture from "../../__fixtures__/email-test.json";
import ipFixture from "../../__fixtures__/ip-8.8.8.8.json";
import type { LookupResponse } from "../../services/api";
import { buildHeadline } from "../assessmentView";
import { buildProviderRows, groupProviderRows } from "../providerEvidence";

function headline(fixture: unknown) {
  const result = fixture as LookupResponse;
  return buildHeadline(result, groupProviderRows(buildProviderRows(result.results, result.final_assessment?.provider_breakdown)));
}

function metric(value: ReturnType<typeof headline>, label: string) {
  return value.metrics.find((item) => item.label === label);
}

describe("buildHeadline", () => {
  it("reads a CVE from final_assessment instead of the unknown/0 composite", () => {
    const view = headline(cveFixture);
    expect((cveFixture as unknown as LookupResponse).composite.verdict).toBe("unknown");
    expect(view.verdict).toBe("critical");
    expect(view.verdictLabel).toBe("Critical");
    expect(view.score).toBe(100);
    expect(view.scoreText).toBe("CVSS 10.0 · risk 100/100");
    expect(view.domainLabel).toBe("Vulnerability");
    expect(view.reason).toMatch(/critical severity/);
    expect(metric(view, "CVSS base score")?.value).toBe("10.0");
    expect(metric(view, "CVSS base score")?.detail).toBe("Critical");
    expect(metric(view, "EPSS")?.value).toBe("100.0%");
    expect(metric(view, "Known exploitation")?.value).toBe("CISA KEV");
  });

  it("reads a breached email as a credential exposure with its score", () => {
    const view = headline(emailFixture);
    expect(view.verdictLabel).toBe("Breached");
    expect(view.domainLabel).toBe("Credential exposure");
    expect(view.scoreText).toBe("77/100");
    expect(view.scoreCaption).toBe("Exposure score");
    expect(metric(view, "Public breaches")?.value).toBe("50");
    expect(metric(view, "Infostealer infections")?.value).toBe("5");
  });

  it("does not present an unknown verdict as a zero score", () => {
    const view = headline(btcFixture);
    expect(view.verdictLabel).toBe("Unknown");
    expect(view.score).toBeNull();
    expect(view.scoreText).toBe("Not scored");
  });

  it("matches the reputation verdict, score and confidence for an IP", () => {
    const view = headline(ipFixture);
    expect(view.verdictLabel).toBe("Benign");
    expect(view.scoreText).toBe("0/100");
    expect(view.confidence).toBe("medium");
    expect(metric(view, "Provider coverage")?.value).toBe("9/11");
    expect(metric(view, "Provider coverage")?.detail).toBe("2 provider problems");
  });

  it("survives a response without final_assessment", () => {
    const view = buildHeadline(
      { composite: { score: 55, verdict: "malicious", confidence: "high" }, results: [] } as unknown as LookupResponse,
      { findings: [], context: [], notFound: [], problems: [] },
    );
    expect(view.verdictLabel).toBe("Malicious");
    expect(view.scoreText).toBe("55/100");
    expect(view.metrics.every((item) => !/NaN|undefined|\[object Object\]/.test(`${item.value} ${item.detail ?? ""}`))).toBe(true);
  });

  it("reads vulnerability facts from evidence_summary when enrichment is absent", () => {
    const base = cveFixture as unknown as LookupResponse;
    const result = {
      ...base,
      enrichment: { ...base.enrichment, cve: undefined },
      final_assessment: {
        ...base.final_assessment!,
        evidence_summary: { severity: "high", cvss_score: 8.1, epss_score: 0.42, known_exploited: true, expected_providers: 3, evaluated_providers: 3 },
      },
    } as LookupResponse;
    const view = buildHeadline(result, groupProviderRows(buildProviderRows(result.results, result.final_assessment?.provider_breakdown)));
    expect(metric(view, "CVSS base score")?.value).toBe("8.1");
    expect(metric(view, "EPSS")?.value).toBe("42.0%");
    expect(metric(view, "Known exploitation")?.value).toBe("Exploited");
  });
});
