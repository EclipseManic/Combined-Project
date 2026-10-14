import { describe, expect, it } from "vitest";
import ipFixture from "../../__fixtures__/ip-8.8.8.8.json";
import emailFixture from "../../__fixtures__/email-test.json";
import type { EvidenceObservation, LookupResponse, NormalizedResult } from "../../services/api";
import { buildProviderRows, EVIDENCE_CLASS_LABELS, groupProviderRows, isThreatFinding, problemReason, tidyTags } from "../providerEvidence";

const ip = ipFixture as unknown as LookupResponse;
const email = emailFixture as unknown as LookupResponse;

function group(result: LookupResponse) {
  return groupProviderRows(buildProviderRows(result.results, result.final_assessment?.provider_breakdown));
}

function row(partial: Partial<NormalizedResult>): NormalizedResult {
  return {
    ioc: "x", ioc_type: "ipv4", source: "Test", verdict: "unknown", status: "error",
    execution_state: "error", raw_score: null, confidence: "low", tags: [], categories: [],
    ...partial,
  };
}

describe("provider grouping", () => {
  it("orders findings before context, not-found and problems and never shows not_applicable rows", () => {
    const grouped = group(ip);
    const sources = (rows: { source: string }[]) => rows.map((item) => item.source);

    expect(sources(grouped.findings)).toEqual(["Hudson Rock", "AbuseIPDB", "VirusTotal"]);
    expect(sources(grouped.context)).toEqual(["Censys", "IPinfo", "Shodan", "Team Cymru"]);
    expect(sources(grouped.notFound)).toEqual(["ThreatFox", "Tor Exit"]);
    expect(sources(grouped.problems)).toEqual(["AlienVault OTX", "GreyNoise"]);

    const all = [...grouped.findings, ...grouped.context, ...grouped.notFound, ...grouped.problems].map((item) => item.source);
    expect(all).not.toContain("AbstractAPI");
    expect(all).not.toContain("Blockchain.info");
  });

  it("gives every provider problem a concrete reason", () => {
    const grouped = group(ip);
    const reasons = Object.fromEntries(grouped.problems.map((item) => [item.source, item.reason]));
    expect(reasons.GreyNoise).toMatch(/^Rate limited/);
    expect(reasons["AlienVault OTX"]).toMatch(/^Timed out/);

    const emailProblems = group(email).problems;
    expect(emailProblems.map((item) => item.source)).toEqual(["AbstractAPI"]);
    expect(emailProblems[0].reason).toBe("Unavailable: API key not authorized; API key rejected as invalid");
  });

  it("explains missing keys, policy blocks and HTTP failures", () => {
    expect(problemReason(row({ execution_state: "unavailable", tags: ["no_api_key_configured"] }))).toBe("Unavailable: no API key configured");
    expect(problemReason(row({ execution_state: "unavailable", tags: ["disabled_by_policy"] }))).toBe("Unavailable: disabled by ENABLED_SOURCES policy");
    expect(problemReason(row({ execution_state: "error", tags: ["http_503"], provider_summary: "Provider returned an error" }))).toBe("Error: HTTP 503");
    expect(problemReason(row({ execution_state: "rate_limited", tags: ["rate_limited"], retry_after_seconds: 60 }))).toBe("Rate limited: retry after 60 s");
    expect(problemReason(row({ execution_state: "invalid_request", tags: ["invalid_request"], provider_summary: "Hudson Rock limits infostealer search on broad public domains" })))
      .toBe("Request rejected: Hudson Rock limits infostealer search on broad public domains");
  });

  it("places the scorer's newer evidence classes in the right group", () => {
    const obs = (source: string, evidence_class: string, contribution: string) =>
      ({ source, execution_state: "success", status: "success", evidence_class, contribution, verdict: "malicious" }) as unknown as EvidenceObservation;
    const results = ["Hudson Rock", "HIBP", "ThreatFox", "Tor Exit"].map((source) => row({ source, execution_state: "success", status: "found", verdict: "malicious" }));
    const grouped = groupProviderRows(buildProviderRows(results, [
      obs("Hudson Rock", "exposure_context", "neutral"),
      obs("HIBP", "credential_exposure", "positive"),
      obs("ThreatFox", "related_indicator", "neutral"),
      obs("Tor Exit", "anonymization", "context_risk"),
    ]));
    expect(grouped.findings.map((item) => item.source)).toEqual(["HIBP", "Tor Exit"]);
    expect(grouped.context.map((item) => item.source)).toEqual(["Hudson Rock", "ThreatFox"]);
  });
});

describe("tidyTags", () => {
  it("moves key: value transport tags into attributes and drops state tags", () => {
    const { chips, attributes } = tidyTags([
      "suspicious-udp", "votes_malicious: 59", "votes_harmless: 294", "cached", "rate_limited",
      "domain: example.com", "domain: www.example.com", "tor_exit_node", "infostealer_compromised", "infostealer_compromised",
    ]);
    expect(chips).toEqual(["suspicious-udp", "tor exit node", "infostealer compromised"]);
    expect(attributes).toEqual([
      ["Votes Malicious", "59"],
      ["Votes Harmless", "294"],
      ["Domain", "example.com, www.example.com"],
    ]);
  });

  it("tolerates non-string and missing tags", () => {
    expect(tidyTags(undefined)).toEqual({ chips: [], attributes: [] });
    expect(tidyTags([null, { a: 1 }, 42, ""]).chips).toEqual(["42"]);
  });
});

describe("threat vs exposure evidence", () => {
  const obs = (source: string, evidence_class: string) =>
    ({ source, execution_state: "success", status: "success", evidence_class, contribution: "positive", verdict: "malicious" }) as unknown as EvidenceObservation;

  it("does not count related, credential-exposure or anonymization evidence as direct threat", () => {
    const classes = ["direct", "supporting", "related_indicator", "credential_exposure", "anonymization"];
    const results = classes.map((c) => row({ source: c, execution_state: "success", status: "found", verdict: "malicious" }));
    const grouped = groupProviderRows(buildProviderRows(results, classes.map((c) => obs(c, c))));
    const threats = grouped.findings.filter(isThreatFinding).map((item) => item.source).sort();
    expect(threats).toEqual(["direct", "supporting"]);
  });

  it("has a label for every new evidence class", () => {
    for (const key of ["anonymization", "exposure_context", "related_indicator", "credential_exposure"]) {
      expect(EVIDENCE_CLASS_LABELS[key]).toBeTruthy();
    }
  });
});
