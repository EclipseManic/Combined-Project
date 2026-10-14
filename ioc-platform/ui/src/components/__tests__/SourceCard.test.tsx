import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import SourceCard from "../SourceCard";
import type { NormalizedResult } from "../../services/api";

// Investigation is a triage surface. A provider card carries the finding —
// source, verdict, confidence, tags, latency — and nothing more. Dumping every
// returned field here turned each card into a wall of text and buried the very
// verdict it was meant to support. The structured fields live on the Sources
// tab; the raw JSON stays one click away.

const PHONE_PAYLOAD = {
  phone_number: "+14152007986",
  phone_carrier: { name: "T-Mobile USA Inc.", line_type: "mobile" },
  phone_location: { country_name: "United States", region: "California", city: "San Francisco" },
  phone_validation: { is_valid: true, line_status: "active" },
  phone_risk: { risk_level: "low", is_disposable: false, is_abuse_detected: false },
};

const IP_PAYLOAD = {
  ip_address: "185.197.192.65",
  security: { is_vpn: true, is_proxy: false, is_tor: false },
  asn: { asn: 136787, name: "PacketHub S.A." },
};

function makeResult(overrides: Partial<NormalizedResult> = {}): NormalizedResult {
  return {
    ioc: "+14152007986",
    ioc_type: "phone",
    source: "AbstractAPI Phone",
    verdict: "unknown",
    status: "found",
    execution_state: "success",
    raw_score: 0,
    confidence: "low",
    tags: [],
    categories: [],
    ...overrides,
  } as NormalizedResult;
}

describe("SourceCard stays compact", () => {
  it("does not dump provider fields onto the card", () => {
    render(<SourceCard result={makeResult({ raw_data: PHONE_PAYLOAD })} />);

    // The card must not carry the payload detail.
    expect(screen.queryByText("T-Mobile USA Inc.")).toBeNull();
    expect(screen.queryByText("San Francisco")).toBeNull();
    expect(screen.queryByText("Line Type")).toBeNull();
    expect(screen.queryByText("Is VPN")).toBeNull();
  });

  it("points at the Sources tab instead, with a field count", () => {
    render(<SourceCard result={makeResult({ raw_data: PHONE_PAYLOAD })} />);
    expect(screen.getByText(/fields returned · full payload on the Sources tab/)).toBeTruthy();
  });

  it("keeps the finding itself visible", () => {
    render(
      <SourceCard
        result={makeResult({
          raw_data: PHONE_PAYLOAD,
          provider_summary: "Line type mobile, low risk, no breaches",
          confidence: "medium",
          latency_ms: 420,
        })}
      />,
    );
    expect(screen.getByText("AbstractAPI Phone")).toBeTruthy();
    expect(screen.getByText(/Line type mobile, low risk/)).toBeTruthy();
    expect(screen.getByText(/medium confidence/)).toBeTruthy();
  });

  it("shows tags so the salient facts still surface without the payload", () => {
    render(<SourceCard result={makeResult({ raw_data: PHONE_PAYLOAD, tags: ["disposable_email", "breached"] })} />);
    expect(screen.getByText("disposable email")).toBeTruthy();
    expect(screen.getByText("breached")).toBeTruthy();
  });

  it("omits the field count when there is no payload", () => {
    render(<SourceCard result={makeResult({ raw_data: {} })} />);
    expect(screen.queryByText(/full payload on the Sources tab/)).toBeNull();
  });

  it("still offers the raw JSON one click away", () => {
    render(<SourceCard result={makeResult({ raw_data: IP_PAYLOAD, ioc_type: "ipv4" })} />);
    expect(screen.queryByText(/"PacketHub S.A."/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /raw json/i }));
    expect(screen.getByText(/"PacketHub S.A."/)).toBeTruthy();
  });

  it("carries the verdict so the card stands on its own", () => {
    render(<SourceCard result={makeResult({ raw_data: IP_PAYLOAD, ioc_type: "ipv4", verdict: "suspicious" })} />);
    expect(screen.getByText("AbstractAPI Phone")).toBeTruthy();
    // Verdict badge plus the summary line both name it.
    expect(screen.getAllByText(/suspicious/i).length).toBeGreaterThan(0);
  });
});
