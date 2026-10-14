import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import PhoneIntelligenceCard from "../PhoneIntelligenceCard";

const IPQS = {
  source: "IPQualityScore Phone",
  verdict: "suspicious",
  confidence: "medium",
  provider_summary: "fraud score 65/100; VoIP line; carrier Aql Wholesale; landline; provider verdict suspicious",
  raw_data: {
    success: true, valid: true, fraud_score: 65, risky: true, VOIP: true,
    prepaid: false, leaked: false, spammer: false, recent_abuse: false,
    do_not_call: false, tcpa_blacklist: false,
    carrier: "Aql Wholesale", line_type: "Landline",
    name: "DOREEN H SEETO", country: "GB", region: "London", city: "North Berwick",
    sms_email: "N/A", sms_domain: "N/A", active_status: "N/A",
    associated_email_addresses: { emails: [], status: "Enterprise Plus or higher required." },
  },
};

const ABSTRACT = {
  source: "AbstractAPI Phone",
  verdict: "unknown",
  confidence: "low",
  raw_data: {
    phone_carrier: { name: "Aql Wholesale", line_type: "mobile" },
    phone_location: { country_code: "GB", region: "London", city: "North Berwick" },
    phone_validation: { is_valid: true, line_status: "active" },
    phone_risk: { risk_level: "medium", is_disposable: false, is_abuse_detected: false },
    phone_messaging: { sms_email: "447700900000@telia.co.uk", sms_domain: "telia.co.uk" },
  },
};

describe("PhoneIntelligenceCard", () => {
  it("leads with the fraud score, validity, line type and risk level", () => {
    render(<PhoneIntelligenceCard results={[IPQS, ABSTRACT]} />);
    expect(screen.getByText("65/100")).toBeTruthy();
    expect(screen.getByText("Valid")).toBeTruthy();
    expect(screen.getByText("Landline")).toBeTruthy();
    expect(screen.getByText("medium")).toBeTruthy();
  });

  it("presents the risk flags together", () => {
    render(<PhoneIntelligenceCard results={[IPQS]} />);
    expect(screen.getByText("VoIP")).toBeTruthy();
    expect(screen.getByText("Flagged risky")).toBeTruthy();
    expect(screen.getByText("Spammer")).toBeTruthy();
    expect(screen.getByText("Recent abuse")).toBeTruthy();
    expect(screen.getByText("Leaked")).toBeTruthy();
    expect(screen.getByText("Do not call")).toBeTruthy();
  });

  it("shows the registered holder and the location", () => {
    render(<PhoneIntelligenceCard results={[IPQS]} />);
    expect(screen.getByText("Registered holder")).toBeTruthy();
    expect(screen.getByText("DOREEN H SEETO")).toBeTruthy();
    expect(screen.getByText("North Berwick, London, GB")).toBeTruthy();
  });

  it("falls back to the other provider when IPQS is absent", () => {
    render(<PhoneIntelligenceCard results={[ABSTRACT]} />);
    // Carrier and line type come from AbstractAPI in this case.
    expect(screen.getByText(/Carrier Aql Wholesale · mobile · GB/)).toBeTruthy();
    // Fraud score is IPQS-only, and Risk level AbstractAPI-only.
    expect(screen.getByText("Fraud score")).toBeTruthy();
    expect(screen.getByText("Risk level")).toBeTruthy();
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
  });

  it("names plan limits instead of showing them as missing data", () => {
    render(<PhoneIntelligenceCard results={[IPQS]} />);
    // A paywalled field must not read as "no risk found".
    expect(screen.getByText(/Not available on this plan: associated email addresses/)).toBeTruthy();
  });

  it("shows every provider's verdict so disagreement is visible", () => {
    render(<PhoneIntelligenceCard results={[IPQS, ABSTRACT]} />);
    expect(screen.getByText("IPQualityScore Phone")).toBeTruthy();
    expect(screen.getByText("AbstractAPI Phone")).toBeTruthy();
    expect(screen.getByText("suspicious")).toBeTruthy();
    expect(screen.getByText("unknown")).toBeTruthy();
  });

  it("surfaces the messaging address as a pivot when present", () => {
    render(<PhoneIntelligenceCard results={[ABSTRACT]} />);
    expect(screen.getByText("447700900000@telia.co.uk")).toBeTruthy();
    expect(screen.getByText(/can be investigated on its own/)).toBeTruthy();
  });

  it("degrades cleanly with no usable data", () => {
    render(<PhoneIntelligenceCard results={[{ source: "X", verdict: "unknown", raw_data: {} }]} />);
    expect(screen.getByText("No carrier data returned")).toBeTruthy();
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
  });

  it("renders without data at all", () => {
    const { container } = render(<PhoneIntelligenceCard results={[]} />);
    expect(container.textContent).not.toMatch(/\[object Object\]|undefined|NaN/);
  });
});
