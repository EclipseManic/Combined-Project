import { describe, expect, it } from "vitest";
import { buildPayloadSections, countPayloadFields, humanizeKey, limitPayloadSections } from "../rawPayload";

const PHONE_PAYLOAD = {
  phone_number: "+14152007986",
  phone_format: { international: "+1 415-200-7986", national: "(415) 200-7986" },
  phone_carrier: { name: "T-Mobile USA Inc.", line_type: "mobile", mcc: 310, mnc: 160 },
  phone_location: {
    country_name: "United States",
    country_code: "US",
    region: "California",
    city: "San Francisco",
  },
  phone_validation: { is_valid: true, line_status: "active", is_voip: false },
  phone_risk: { risk_level: "low", is_disposable: false, is_abuse_detected: false },
};

const IP_PAYLOAD = {
  ip_address: "185.197.192.65",
  security: { is_vpn: true, is_proxy: false, is_tor: true, is_hosting: false, is_abuse: false },
  asn: { asn: 136787, name: "PacketHub S.A.", type: "isp" },
  location: { city: "Miami", country_code: "US", latitude: 25.7689, longitude: -80.1946 },
};

function section(sections: ReturnType<typeof buildPayloadSections>, label: string) {
  return sections.find((item) => item.label === label);
}

function rowValue(rows: { label: string; value?: string; children?: unknown[] }[] | undefined, label: string) {
  return rows?.find((item) => item.label === label)?.value;
}

describe("humanizeKey", () => {
  it("turns snake_case into analyst wording", () => {
    expect(humanizeKey("line_type")).toBe("Line Type");
    expect(humanizeKey("country_code")).toBe("Country Code");
    expect(humanizeKey("is_valid")).toBe("Is Valid");
  });

  it("keeps initialisms correctly cased", () => {
    expect(humanizeKey("is_vpn")).toBe("Is VPN");
    expect(humanizeKey("is_tor")).toBe("Is TOR");
    expect(humanizeKey("mcc")).toBe("MCC");
    expect(humanizeKey("sms_domain")).toBe("SMS Domain");
    expect(humanizeKey("ip_address")).toBe("IP Address");
    expect(humanizeKey("is_voip")).toBe("Is VoIP");
  });
});

describe("buildPayloadSections", () => {
  it("splits a nested payload into one labelled section per top-level key", () => {
    const sections = buildPayloadSections(PHONE_PAYLOAD);
    const labels = sections.map((item) => item.label);
    expect(labels).toContain("Phone Carrier");
    expect(labels).toContain("Phone Location");
    expect(labels).toContain("Phone Validation");
  });

  it("surfaces values that were previously only visible as JSON", () => {
    const sections = buildPayloadSections(PHONE_PAYLOAD);
    const carrier = section(sections, "Phone Carrier");
    expect(rowValue(carrier?.rows, "Name")).toBe("T-Mobile USA Inc.");
    expect(rowValue(carrier?.rows, "Line Type")).toBe("mobile");
    const location = section(sections, "Phone Location");
    expect(rowValue(location?.rows, "Country Name")).toBe("United States");
    expect(rowValue(location?.rows, "City")).toBe("San Francisco");
  });

  it("renders booleans as Yes/No and flags the true ones", () => {
    const sections = buildPayloadSections(IP_PAYLOAD);
    const security = section(sections, "Security");
    const vpn = security?.rows.find((row) => row.label === "Is VPN");
    expect(vpn?.value).toBe("Yes");
    expect(vpn?.flag).toBe(true);
    const proxy = security?.rows.find((row) => row.label === "Is Proxy");
    expect(proxy?.value).toBe("No");
    expect(proxy?.flag).toBe(false);
  });

  it("collects top-level scalars into a Response section", () => {
    const sections = buildPayloadSections({ total: 3, ok: true, note: "done" });
    expect(sections[0].label).toBe("Response");
    expect(rowValue(sections[0].rows, "Note")).toBe("done");
  });

  it("renders an array of scalars as a list rather than joined text", () => {
    const sections = buildPayloadSections({ tags_list: ["a", "b", "c"] });
    const row = sections[0].rows.find((item) => item.label === "Tags List");
    expect(row?.items).toEqual(["a", "b", "c"]);
  });

  it("names items in an array of objects and nests their fields", () => {
    const sections = buildPayloadSections({
      breaches: [
        { domain: "facebook.com", breach_date: "2019-07-23" },
        { domain: "example.org", breach_date: "2021-01-02" },
      ],
    });
    // The section is the key; its rows are the items, each labelled by its
    // descriptive field with the remaining fields nested beneath.
    expect(sections[0].label).toBe("Breaches");
    expect(sections[0].rows).toHaveLength(2);
    expect(sections[0].rows[0].label).toBe("facebook.com");
    expect(rowValue(sections[0].rows[0].children, "Breach Date")).toBe("2019-07-23");
  });

  it("does not apply locale digit grouping to identifier-like numbers", () => {
    // 136787 was rendered as "1,36,787" under some locales, which corrupts an
    // ASN. Geoname IDs and postal codes are identifiers too.
    const sections = buildPayloadSections({
      asn: { asn: 136787, name: "PacketHub S.A." },
      location: { postal_code: 25134, latitude: 25.7617, city_geoname_id: 4164138 },
    });
    const asn = section(sections, "ASN");
    expect(rowValue(asn?.rows, "ASN")).toBe("136787");
    const location = section(sections, "Location");
    expect(rowValue(location?.rows, "Postal Code")).toBe("25134");
    expect(rowValue(location?.rows, "City Geoname ID")).toBe("4164138");
    expect(rowValue(location?.rows, "Latitude")).toBe("25.7617");
    for (const value of Object.values(asn?.rows ?? []).concat(Object.values(location?.rows ?? {}))) {
      expect(String(value.value)).not.toMatch(/^\d{1,2},\d{3}$/);
    }
  });

  it("keeps working for a payload with no nesting at all", () => {
    const sections = buildPayloadSections({ verdict: "malicious", score: 91.5 });
    expect(sections.length).toBe(1);
    expect(rowValue(sections[0].rows, "Verdict")).toBe("malicious");
  });

  it("drops null, undefined and empty values instead of showing blanks", () => {
    const sections = buildPayloadSections({ a: null, b: undefined, c: "", d: 0, e: false, keep: "yes" });
    const labels = sections.flatMap((item) => item.rows.map((row) => row.label));
    expect(labels).not.toContain("A");
    expect(labels).not.toContain("B");
    expect(labels).not.toContain("C");
    // 0 and false are real data and must survive.
    expect(labels).toContain("D");
    expect(labels).toContain("E");
    expect(labels).toContain("Keep");
  });

  it("returns nothing for empty or non-object payloads", () => {
    expect(buildPayloadSections({})).toEqual([]);
    expect(buildPayloadSections(null)).toEqual([]);
    expect(buildPayloadSections("text")).toEqual([]);
    expect(buildPayloadSections([1, 2])).toEqual([]);
    expect(buildPayloadSections({ all: null })).toEqual([]);
  });
});

describe("countPayloadFields", () => {
  it("counts nested leaves", () => {
    const sections = buildPayloadSections(PHONE_PAYLOAD);
    // 1 top-level scalar + 2 + 4 + 4 + 3 + 3 nested scalars.
    expect(countPayloadFields(sections)).toBeGreaterThan(10);
  });
});

describe("limitPayloadSections", () => {
  it("reports how many rows were hidden", () => {
    const wide: Record<string, number> = {};
    for (let index = 0; index < 40; index += 1) wide[`field_${index}`] = index;
    const { sections, hidden } = limitPayloadSections(buildPayloadSections(wide));
    expect(hidden).toBeGreaterThan(0);
    expect(sections[0].rows.length).toBeLessThanOrEqual(14);
  });

  it("leaves small payloads untouched", () => {
    const input = buildPayloadSections({ a: 1, b: 2 });
    const { sections, hidden } = limitPayloadSections(input);
    expect(hidden).toBe(0);
    expect(sections).toEqual(input);
  });
});
