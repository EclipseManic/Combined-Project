import { describe, expect, it } from "vitest";
import { buildCredentialAudit, idleKeys, REASON_LABEL } from "../credentials";
import type { GroupedProviders } from "../providerEvidence";
import type { SourceInventoryItem } from "../../services/api";

function source(overrides: Partial<SourceInventoryItem> = {}): SourceInventoryItem {
  return {
    name: "Example",
    supported_types: ["domain"],
    public_without_key: false,
    configured: true,
    available: true,
    credential_env: "EXAMPLE_API_KEY",
    credential_source: ".env",
    ...overrides,
  } as SourceInventoryItem;
}

function group(partial: Partial<GroupedProviders> = {}): GroupedProviders {
  return { findings: [], context: [], notFound: [], problems: [], ...partial };
}

function row(sourceName: string, groupName: keyof GroupedProviders) {
  return { source: sourceName, group: groupName, state: "success", verdict: "unknown" } as never;
}

describe("buildCredentialAudit", () => {
  it("classifies a source with no key for this IOC type as key_missing", () => {
    const audit = buildCredentialAudit(
      [source({ name: "AbstractAPI IP", supported_types: ["ipv4"], configured: false, credential_env: "ABSTRACTAPI_IP_KEY" })],
      group(),
      "ipv4",
      [],
    );
    expect(audit.missing).toEqual(["AbstractAPI IP"]);
    expect(audit.unused[0].reason).toBe("key_missing");
    expect(audit.unused[0].credentialEnv).toBe("ABSTRACTAPI_IP_KEY");
    expect(idleKeys(audit).map((item) => item.name)).toEqual(["AbstractAPI IP"]);
  });

  it("flags a configured key that was never queried", () => {
    const audit = buildCredentialAudit(
      [source({ name: "AbstractAPI IP", supported_types: ["ipv4"], configured: true })],
      group(),
      "ipv4",
      [],
    );
    expect(audit.keyed).toEqual(["AbstractAPI IP"]);
    expect(audit.missing).toEqual([]);
    expect(audit.unused[0].reason).toBe("not_queried");
  });

  it("separates a failed call from an unused key", () => {
    const audit = buildCredentialAudit(
      [source({ name: "GreyNoise", supported_types: ["ipv4"], configured: true })],
      group({ problems: [row("GreyNoise", "problems")] }),
      "ipv4",
      [],
    );
    expect(audit.failed).toEqual(["GreyNoise"]);
    expect(audit.unused[0].reason).toBe("call_failed");
    // A key that was spent and failed is not an idle key.
    expect(idleKeys(audit)).toEqual([]);
  });

  it("treats a source that does not handle the type as not applicable, not as a missing key", () => {
    const audit = buildCredentialAudit(
      [source({ name: "Hunter.io", supported_types: ["email"], configured: false })],
      group(),
      "ipv4",
      [],
    );
    expect(audit.missing).toEqual([]);
    expect(audit.unused[0].reason).toBe("not_applicable");
    expect(idleKeys(audit)).toEqual([]);
  });

  it("prefers the explicit not-applicable list over capability inference", () => {
    const audit = buildCredentialAudit(
      [source({ name: "A", supported_types: ["domain"] }), source({ name: "B", supported_types: ["domain"] })],
      group(),
      "domain",
      ["A", "B"],
    );
    expect(audit.notApplicable).toEqual(["A", "B"]);
    expect(audit.unused.every((item) => item.reason === "not_applicable")).toBe(true);
  });

  it("does not report a source that answered as unused", () => {
    const audit = buildCredentialAudit(
      [source({ name: "VirusTotal", supported_types: ["domain"], configured: true })],
      group({ findings: [row("VirusTotal", "findings")] }),
      "domain",
      [],
    );
    expect(audit.used).toEqual(["VirusTotal"]);
    expect(audit.unused).toEqual([]);
  });

  it("counts a public source as keyed so it is never reported as a missing key", () => {
    const audit = buildCredentialAudit(
      [source({ name: "cve.org", supported_types: ["cve"], public_without_key: true, configured: false, credential_env: "" })],
      group(),
      "cve",
      [],
    );
    expect(audit.keyed).toEqual(["cve.org"]);
    expect(audit.missing).toEqual([]);
  });

  it("prefers the provider plan name over capability when a source ran", () => {
    const audit = buildCredentialAudit(
      [source({ name: "Ran", supported_types: ["domain"] })],
      group({ context: [row("Ran", "context")] }),
      "domain",
      ["Ran"],
    );
    expect(audit.used).toEqual(["Ran"]);
    expect(audit.notApplicable).toEqual([]);
  });

  it("handles an empty inventory without throwing", () => {
    const audit = buildCredentialAudit([], group(), "domain", []);
    expect(audit.unused).toEqual([]);
    expect(audit.missing).toEqual([]);
  });
});

describe("REASON_LABEL", () => {
  it("has a distinct analyst label for every reason", () => {
    const labels = Object.values(REASON_LABEL);
    expect(new Set(labels).size).toBe(labels.length);
  });
});
