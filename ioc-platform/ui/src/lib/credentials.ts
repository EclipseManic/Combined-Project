// Which providers ran, which were skipped, and which credentials went unused.
//
// The result view answers "what did the sources say". This answers the audit
// question behind it: "what did we NOT ask, and why?" A provider that silently
// never ran looks identical to a provider that ran and found nothing, which is
// how a missing API key goes unnoticed for months. Everything here is derived
// from three inputs the result already carries: the source inventory (every
// registered adapter and whether it is configured), the provider rows (who
// actually answered) and the provider plan (who was ruled out by capability).

import type { SourceInventoryItem } from "../services/api";
import type { GroupedProviders } from "./providerEvidence";

export type UnusedReason =
  /** Registered for this IOC type and needs a key, but no key is configured. */
  | "key_missing"
  /** Registered for this IOC type and keyed, but no response was produced. */
  | "not_queried"
  /** Keyed and applicable, but the call failed or was throttled. */
  | "call_failed"
  /** Does not handle this IOC type at all, so no key would have been spent. */
  | "not_applicable";

export interface UnusedSource {
  name: string;
  reason: UnusedReason;
  /** The env var that would enable this source, when it is known. */
  credentialEnv?: string;
  supportedTypes: string[];
  /** Analyst-readable explanation. */
  detail: string;
}

export interface CredentialAudit {
  /** Sources that answered, ordered findings first. */
  used: string[];
  /** Registered sources that did not contribute to this result, split by why. */
  unused: UnusedSource[];
  /** Sources that ran but ended in a problem state. */
  failed: string[];
  /** Sources ruled out by capability for this IOC type. */
  notApplicable: string[];
  /** Sources applicable to this IOC type that hold a valid key. */
  keyed: string[];
  /** Sources applicable to this IOC type that need a key and lack one. */
  missing: string[];
}

const REASON_DETAIL: Record<UnusedReason, string> = {
  key_missing: "Supports this indicator type but has no API key, so it was never called. This result is less complete than it could be.",
  not_queried: "A key is configured and the source supports this indicator type, but it produced no response for this lookup.",
  call_failed: "A key is configured and the source was called, but the lookup did not complete.",
  not_applicable: "Does not support this indicator type, so no request was made and no credit was spent.",
};

export function buildCredentialAudit(
  inventory: SourceInventoryItem[],
  grouped: GroupedProviders,
  iocType: string,
  notApplicableNames: string[],
): CredentialAudit {
  const used = [
    ...grouped.findings.map((row) => row.source),
    ...grouped.context.map((row) => row.source),
    ...grouped.notFound.map((row) => row.source),
  ];
  const usedSet = new Set(used);
  const failed = grouped.problems.map((row) => row.source);
  const failedSet = new Set(failed);
  const notApplicable = notApplicableNames.filter((name) => !usedSet.has(name));
  const notApplicableSet = new Set(notApplicable);

  const unused: UnusedSource[] = [];
  const keyed: string[] = [];
  const missing: string[] = [];

  for (const source of inventory) {
    const supportsType = source.supported_types.includes(iocType);
    if (supportsType) {
      if (source.public_without_key || source.configured) keyed.push(source.name);
      else missing.push(source.name);
    }

    if (usedSet.has(source.name)) continue;

    const reason: UnusedReason | null = notApplicableSet.has(source.name)
      ? "not_applicable"
      : failedSet.has(source.name)
        ? "call_failed"
        : !supportsType
          ? "not_applicable"
          : !source.public_without_key && !source.configured
            ? "key_missing"
            : "not_queried";

    unused.push({
      name: source.name,
      reason,
      credentialEnv: source.credential_env,
      supportedTypes: source.supported_types,
      detail: REASON_DETAIL[reason],
    });
  }

  return { used, unused, failed, notApplicable, keyed, missing };
}

/** Sources whose key is present but was not spent on this lookup. */
export function idleKeys(audit: CredentialAudit): UnusedSource[] {
  return audit.unused.filter((item) => item.reason === "not_queried" || item.reason === "key_missing");
}

export const REASON_LABEL: Record<UnusedReason, string> = {
  key_missing: "Key missing",
  not_queried: "Key present, not queried",
  call_failed: "Call failed",
  not_applicable: "Not applicable",
};
