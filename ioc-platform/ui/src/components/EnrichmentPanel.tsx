import { useState, type ReactNode } from "react";
import type { EnrichmentData } from "../services/api";
import HostVulnerabilityMatrix from "./HostVulnerabilityMatrix";
import InfostealerExposureCard from "./InfostealerExposureCard";
import WebPreviewCard from "./WebPreviewCard";
import AbuseReportsPanel from "./AbuseReportsPanel";
import DataProvenanceBadge from "./DataProvenanceBadge";
import PayloadFields from "./PayloadFields";
import ContextIntelCard from "./ContextIntelCard";
import SubdomainsCard from "./SubdomainsCard";
import {
  describeEmptyState,
  isEnrichmentEmpty,
  keysRenderedByCards,
  MODULE_STATE_LABEL,
  parseCollectionStatus,
  type CollectionStatus,
  type ModuleState,
} from "../lib/enrichment";

/**
 * A section renders its data as readable fields at every depth.
 *
 * It previously used JSON.stringify for anything nested, which turned a deep
 * module such as host_intel or whois into a wall of braces. The raw JSON is still
 * one click away for audit, but it is no longer the only view.
 */
function Section({
  title,
  data,
  badge,
}: {
  title: string;
  data: object;
  badge?: ReactNode;
}) {
  const [showJson, setShowJson] = useState(false);
  const entries = Object.entries(data).filter(
    ([_, value]) =>
      value !== null &&
      value !== undefined &&
      value !== "" &&
      !(Array.isArray(value) && value.length === 0)
  );
  if (entries.length === 0 && !badge) return null;
  return (
    <section className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-2">
        <h4 className="text-xs font-semibold uppercase tracking-[0.14em] text-accent">{title}</h4>
        {badge}
      </div>
      <div className="rounded-lg border border-border/70 bg-bg-elevated/30 p-3">
        <PayloadFields raw={data} />
      </div>
      <button
        type="button"
        onClick={() => setShowJson((value) => !value)}
        className="rounded-md border border-border bg-bg-elevated px-2.5 py-1.5 text-xs font-semibold text-text-secondary hover:border-accent/50 hover:text-accent transition-colors"
      >
        {showJson ? "Hide raw JSON" : "Raw JSON"}
      </button>
      {showJson && (
        <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-border bg-[#080b12] p-3 font-mono text-xs leading-relaxed text-slate-300">
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </section>
  );
}

const MODULE_TONE: Record<ModuleState, string> = {
  ok: "border-verdict-clean/30 bg-verdict-clean/10 text-verdict-clean",
  not_found: "border-border bg-bg-elevated text-text-secondary",
  unavailable: "border-amber-500/30 bg-amber-500/10 text-amber-200",
  skipped: "border-border bg-bg-elevated/50 text-text-secondary",
  error: "border-verdict-malicious/30 bg-verdict-malicious/10 text-verdict-malicious",
};

/** Per-module collection state, so a sparse tab explains itself. */
function CollectionStatusPanel({ status }: { status: CollectionStatus }) {
  if (status.modules.length === 0) return null;
  return (
    <section className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
      <div>
        <h4 className="text-xs font-semibold uppercase tracking-[0.14em] text-accent">Collection status</h4>
        <p className="mt-1 text-xs text-text-secondary">{status.summary}</p>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {status.modules.map((module) => (
          <span
            key={module.module}
            title={module.title}
            className={`rounded border px-1.5 py-0.5 text-xs font-semibold ${MODULE_TONE[module.state]}`}
          >
            {module.title}: {MODULE_STATE_LABEL[module.state]}
          </span>
        ))}
      </div>
    </section>
  );
}

function Stat({
  label,
  value,
  accent = "text-text-primary",
}: {
  label: string;
  value: string | number;
  accent?: string;
}) {
  return (
    <div className="rounded-lg border border-border/70 bg-bg-elevated/50 p-3">
      <div className="text-xs uppercase tracking-wider text-text-secondary">{label}</div>
      <div className={`mt-1 truncate text-sm font-semibold ${accent}`}>{value}</div>
    </div>
  );
}

export default function EnrichmentPanel({
  enrichment,
  iocType,
}: {
  enrichment: EnrichmentData;
  iocType?: string;
}) {
  const sections: [string, object][] = [];
  const extra = enrichment.extra ?? {};

  if (enrichment.dns) sections.push(["DNS records", enrichment.dns]);
  if (enrichment.ssl) sections.push(["SSL certificate", enrichment.ssl]);
  if (enrichment.reverse_dns) sections.push(["Reverse DNS", enrichment.reverse_dns]);
  if (enrichment.subdomains) sections.push(["Subdomains", enrichment.subdomains]);
  if (enrichment.breach) sections.push(["Breach exposure & credentials", enrichment.breach]);
  if (enrichment.email_security) sections.push(["Email security & delivery", enrichment.email_security]);
  if (enrichment.cve) sections.push(["CVE context", enrichment.cve]);
  if (enrichment.passive_dns) sections.push(["Passive DNS", enrichment.passive_dns]);
  if (enrichment.favicon) sections.push(["Favicon", enrichment.favicon]);
  if (enrichment.url_preview && Object.keys(enrichment.url_preview).length)
    sections.push(["URL preview", enrichment.url_preview]);
  if (enrichment.redirect_chain?.length)
    sections.push(["Redirect chain", { chain: enrichment.redirect_chain }]);
  // The wallet dashboards for BTC and ETH live on the Investigation tab, so
  // neither is repeated here as a card. `bitcoin` and `ethereum` therefore stay
  // in `consumed` only so they are not double-registered as sections; they are
  // rendered once below under "Indicator context" at full field depth.
  const consumed = new Set<string>();
  const additional = Object.fromEntries(
    Object.entries(extra).filter(([key]) => !consumed.has(key))
  );
  if (Object.keys(additional).length) sections.push(["Indicator context", additional]);

  const geo = enrichment.geoip;
  const breach = enrichment.breach as Record<string, unknown> | undefined;
  const breachCount = typeof breach?.breach_count === "number" ? breach.breach_count : 0;
  const breachSource = typeof breach?.source === "string" ? breach.source : "None";
  const exposedTypeCount = Array.isArray(breach?.exposed_data_types) ? breach.exposed_data_types.length : 0;
  const emailSec = enrichment.email_security as Record<string, unknown> | undefined;
  const spfValue = typeof emailSec?.spf === "string" ? emailSec.spf : "";
  const spfConfigured = Boolean(spfValue && spfValue !== "missing");
  const contextLabel = iocType ? `${iocType.toUpperCase()} context` : "Contextual enrichment";

  const hasHostIntel = !!enrichment.host_intel || (enrichment.open_ports && enrichment.open_ports.length > 0);
  const hostingIps = Object.entries(enrichment.hosting_ip_intel ?? {});
  const hasIdentityData = Boolean(
    (breach && Object.keys(breach).length > 0) || (emailSec && Object.keys(emailSec).length > 0),
  );
  const status = parseCollectionStatus(enrichment);
  const empty = isEnrichmentEmpty(enrichment);
  const carded = keysRenderedByCards(enrichment);
  // Anything a purpose-built card did not claim, rendered generically, so a
  // module added on the backend is never silently invisible.
  const uncarded = Object.fromEntries(
    Object.entries(enrichment ?? {}).filter(
      ([key, value]) =>
        key !== "completeness" &&
        !carded.has(key) &&
        value !== null &&
        value !== undefined &&
        value !== "" &&
        !(Array.isArray(value) && value.length === 0) &&
        !(typeof value === "object" && !Array.isArray(value) && Object.keys(value as object).length === 0),
    ),
  );

  return (
    <div className="space-y-4">
      <div>
        <div className="text-xs font-semibold uppercase tracking-[0.16em] text-accent">{contextLabel}</div>
        <h3 className="mt-1 text-lg font-bold">Enrichment & OSINT Data</h3>
        <p className="mt-1 text-xs text-text-secondary">
          Corroborating technical signals that augment the composite threat evaluation. Everything the backend
          collected is shown here at full depth; the Investigation tab carries only the decision-critical subset.
        </p>
      </div>

      {/* Collection status first: it is what explains everything below it. */}
      <CollectionStatusPanel status={status} />

      {enrichment.analysis_notes?.length ? (
        <Section title="Analyst Notes" data={{ notes: enrichment.analysis_notes }} />
      ) : null}

      {geo && (
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Stat label="Country" value={geo.country || geo.country_code || "—"} />
          <Stat label="City" value={geo.city || "—"} />
          <Stat label="ISP / Org" value={geo.isp || geo.org || "—"} />
          <Stat label="ASN" value={geo.asn || "—"} />
        </div>
      )}

      {/* 1. Web Preview Card (urlscan.io proxied live preview) */}
      {enrichment.web_preview && (
        <WebPreviewCard preview={enrichment.web_preview} domainOrUrl={iocType} />
      )}

      {/* Subdomain list. Previously only on the Investigation tab. */}
      {enrichment.subdomains && (
        <SubdomainsCard subdomainsData={enrichment.subdomains} />
      )}

      {/* Context indicator types (ASN routing, MITRE ATT&CK, host artifacts,
          file hashes, filenames/paths, user-agents, MACs, fuzzy hashes). This
          used to render on the Investigation tab; it lives here now so the two
          tabs never show the same module. */}
      <ContextIntelCard extra={enrichment.extra} />

      {/* 2. Infostealer Attack Surface (Hudson Rock) */}
      {enrichment.infostealer && (
        <InfostealerExposureCard infostealer={enrichment.infostealer} domainOrUser={iocType} />
      )}

      {/* 3. Host Intelligence & Attack Surface Matrix (Shodan InternetDB / Active) */}
      {hasHostIntel && (
        <HostVulnerabilityMatrix
          hostIntel={enrichment.host_intel}
          geoip={enrichment.geoip}
          legacyPorts={enrichment.open_ports}
        />
      )}

      {/* 4. Sysadmin Abuse & Incident Reports (AbuseIPDB verbose) */}
      {enrichment.abuse_reports && enrichment.abuse_reports.length > 0 && (
        <AbuseReportsPanel reports={enrichment.abuse_reports} />
      )}

      {/* 5. Domain Hosting IP Pivot Intelligence */}
      {hostingIps.length > 0 && (
        <section className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-border/50 pb-2">
            <h4 className="text-xs font-semibold uppercase tracking-[0.14em] text-accent">
              Hosting Infrastructure Pivot
            </h4>
            <span className="text-xs text-text-secondary">Resolved A-Records Context</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {hostingIps.map(([ip, rawInfo]) => {
              const info = rawInfo as Record<string, unknown>;
              const isRiot = !!info.riot;
              const riotName = (info.riot_name as string) || "Cloudflare / CDN Provider";
              const isDatacenter = !!info.is_datacenter;
              const org = (info.org as string) || (info.isp as string) || "";

              return (
                <div
                  key={ip}
                  className="rounded-lg border border-border/70 bg-bg-elevated/40 p-3 space-y-1.5 text-xs font-mono"
                >
                  <div className="flex items-center justify-between font-bold">
                    <span className="text-text-primary">{ip}</span>
                    {isRiot ? (
                      <span className="rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.2 text-xs">
                        RIOT (Known Good CDN)
                      </span>
                    ) : isDatacenter ? (
                      <span className="rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/30 px-2 py-0.2 text-xs">
                        Datacenter IP
                      </span>
                    ) : null}
                  </div>
                  <div className="text-xs text-text-secondary">
                    {isRiot ? (
                      <span>Provider: <strong className="text-emerald-300">{riotName}</strong></span>
                    ) : org ? (
                      <span>Network: {org}</span>
                    ) : (
                      <span>Resolved Host IP</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* 6. Malware URLs & Associated Hashes (OTX / URLhaus) */}
      {(enrichment.malware_urls?.length || enrichment.associated_hashes?.length) && (
        <section className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-border/50 pb-2">
            <h4 className="text-xs font-semibold uppercase tracking-[0.14em] text-accent">
              Associated Malware & C2 Indicators
            </h4>
            <span className="text-xs text-text-secondary">AlienVault OTX Correlated</span>
          </div>

          {enrichment.malware_urls && enrichment.malware_urls.length > 0 && (
            <div className="space-y-1">
              <span className="text-xs font-semibold text-red-400 block">
                Malicious URLs on Host ({enrichment.malware_urls.length})
              </span>
              <div className="max-h-32 overflow-y-auto space-y-1 font-mono text-xs">
                {enrichment.malware_urls.map((url, i) => (
                  <div key={i} className="truncate rounded bg-bg-elevated/70 p-1.5 text-text-secondary border border-border/40" title={url}>
                    {url}
                  </div>
                ))}
              </div>
            </div>
          )}

          {enrichment.associated_hashes && enrichment.associated_hashes.length > 0 && (
            <div className="space-y-1 pt-2">
              <span className="text-xs font-semibold text-amber-400 block">
                Associated Malware Hashes ({enrichment.associated_hashes.length})
              </span>
              <div className="flex flex-wrap gap-1 font-mono text-xs">
                {enrichment.associated_hashes.map((h, i) => (
                  <span key={i} className="rounded bg-bg-elevated px-2 py-0.5 text-xs border border-border/50 text-text-secondary">
                    {h.slice(0, 16)}...
                  </span>
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {/* Identity & Breach Exposure Highlight.
          Gated strictly on the presence of breach/email data. It used to also
          fire on `iocType === "email" | "phone"`, which rendered an all-zero
          panel (Breach Count 0, Source "None", SPF "Unavailable") for any phone
          lookup even though the backend collects no breach data for phone at
          all. A row of zeroes reads as a finding, which is worse than absence. */}
      {hasIdentityData && (
        <div className="rounded-xl border border-red-500/20 bg-red-950/10 p-3.5">
          <div className="mb-2 text-xs font-bold uppercase tracking-wider text-red-400">
            Identity & Credential Exposure Summary
          </div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat
              label="Breach Count"
              value={String(breachCount)}
              accent={breachCount > 0 ? "text-red-400" : "text-emerald-400"}
            />
            <Stat
              label="Breach Source"
              value={breachSource}
            />
            <Stat
              label="Exposed Data Types"
              value={String(exposedTypeCount)}
            />
            <Stat
              label="SPF"
              value={spfConfigured ? spfValue : emailSec ? "Missing" : "Unavailable"}
              accent={spfConfigured ? "text-emerald-400" : "text-amber-400"}
            />
          </div>
        </div>
      )}

      {/* WHOIS section with Data Provenance Badge */}
      {enrichment.whois && (
        <Section
          title="WHOIS / Registration Record"
          data={enrichment.whois}
          badge={
            <DataProvenanceBadge
              tier={enrichment.whois.fallback_tier_used}
              privacyProtected={enrichment.whois.privacy_protected}
              isNewlyRegistered={enrichment.whois.is_newly_registered}
            />
          }
        />
      )}

      {sections.map(([title, data]) => (
        <Section key={title} title={title} data={data} />
      ))}

      {/* Anything the purpose-built cards above did not claim, rendered in
          depth. This is what keeps a newly added backend module from being
          invisible in the UI. */}
      {Object.keys(uncarded).length > 0 && (
        <Section title="All Other Collected Data" data={uncarded} />
      )}

      {empty && (
        <div className="rounded-xl border border-border bg-bg-card p-6 text-center">
          <div className="text-sm font-semibold text-text-primary">No enrichment data for this indicator</div>
          <p className="mx-auto mt-2 max-w-xl text-xs text-text-secondary">{describeEmptyState(enrichment, iocType)}</p>
        </div>
      )}
    </div>
  );
}
