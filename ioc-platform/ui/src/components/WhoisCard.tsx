import type { WhoisInfo } from "../services/api";
import DataProvenanceBadge from "./DataProvenanceBadge";

function formatDate(dateStr?: string): string {
  if (!dateStr) return "—";
  try {
    const d = new Date(dateStr);
    return isNaN(d.getTime()) ? dateStr : d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
  } catch {
    return dateStr;
  }
}

export default function WhoisCard({ whois }: { whois: WhoisInfo }) {
  const age = whois.domain_age_days;
  const isNew = whois.is_newly_registered || (age != null && age < 30);

  return (
    <div className="rounded-xl border border-border bg-bg-card p-4 space-y-3.5">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-2.5">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-accent" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <rect x="3" y="4" width="18" height="16" rx="2" />
            <line x1="16" y1="2" x2="16" y2="6" />
            <line x1="8" y1="2" x2="8" y2="6" />
            <line x1="3" y1="10" x2="21" y2="10" />
          </svg>
          <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary">
            WHOIS & Registration Provenance
          </h4>
        </div>
        <DataProvenanceBadge
          tier={whois.fallback_tier_used}
          privacyProtected={whois.privacy_protected}
          isNewlyRegistered={isNew}
        />
      </div>

      {/* Primary Attributes Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs">
        <div className="rounded-lg bg-bg-elevated/40 border border-border/50 p-2.5">
          <span className="text-xs uppercase tracking-wider text-text-secondary block">Registrar</span>
          <span className="font-semibold text-text-primary truncate block mt-0.5" title={whois.registrar || "Unknown"}>
            {whois.registrar || "Not disclosed"}
          </span>
        </div>

        <div className="rounded-lg bg-bg-elevated/40 border border-border/50 p-2.5">
          <span className="text-xs uppercase tracking-wider text-text-secondary block">Domain Age</span>
          <span className={`font-semibold block mt-0.5 ${isNew ? "text-red-400 font-bold" : "text-text-primary"}`}>
            {age != null ? `${age} days` : "Unknown"}
            {isNew && <span className="ml-1 text-xs uppercase text-red-400">(New)</span>}
          </span>
        </div>

        <div className="rounded-lg bg-bg-elevated/40 border border-border/50 p-2.5">
          <span className="text-xs uppercase tracking-wider text-text-secondary block">Registrant Country</span>
          <span className="font-semibold text-text-primary block mt-0.5">
            {whois.registrant_country || "Redacted / Privacy"}
          </span>
        </div>

        <div className="rounded-lg bg-bg-elevated/40 border border-border/50 p-2.5">
          <span className="text-xs uppercase tracking-wider text-text-secondary block">Created Date</span>
          <span className="font-mono text-text-secondary block mt-0.5">
            {formatDate(whois.creation_date)}
          </span>
        </div>

        <div className="rounded-lg bg-bg-elevated/40 border border-border/50 p-2.5">
          <span className="text-xs uppercase tracking-wider text-text-secondary block">Expiry Date</span>
          <span className="font-mono text-text-secondary block mt-0.5">
            {formatDate(whois.expiration_date)}
          </span>
        </div>

        <div className="rounded-lg bg-bg-elevated/40 border border-border/50 p-2.5">
          <span className="text-xs uppercase tracking-wider text-text-secondary block">Updated Date</span>
          <span className="font-mono text-text-secondary block mt-0.5">
            {formatDate(whois.updated_date)}
          </span>
        </div>
      </div>

      {/* Nameservers */}
      {whois.nameservers && whois.nameservers.length > 0 && (
        <div className="space-y-1.5 pt-1">
          <span className="text-xs uppercase tracking-wider text-text-secondary font-semibold block">Authoritative Nameservers</span>
          <div className="flex flex-wrap gap-1.5 font-mono text-xs">
            {whois.nameservers.map((ns, i) => (
              <span key={i} className="rounded bg-bg-elevated px-2 py-0.5 border border-border/60 text-text-primary">
                {ns}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Status Codes */}
      {whois.status_codes && whois.status_codes.length > 0 && (
        <div className="space-y-1 pt-1">
          <span className="text-xs uppercase tracking-wider text-text-secondary font-semibold block">Registry Status Codes</span>
          <div className="flex flex-wrap gap-1 font-mono text-xs text-text-secondary">
            {whois.status_codes.map((st, i) => (
              <span key={i} className="rounded bg-bg-elevated/50 px-1.5 py-0.5 border border-border/40">
                {st}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
