import { useState } from "react";
import type { SubdomainInfo } from "../services/api";

export default function SubdomainsCard({
  subdomainsData,
}: {
  subdomainsData?: SubdomainInfo;
}) {
  const [filter, setFilter] = useState("");
  const [copied, setCopied] = useState(false);

  if (!subdomainsData || !subdomainsData.subdomains || subdomainsData.subdomains.length === 0) {
    return null;
  }

  const allSubs = subdomainsData.subdomains;
  const filtered = filter.trim()
    ? allSubs.filter((s) => s.toLowerCase().includes(filter.toLowerCase()))
    : allSubs;

  const handleCopy = () => {
    void navigator.clipboard?.writeText(allSubs.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-2.5">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-accent" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <rect x="3" y="3" width="7" height="7" />
            <rect x="14" y="3" width="7" height="7" />
            <rect x="14" y="14" width="7" height="7" />
            <rect x="3" y="14" width="7" height="7" />
          </svg>
          <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary">
            Certificate Transparency Subdomains
          </h4>
          <span className="rounded-full bg-accent/10 border border-accent/30 px-2 py-0.2 text-xs font-mono text-accent">
            {allSubs.length}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-text-secondary">Source: Certificate Transparency (crt.sh)</span>
          <button
            type="button"
            onClick={handleCopy}
            className="rounded border border-border px-2 py-0.5 text-xs text-text-secondary hover:text-accent hover:border-accent transition-colors"
          >
            {copied ? "Copied!" : "Copy all"}
          </button>
        </div>
      </div>

      {/* Filter bar */}
      {allSubs.length > 5 && (
        <div className="relative">
          <input
            type="text"
            placeholder="Filter subdomains (e.g. vpn, mail, api)..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="w-full rounded-lg border border-border bg-bg-elevated/40 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-secondary/60 focus:border-accent focus:outline-none"
          />
          {filter && (
            <button
              type="button"
              onClick={() => setFilter("")}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-xs text-text-secondary hover:text-text-primary"
            >
              âœ•
            </button>
          )}
        </div>
      )}

      {/* Subdomains list */}
      <div className="max-h-48 overflow-y-auto space-y-1 font-mono text-xs pr-1">
        {filtered.slice(0, 50).map((sub, i) => (
          <div
            key={i}
            className="flex items-center justify-between rounded bg-bg-elevated/40 px-2.5 py-1.5 border border-border/40 hover:border-accent/40 transition-colors"
          >
            <span className="text-text-primary truncate">{sub}</span>
          </div>
        ))}
        {filtered.length > 50 && (
          <div className="text-center text-xs text-text-secondary py-1">
            Showing first 50 of {filtered.length} subdomains
          </div>
        )}
        {filtered.length === 0 && (
          <div className="text-center text-xs text-text-secondary py-3">
            No subdomains match "{filter}"
          </div>
        )}
      </div>
    </div>
  );
}
