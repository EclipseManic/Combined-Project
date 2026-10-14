interface DataProvenanceBadgeProps {
  tier?: number;
  privacyProtected?: boolean;
  isNewlyRegistered?: boolean;
  sourceName?: string;
}

export default function DataProvenanceBadge({
  tier,
  privacyProtected,
  isNewlyRegistered,
  sourceName,
}: DataProvenanceBadgeProps) {
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-xs">
      {tier === 1 && (
        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 font-medium text-emerald-400">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
          Authoritative RDAP
        </span>
      )}
      {tier === 2 && (
        <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-0.5 font-medium text-amber-400">
          <span className="h-1.5 w-1.5 rounded-full bg-amber-400"></span>
          Port 43 TCP WHOIS
        </span>
      )}
      {tier === 3 && (
        <span className="inline-flex items-center gap-1 rounded-full border border-purple-500/30 bg-purple-500/10 px-2.5 py-0.5 font-medium text-purple-400">
          <span className="h-1.5 w-1.5 rounded-full bg-purple-400"></span>
          VirusTotal Attributes Fallback
        </span>
      )}
      {privacyProtected && (
        <span className="inline-flex items-center gap-1 rounded-full border border-blue-500/30 bg-blue-500/10 px-2.5 py-0.5 font-medium text-blue-400">
          <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          Privacy Protected / GDPR
        </span>
      )}
      {isNewlyRegistered && (
        <span className="inline-flex items-center gap-1 rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-0.5 font-semibold text-red-400 animate-pulse">
          <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          Newly Registered (&lt;30 days)
        </span>
      )}
      {sourceName && (
        <span className="text-xs text-text-secondary">
          via {sourceName}
        </span>
      )}
    </div>
  );
}
