export default function HostingPivotCard({
  hostingIpIntel,
}: {
  hostingIpIntel?: Record<string, unknown>;
}) {
  const entries = Object.entries(hostingIpIntel ?? {});
  if (entries.length === 0) return null;

  return (
    <div className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
      <div className="flex items-center justify-between border-b border-border/60 pb-2">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-sky-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
            <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
            <line x1="6" y1="6" x2="6.01" y2="6" />
            <line x1="6" y1="18" x2="6.01" y2="18" />
          </svg>
          <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary">
            Hosting Infrastructure & CDN Bypass
          </h4>
        </div>
        <span className="text-xs text-text-secondary">Resolved Host IPs ({entries.length})</span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
        {entries.map(([ip, rawInfo]) => {
          const info = (rawInfo && typeof rawInfo === "object" ? rawInfo : {}) as Record<string, unknown>;
          const isRiot = !!info.riot;
          const riotName = (info.riot_name as string) || "Cloudflare / CDN Provider";
          const isDatacenter = !!info.is_datacenter;
          const org = (info.org as string) || (info.isp as string) || "";
          const country = (info.country as string) || "";

          return (
            <div
              key={ip}
              className="rounded-lg border border-border/70 bg-bg-elevated/40 p-3 space-y-1.5 text-xs font-mono"
            >
              <div className="flex items-center justify-between font-bold">
                <span className="text-text-primary text-sm">{ip}</span>
                {isRiot ? (
                  <span className="rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 text-xs font-semibold">
                    RIOT Verified CDN
                  </span>
                ) : isDatacenter ? (
                  <span className="rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/30 px-2 py-0.5 text-xs font-semibold">
                    Datacenter Host
                  </span>
                ) : null}
              </div>

              <div className="text-xs text-text-secondary pt-0.5">
                {isRiot ? (
                  <div className="text-emerald-300 font-medium">
                    CDN Provider: <strong>{riotName}</strong>
                    <div className="text-xs text-text-secondary font-normal mt-0.5">
                      Port scanning bypassed to eliminate shared CDN false positives.
                    </div>
                  </div>
                ) : (
                  <div>
                    {org && <span className="block text-text-primary truncate">Org: {org}</span>}
                    {country && <span className="block text-text-secondary text-xs">Location: {country}</span>}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
