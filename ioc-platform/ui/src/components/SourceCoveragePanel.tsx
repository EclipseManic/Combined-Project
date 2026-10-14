import { useEffect, useState } from "react";
import { getSourceInventory, type SourceInventory } from "../services/api";

export default function SourceCoveragePanel() {
  const [inventory, setInventory] = useState<SourceInventory | null>(null);
  const [error, setError] = useState(false);
  useEffect(() => {
    let cancelled = false;
    getSourceInventory().then((inv) => { if (!cancelled) setInventory(inv); }).catch(() => { if (!cancelled) setError(true); });
    return () => { cancelled = true; };
  }, []);
  if (error) {
    return (
      <p className="max-w-6xl mx-auto mb-6 text-xs text-text-secondary bg-bg-card border border-border rounded-lg p-4">
        Source coverage could not be loaded. Check the backend health endpoint.
      </p>
    );
  }
  if (!inventory) {
    return (
      <div className="max-w-6xl mx-auto mb-6 bg-bg-card border border-border rounded-lg p-4">
        <div className="h-4 w-48 bg-bg-elevated rounded animate-pulse" />
        <div className="h-3 w-full bg-bg-elevated rounded mt-2 animate-pulse" />
      </div>
    );
  }
  return (
    <details className="max-w-6xl mx-auto mb-6 bg-bg-card border border-border rounded-lg p-4 text-sm">
      <summary className="cursor-pointer text-text-secondary uppercase tracking-wider text-xs font-semibold">
        Source coverage ({inventory.available_count}/{inventory.count} usable; {inventory.credential_configured_count} credentials loaded)
      </summary>
      <p className="mt-2 text-xs text-text-secondary">“Public” means the adapter can run without a credential; it does not mean the provider is available, complete, or suitable for sensitive IOCs.</p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-3">
        {inventory.sources.map((source) => (
          <div key={source.name} className="flex items-center justify-between gap-3 bg-bg-elevated rounded p-2">
            <span><span className="block">{source.name}</span><span className="block text-xs text-text-secondary">{source.supported_types.join(", ")}</span></span>
            <span className={source.enabled_by_policy && (source.configured || source.public_without_key) ? "text-green-400" : "text-amber-400"}>
              {!source.enabled_by_policy
                ? "disabled by policy"
                : source.credential_source === "public_no_key"
                ? "public"
                : source.configured
                  ? source.credential_source
                  : `${source.credential_env ?? "API key"} missing`}
            </span>
          </div>
        ))}
      </div>
    </details>
  );
}
