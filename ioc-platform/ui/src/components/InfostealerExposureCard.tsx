import type { InfostealerIntel } from "../services/api";

interface InfostealerExposureCardProps {
  infostealer?: InfostealerIntel;
  domainOrUser?: string;
}

export default function InfostealerExposureCard({
  infostealer,
  domainOrUser,
}: InfostealerExposureCardProps) {
  if (!infostealer) return null;

  const {
    total_employee_compromises = 0,
    total_client_compromises = 0,
    top_corporate_services = [],
    top_external_services = [],
    stealer_families = {},
    password_strength_weak_pct,
    password_strength_strong_pct,
    total_compromised_urls,
    date_range,
  } = infostealer;

  const totalInfections = total_employee_compromises + total_client_compromises;
  const isCompromised = totalInfections > 0;
  const familiesList = Object.entries(stealer_families).filter(([_, count]) => count > 0);

  return (
    <section className="rounded-xl border border-border bg-bg-card p-4 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-2.5">
        <div className="flex items-center gap-2">
          <span className="flex h-6 w-6 items-center justify-center rounded-md bg-red-500/10 text-red-400">
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </span>
          <h4 className="text-xs font-semibold uppercase tracking-[0.14em] text-accent">
            Infostealer Attack Surface
          </h4>
        </div>
        <span className="text-xs text-text-secondary bg-bg-elevated px-2 py-0.5 rounded border border-border/60">
          Hudson Rock Cavalier Intelligence
        </span>
      </div>

      {/* Compromise Status Banner */}
      <div
        className={`rounded-lg p-3 border ${
          isCompromised
            ? "border-red-500/30 bg-red-950/20 text-red-200"
            : "border-emerald-500/30 bg-emerald-950/20 text-emerald-200"
        }`}
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold uppercase tracking-wider">
            {isCompromised ? "Compromised Credentials Detected" : "No Active Compromises Observed"}
          </span>
          {date_range && (
            <span className="text-xs text-text-secondary opacity-80">
              Active window: {date_range}
            </span>
          )}
        </div>
        <p className="mt-1 text-xs opacity-90">
          {isCompromised
            ? `Malware infections observed harvesting authentication credentials for ${domainOrUser || "this target"}.`
            : "No infostealer botnet logs currently record compromised logins for this target."}
        </p>
      </div>

      {/* Dual Metrics */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <div className="rounded-lg border border-border/70 bg-bg-elevated/50 p-3">
          <div className="text-xs uppercase tracking-wider text-text-secondary">
            Employee Compromises
          </div>
          <div
            className={`mt-1 text-base font-bold ${
              total_employee_compromises > 0 ? "text-red-400" : "text-emerald-400"
            }`}
          >
            {total_employee_compromises}
          </div>
        </div>

        <div className="rounded-lg border border-border/70 bg-bg-elevated/50 p-3">
          <div className="text-xs uppercase tracking-wider text-text-secondary">
            Client/User Compromises
          </div>
          <div
            className={`mt-1 text-base font-bold ${
              total_client_compromises > 0 ? "text-amber-400" : "text-emerald-400"
            }`}
          >
            {total_client_compromises}
          </div>
        </div>

        {total_compromised_urls !== undefined && (
          <div className="rounded-lg border border-border/70 bg-bg-elevated/50 p-3">
            <div className="text-xs uppercase tracking-wider text-text-secondary">
              Compromised URLs
            </div>
            <div className="mt-1 text-base font-bold text-text-primary">
              {total_compromised_urls}
            </div>
          </div>
        )}

        {(password_strength_weak_pct !== undefined || password_strength_strong_pct !== undefined) && (
          <div className="rounded-lg border border-border/70 bg-bg-elevated/50 p-3">
            <div className="text-xs uppercase tracking-wider text-text-secondary">
              Password Hygiene
            </div>
            <div className="mt-1 text-xs font-semibold">
              <span className="text-red-400">{password_strength_weak_pct ?? 0}% Weak</span>
              <span className="text-text-secondary"> / </span>
              <span className="text-emerald-400">{password_strength_strong_pct ?? 0}% Strong</span>
            </div>
          </div>
        )}
      </div>

      {/* Stealer Families Breakdown */}
      {familiesList.length > 0 && (
        <div>
          <div className="mb-2 text-xs font-semibold text-text-secondary">
            Identified Malware Stealer Families ({familiesList.length})
          </div>
          <div className="flex flex-wrap gap-2">
            {familiesList.map(([family, count]) => (
              <div
                key={family}
                className="inline-flex items-center gap-1.5 rounded-md border border-red-500/20 bg-bg-elevated px-2.5 py-1 text-xs"
              >
                <span className="h-1.5 w-1.5 rounded-full bg-red-400"></span>
                <span className="font-semibold text-text-primary">{family}</span>
                <span className="rounded bg-red-950/40 px-1.5 py-0.2 text-xs font-mono text-red-300">
                  {count}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Top Corporate Services Exposed */}
      {top_corporate_services.length > 0 && (
        <div>
          <div className="mb-2 text-xs font-semibold text-text-secondary">
            Targeted Corporate Logins & Portals
          </div>
          <div className="flex flex-wrap gap-1.5">
            {top_corporate_services.map((svc) => (
              <span
                key={svc}
                className="inline-flex items-center gap-1 rounded bg-bg-elevated px-2 py-0.5 text-xs font-mono text-text-primary border border-border/60"
              >
                <span className="text-accent">ðŸ”’</span> {svc}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* External Services */}
      {top_external_services.length > 0 && (
        <div>
          <div className="mb-1.5 text-xs font-semibold text-text-secondary">
            Compromised External Integrations
          </div>
          <div className="flex flex-wrap gap-1 text-xs font-mono text-text-secondary">
            {top_external_services.map((svc) => (
              <span key={svc} className="rounded bg-bg-elevated/60 px-1.5 py-0.5">
                {svc}
              </span>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
