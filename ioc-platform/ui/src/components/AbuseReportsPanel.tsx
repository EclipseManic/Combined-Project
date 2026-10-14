import { useState } from "react";
import type { AbuseReport } from "../services/api";

interface AbuseReportsPanelProps {
  reports?: AbuseReport[];
}

export default function AbuseReportsPanel({ reports = [] }: AbuseReportsPanelProps) {
  const [displayCount, setDisplayCount] = useState(5);

  if (!reports || reports.length === 0) return null;

  const visibleReports = reports.slice(0, displayCount);

  return (
    <section className="rounded-xl border border-border bg-bg-card p-4 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-2.5">
        <div className="flex items-center gap-2">
          <span className="flex h-6 w-6 items-center justify-center rounded-md bg-amber-500/10 text-amber-400">
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 13a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 8h6v4H7V8z" />
            </svg>
          </span>
          <h4 className="text-xs font-semibold uppercase tracking-[0.14em] text-accent">
            Sysadmin Abuse & Incident Reports ({reports.length})
          </h4>
        </div>
        <span className="text-xs text-text-secondary bg-bg-elevated px-2 py-0.5 rounded border border-border/60">
          AbuseIPDB Verified Community Reports
        </span>
      </div>

      <div className="space-y-3">
        {visibleReports.map((report, idx) => {
          const categories = report.category_names?.length
            ? report.category_names
            : report.categories?.length
            ? report.categories
            : ["Suspicious Activity"];

          return (
            <div
              key={idx}
              className="rounded-lg border border-border/70 bg-bg-elevated/40 p-3 space-y-2 text-xs font-mono"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-text-secondary">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-text-primary">
                    {report.reported_at ? report.reported_at.replace("T", " ").replace("Z", " UTC") : "Recent"}
                  </span>
                  {report.reporter_country && (
                    <span className="rounded bg-bg-card px-1.5 py-0.5 border border-border/50 text-xs">
                      Reporter: {report.reporter_country}
                    </span>
                  )}
                </div>
                <div className="flex flex-wrap gap-1">
                  {categories.map((cat, cIdx) => (
                    <span
                      key={cIdx}
                      className="rounded bg-amber-950/40 text-amber-300 border border-amber-500/30 px-1.5 py-0.2 text-xs font-medium"
                    >
                      {cat}
                    </span>
                  ))}
                </div>
              </div>

              {report.comment ? (
                <p className="text-text-primary whitespace-pre-wrap break-all bg-bg-card/70 p-2 rounded border border-border/40 text-xs">
                  {report.comment}
                </p>
              ) : (
                <span className="text-text-secondary italic text-xs">
                  No reporter commentary attached.
                </span>
              )}
            </div>
          );
        })}
      </div>

      {reports.length > displayCount && (
        <div className="text-center pt-1">
          <button
            onClick={() => setDisplayCount((prev) => Math.min(prev + 5, reports.length))}
            className="rounded-lg border border-border bg-bg-elevated px-3 py-1.5 text-xs font-medium text-text-primary hover:bg-bg-elevated/80 transition-colors"
          >
            Show more reports ({reports.length - displayCount} remaining)
          </button>
        </div>
      )}
    </section>
  );
}
