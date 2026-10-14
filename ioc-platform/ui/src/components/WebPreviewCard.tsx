import { useEffect, useState } from "react";
import { fetchProtectedImage } from "../services/api";
import type { WebPreviewInfo } from "../services/api";

interface WebPreviewCardProps {
  preview?: WebPreviewInfo;
  domainOrUrl?: string;
}

export default function WebPreviewCard({ preview, domainOrUrl }: WebPreviewCardProps) {
  const [imageFailed, setImageFailed] = useState(false);
  const [protectedImage, setProtectedImage] = useState<string>();

  const screenshotUrl = preview?.screenshot_url;
  useEffect(() => {
    let active = true;
    let objectUrl: string | undefined;
    setProtectedImage(undefined);
    setImageFailed(false);
    if (!screenshotUrl) return () => {
      active = false;
    };
    if (!screenshotUrl.startsWith("/api/")) {
      setProtectedImage(screenshotUrl);
      return () => {
        active = false;
      };
    }
    fetchProtectedImage(screenshotUrl)
      .then((url) => {
        if (!active) {
          URL.revokeObjectURL(url);
          return;
        }
        objectUrl = url;
        setProtectedImage(url);
      })
      .catch(() => {
        if (active) setImageFailed(true);
      });
    return () => {
      active = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [screenshotUrl]);

  if (!preview) return null;

  const {
    screenshot_url,
    page_title,
    server,
    language,
    domain_age_days,
    tls_issuer,
    tls_valid_days,
    asn_name,
    detected_brands = [],
    detected_technologies = [],
    mime_type,
    scan_uuid,
  } = preview;

  const isNewlyRegistered = domain_age_days !== undefined && domain_age_days < 30;
  const hasBrands = detected_brands.length > 0;
  const displayImage = protectedImage ?? (screenshot_url && !screenshot_url.startsWith("/api/") ? screenshot_url : undefined);

  return (
    <section className="rounded-xl border border-border bg-bg-card p-4 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-2.5">
        <div className="flex items-center gap-2">
          <span className="flex h-6 w-6 items-center justify-center rounded-md bg-blue-500/10 text-blue-400">
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
          </span>
          <h4 className="text-xs font-semibold uppercase tracking-[0.14em] text-accent">
            Live Web Page Preview & Fingerprint
          </h4>
        </div>
        {scan_uuid && (
          <a
            href={`https://urlscan.io/result/${scan_uuid}/`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-accent hover:underline flex items-center gap-1"
          >
            urlscan.io report â†—
          </a>
        )}
      </div>

      {/* Brand Impersonation Warning */}
      {hasBrands && (
        <div className="rounded-lg border border-red-500/40 bg-red-950/30 p-3 text-red-200">
          <div className="flex items-center gap-2 text-xs font-bold text-red-400">
            <svg className="h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            Brand Impersonation / Phishing Target Detected
          </div>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {detected_brands.map((brand) => (
              <span
                key={brand}
                className="rounded bg-red-900/50 px-2 py-0.5 text-xs font-semibold text-red-100"
              >
                Target: {brand}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Content Layout: Screenshot + Metadata */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Proxied Screenshot */}
        <div className="md:col-span-1 rounded-lg border border-border/70 bg-bg-elevated overflow-hidden relative flex flex-col justify-center items-center min-h-[160px]">
          {displayImage && !imageFailed ? (
            <img
              src={displayImage}
              alt={`Web page preview of ${domainOrUrl || "target"}`}
              className="w-full h-full object-cover max-h-[220px]"
              onError={() => setImageFailed(true)}
              loading="lazy"
            />
          ) : (
            <div className="p-4 text-center text-xs text-text-secondary">
              <svg className="h-8 w-8 mx-auto mb-2 opacity-40" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
              {screenshot_url ? "Screenshot unavailable from upstream" : "No screenshot captured"}
            </div>
          )}
        </div>

        {/* Page Metadata & Technical Context */}
        <div className="md:col-span-2 space-y-3">
          {page_title && (
            <div>
              <div className="text-xs uppercase tracking-wider text-text-secondary">Page Title</div>
              <div className="text-sm font-semibold text-text-primary line-clamp-2">{page_title}</div>
            </div>
          )}

          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            {server && (
              <div className="rounded bg-bg-elevated/60 p-2 border border-border/50">
                <span className="text-text-secondary text-xs uppercase block">Server</span>
                <span className="text-text-primary font-medium">{server}</span>
              </div>
            )}
            {domain_age_days !== undefined && (
              <div className="rounded bg-bg-elevated/60 p-2 border border-border/50">
                <span className="text-text-secondary text-xs uppercase block">Domain Age</span>
                <span className={`font-semibold ${isNewlyRegistered ? "text-red-400" : "text-emerald-400"}`}>
                  {domain_age_days} days {isNewlyRegistered ? "(New)" : ""}
                </span>
              </div>
            )}
            {tls_issuer && (
              <div className="rounded bg-bg-elevated/60 p-2 border border-border/50">
                <span className="text-text-secondary text-xs uppercase block">TLS Certificate</span>
                <span className="text-text-primary truncate block" title={tls_issuer}>
                  {tls_issuer} {tls_valid_days ? `(${tls_valid_days}d valid)` : ""}
                </span>
              </div>
            )}
            {asn_name && (
              <div className="rounded bg-bg-elevated/60 p-2 border border-border/50">
                <span className="text-text-secondary text-xs uppercase block">Host Network</span>
                <span className="text-text-primary truncate block" title={asn_name}>{asn_name}</span>
              </div>
            )}
            {language && (
              <div className="rounded bg-bg-elevated/60 p-2 border border-border/50">
                <span className="text-text-secondary text-xs uppercase block">Language</span>
                <span className="text-text-primary">{language.toUpperCase()}</span>
              </div>
            )}
            {mime_type && (
              <div className="rounded bg-bg-elevated/60 p-2 border border-border/50">
                <span className="text-text-secondary text-xs uppercase block">Content-Type</span>
                <span className="text-text-primary truncate block">{mime_type}</span>
              </div>
            )}
          </div>

          {detected_technologies.length > 0 && (
            <div>
              <div className="text-xs uppercase tracking-wider text-text-secondary mb-1">
                Detected Technologies
              </div>
              <div className="flex flex-wrap gap-1">
                {detected_technologies.map((tech) => (
                  <span
                    key={tech}
                    className="rounded bg-bg-elevated px-2 py-0.5 text-xs font-mono text-text-secondary border border-border/50"
                  >
                    {tech}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
