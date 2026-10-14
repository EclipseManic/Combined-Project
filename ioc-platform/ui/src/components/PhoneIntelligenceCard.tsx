import { formatNumber } from "../lib/format";

/**
 * Phone intelligence dashboard.
 *
 * The `phone` indicator type arrived with no card at all: every provider's
 * answer was reachable only as fields on a provider card, so the carrier, the
 * line type and the registered holder were never presented together. Two
 * providers now serve it (AbstractAPI Phone Intelligence and IPQualityScore
 * Phone), which is enough to show where they agree and where they do not.
 *
 * The one field worth thinking about is `name` — the registered holder. It is
 * personal data returned by the vendor, and this card shows it because an
 * analyst triaging a phone number is exactly who needs to know who it is
 * registered to. It is stored in the provider payload like any other field, so
 * it will appear in exports; see the README note on that.
 */

interface ProviderRow {
  source?: string;
  verdict?: string;
  confidence?: string;
  raw_data?: Record<string, unknown> | null;
  provider_summary?: string | null;
}

function str(value: unknown): string | null {
  return typeof value === "string" && value && value !== "N/A" ? value : null;
}

function num(value: unknown): string | null {
  return typeof value === "number" && Number.isFinite(value) ? formatNumber(value) : null;
}

function nested(data: Record<string, unknown> | null | undefined, ...path: string[]): unknown {
  let current: unknown = data;
  for (const key of path) {
    if (typeof current !== "object" || current === null) return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

function bool(value: unknown): string {
  if (value === true) return "Yes";
  if (value === false) return "No";
  return "—";
}

/** Providers whose name matches, in the order they should be preferred. */
function pick(rows: ProviderRow[], matcher: (name: string) => boolean): ProviderRow | undefined {
  return rows.find((row) => matcher(row.source ?? ""));
}

function Tile({ label, value, accent = "text-text-primary", title }: { label: string; value: string; accent?: string; title?: string }) {
  return (
    <div className="min-w-0 rounded-lg border border-border/70 bg-bg-elevated/50 p-3">
      <div className="text-xs uppercase tracking-wider text-text-secondary">{label}</div>
      <div className={`mt-1 truncate font-mono text-sm font-bold ${accent}`} title={title ?? value}>
        {value}
      </div>
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 rounded border border-border/60 bg-bg-elevated/30 px-2.5 py-1.5">
      <div className="text-xs uppercase tracking-wider text-text-secondary">{label}</div>
      <div className="truncate font-mono text-xs font-semibold text-text-primary" title={value}>
        {value}
      </div>
    </div>
  );
}

/** A per-provider verdict line, so disagreement is visible rather than averaged. */
function Agreement({ rows }: { rows: ProviderRow[] }) {
  if (rows.length === 0) return null;
  return (
    <div className="mt-3 space-y-1.5">
      {rows.map((row) => {
        const tone =
          row.verdict === "malicious"
            ? "border-verdict-malicious/30 bg-verdict-malicious/10 text-verdict-malicious"
            : row.verdict === "suspicious"
              ? "border-amber-500/30 bg-amber-500/10 text-amber-200"
              : row.verdict === "clean"
                ? "border-verdict-clean/30 bg-verdict-clean/10 text-verdict-clean"
                : "border-border bg-bg-elevated text-text-secondary";
        return (
          <div key={row.source} className={`rounded border px-2.5 py-1.5 text-xs ${tone}`}>
            <span className="font-semibold">{row.source}</span>
            <span className="ml-2">{row.verdict ?? "unknown"}</span>
            {row.confidence && <span className="ml-1 opacity-80">({row.confidence} confidence)</span>}
            {row.provider_summary && <div className="mt-0.5 text-text-primary/80">{row.provider_summary}</div>}
          </div>
        );
      })}
    </div>
  );
}

export default function PhoneIntelligenceCard({ results }: { results: ProviderRow[] }) {
  const ipqs = pick(results, (name) => name === "IPQualityScore Phone")?.raw_data ?? null;
  const abstract = pick(results, (name) => name === "AbstractAPI Phone")?.raw_data ?? null;

  const fraudScore = num(ipqs?.fraud_score);
  const carrier = str(ipqs?.carrier) ?? str(nested(abstract, "phone_carrier", "name"));
  const lineType = str(ipqs?.line_type) ?? str(nested(abstract, "phone_carrier", "line_type"));
  const holder = str(ipqs?.name) ?? str(nested(abstract, "phone_registration", "name"));
  const smsEmail = str(ipqs?.sms_email) ?? str(nested(abstract, "phone_messaging", "sms_email"));
  const smsDomain = str(ipqs?.sms_domain) ?? str(nested(abstract, "phone_messaging", "sms_domain"));
  const country = str(ipqs?.country) ?? str(nested(abstract, "phone_location", "country_code"));
  const region = str(ipqs?.region) ?? str(nested(abstract, "phone_location", "region"));
  const city = str(ipqs?.city) ?? str(nested(abstract, "phone_location", "city"));
  const riskLevel = str(nested(abstract, "phone_risk", "risk_level"));

  const voip = ipqs?.VOIP;
  const risky = ipqs?.risky;
  const spammer = ipqs?.spammer;
  const recentAbuse = ipqs?.recent_abuse;
  const leaked = ipqs?.leaked;
  const doNotCall = ipqs?.do_not_call;
  const isValid = ipqs?.valid ?? nested(abstract, "phone_validation", "is_valid");
  const activeStatus = str(ipqs?.active_status);

  const blocked = (["associated_email_addresses", "user_activity", "number_recycling"] as const).filter(
    (key) => typeof ipqs?.[key] === "object" && ipqs?.[key] !== null,
  );

  return (
    <section className="rounded-xl border border-border bg-bg-card p-4">
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-border/50 pb-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="rounded border border-border px-1.5 py-0.5 text-xs font-bold uppercase tracking-wider text-text-secondary">
              Phone
            </span>
            <h3 className="text-sm font-bold uppercase tracking-wider text-text-primary">Number intelligence</h3>
          </div>
          <p className="mt-1 text-xs text-text-secondary">
            {carrier ? `Carrier ${carrier}` : "No carrier data returned"}
            {lineType ? ` · ${lineType}` : ""}
            {country ? ` · ${country}` : ""}
          </p>
        </div>
      </header>

      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Tile
          label="Fraud score"
          value={fraudScore === null ? "—" : `${fraudScore}/100`}
          accent={fraudScore === null ? "text-text-secondary" : Number(fraudScore) >= 40 ? "text-amber-300" : "text-emerald-300"}
          title="IPQualityScore 0-100. Not comparable to the platform's own risk score."
        />
        <Tile label="Valid" value={isValid === undefined ? "—" : bool(isValid)} />
        <Tile label="Line type" value={lineType ?? "—"} />
        <Tile label="Risk level" value={riskLevel ?? "—"} title={riskLevel ? "AbstractAPI risk level" : "Not provided by IPQualityScore"} />
      </div>

      <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Detail label="VoIP" value={voip === undefined ? "—" : bool(voip)} />
        <Detail label="Flagged risky" value={risky === undefined ? "—" : bool(risky)} />
        <Detail label="Spammer" value={spammer === undefined ? "—" : bool(spammer)} />
        <Detail label="Recent abuse" value={recentAbuse === undefined ? "—" : bool(recentAbuse)} />
        <Detail label="Leaked" value={leaked === undefined ? "—" : bool(leaked)} />
        <Detail label="Do not call" value={doNotCall === undefined ? "—" : bool(doNotCall)} />
        <Detail label="Location" value={[city, region, country].filter(Boolean).join(", ") || "—"} />
        <Detail label="Active status" value={activeStatus ?? "—"} />
      </div>

      {(holder || smsEmail || smsDomain) && (
        <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-3">
          {holder && <Detail label="Registered holder" value={holder} />}
          {smsEmail && <Detail label="Messaging address" value={smsEmail} />}
          {smsDomain && <Detail label="Messaging domain" value={smsDomain} />}
        </div>
      )}

      {blocked.length > 0 && (
        <p className="mt-2 text-xs text-text-secondary">
          Not available on this plan: {blocked.join(", ").replace(/_/g, " ")}. Those values are absent, not benign.
        </p>
      )}

      <Agreement rows={results.filter((row) => row.raw_data)} />

      {smsEmail && (
        <p className="mt-3 text-xs text-text-secondary">
          The messaging address is a pivot to another indicator type and can be investigated on its own.
        </p>
      )}
    </section>
  );
}
