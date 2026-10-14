/**
 * Phishing Detector's Sender & Auth and Artifacts panels, rebuilt to the
 * original's own sections.
 *
 * Read from templates/index.html:
 *   :993  Sender & Auth  — a two-column sender KV grid, five mismatch rows,
 *                          the four-cell SPF/DKIM/DMARC/ARC auth grid, then
 *                          Composite Authentication, Authentication-Results,
 *                          Primary Authentication Results, Received-SPF, DKIM
 *                          Signatures and Microsoft Security Headers
 *   :997  Artifacts      — detail cards rendered only when they have content:
 *                          URLs Detected (expandable url cards), urlscan.io,
 *                          Attachments, Email Content Analysis, and Technical
 *                          Observables with a search box over grouped IOCs.
 *                          Sections with nothing get an explicit empty line,
 *                          which is a deliberate difference from a silently
 *                          absent card: "we looked and found none" is not the
 *                          same claim as "we did not look".
 *   :1242 renderHopFlow  — the received path, badged for TLS, delay, internal
 *                          and MSA hops
 *   :1158 renderAuthGrid — SPF / DKIM / DMARC / ARC cells
 */
import { useState } from "react";
import {
  Card,
  CardHead,
  CardBody,
  Button,
  Badge,
  KV,
  Callout,
} from "../../ui";
import { Icon } from "../../lib/icons";
import { PHISHING_REPORT as P } from "../../data/fixtures";
import { copyText, truncate } from "../../lib/utils";
import { toast } from "../../shell/chrome";

/* =============================================================
   SENDER & AUTHENTICATION
   ============================================================= */

export function SenderAuth() {
  const a = P.auth;

  const methods = [
    { p: "SPF", r: "fail", al: "misaligned" },
    { p: "DKIM", r: "fail", al: "misaligned" },
    { p: "DMARC", r: "fail", al: "" },
    { p: "ARC", r: "not found", al: "" },
  ];

  const mismatches = [
    { label: "From vs Reply-To", left: P.fromAddress, right: P.replyTo, bad: true },
    { label: "From vs Return-Path", left: P.fromAddress, right: P.returnPath, bad: false },
    { label: "From vs Sender", left: P.fromAddress, right: "—", bad: false },
    { label: "From vs Resent-From", left: P.fromAddress, right: "—", bad: false },
  ];

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHead
          title="Sender & Authentication"
          icon="lock"
          subtitle="Everything the headers claim, next to everything they actually show"
        />
        <CardBody className="flex flex-col gap-5">
          {/* :992 — the sender KV grid, split into two columns */}
          <div className="grid md:grid-cols-2 gap-x-6">
            <div>
              <KV label="From" mono copyable>{P.from}</KV>
              <KV label="Reply-To" mono copyable>{P.replyTo}</KV>
              <KV label="Return-Path" mono copyable>{P.returnPath}</KV>
              <KV label="To" mono copyable>{P.to}</KV>
              <KV label="Message-ID" mono copyable>{P.messageId}</KV>
            </div>
            <div>
              <KV label="Subject">{P.subject}</KV>
              <KV label="Date">{P.date}</KV>
              <KV label="MIME-Version">1.0</KV>
              <KV label="X-Mailer">Zimbra 9.0</KV>
              <KV label="Domain age">
                <span style={{ color: "var(--color-warn)" }}>9 days</span>
              </KV>
              <KV label="Received hops">{P.hops.length}</KV>
            </div>
          </div>

          {/* :993 — the mismatch rows */}
          <div
            className="flex flex-col gap-2 pt-4 border-t"
            style={{ borderColor: "var(--color-line)" }}
          >
            {mismatches.map((m) => (
              <div key={m.label} className="flex items-start gap-3">
                <span
                  className="w-1.5 h-1.5 rounded-full mt-2 shrink-0"
                  style={{ background: m.bad ? "var(--color-bad)" : "var(--color-ok)" }}
                />
                <div className="min-w-0 flex-1">
                  <div
                    className="text-[12px] font-semibold"
                    style={{ color: m.bad ? "var(--color-bad)" : "var(--color-ink-3)" }}
                  >
                    {m.label} {m.bad ? "— MISMATCH" : "— aligned"}
                  </div>
                  <div
                    className="mono text-[11.5px] mt-0.5 break-all"
                    style={{ color: "var(--color-ink-4)" }}
                  >
                    {m.left} → {m.right}
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* :1159 renderAuthGrid — four protocol cells */}
          <div>
            <div
              className="text-[11px] font-bold uppercase tracking-[0.08em] mb-2"
              style={{ color: "var(--color-ink-4)" }}
            >
              Authentication
            </div>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5">
              {methods.map((m) => {
                const pass = m.r.toLowerCase().includes("pass");
                const fail = m.r.toLowerCase().includes("fail");
                return (
                  <div
                    key={m.p}
                    className="p-3 rounded-[var(--radius-md)] border"
                    style={{
                      background: pass
                        ? "rgb(52 211 153 / 0.06)"
                        : fail
                          ? "rgb(248 113 113 / 0.07)"
                          : "var(--color-surface-2)",
                      borderColor: pass
                        ? "rgb(52 211 153 / 0.28)"
                        : fail
                          ? "rgb(248 113 113 / 0.28)"
                          : "var(--color-line)",
                    }}
                  >
                    <div
                      className="text-[12px] font-black tracking-[0.06em]"
                      style={{
                        color: pass
                          ? "var(--color-ok)"
                          : fail
                            ? "var(--color-bad)"
                            : "var(--color-ink-4)",
                      }}
                    >
                      {m.p}
                    </div>
                    <div className="text-[12.5px] font-semibold mt-1">{m.r}</div>
                    {m.al && (
                      <div className="text-[11px] mt-0.5" style={{ color: "var(--color-ink-4)" }}>
                        {m.al}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* :1172 authDetail — Composite Authentication */}
          <DetailCard title="Composite Authentication" emoji="🔐">
            <KV label="Result">fail</KV>
            <KV label="Reason">
              {a.fromAlignment.detail}
            </KV>
            <KV label="Action">quarantine</KV>
          </DetailCard>

          {/* :1178 — Authentication-Results */}
          {P.authResults.map((ar) => (
            <DetailCard
              key={ar.authserv_id}
              title={`Authentication-Results (${P.authResults.length})`}
              emoji="📋"
            >
              {Object.entries(ar.results).map(([k, v]) => (
                <KV key={k} label={k} mono>
                  {v}
                </KV>
              ))}
              <div className="mt-2 text-[12px]" style={{ color: "var(--color-ink-4)" }}>
                params: {ar.params.join(" · ")}
              </div>
              <div className="text-[12px]" style={{ color: "var(--color-ink-4)" }}>
                sender IPs: {ar.sender_ips.join(", ")}
              </div>
              <div className="text-[12px]" style={{ color: "var(--color-ink-4)" }}>
                SPF mailfrom: {ar.spf_mailfrom_domain}
              </div>
            </DetailCard>
          ))}

          {/* :1206 — Received-SPF */}
          {P.receivedSpf.length > 0 && (
            <DetailCard title={`Received-SPF (${P.receivedSpf.length})`} emoji="🛡️">
              {P.receivedSpf.map((r, i) => (
                <KV key={i} label={`#${i + 1}`} mono>
                  {`result=${r.result}, client_ip=${r.client_ip}, envelope_from=${r.envelope_from}${r.helo ? `, helo=${r.helo}` : ""}`}
                </KV>
              ))}
            </DetailCard>
          )}

          {/* :1215 — DKIM Signatures */}
          {P.dkimSignatures.length > 0 && (
            <DetailCard title={`DKIM Signatures (${P.dkimSignatures.length})`} emoji="✍️">
              {P.dkimSignatures.map((s, i) => (
                <KV key={i} label={`#${i + 1}`} mono>
                  {`domain=${s.domain}, selector=${s.selector}, algorithm=${s.algorithm}, c=${s.canonicalization}, signed_headers=${s.signed_headers.slice(0, 10).join(", ")}`}
                </KV>
              ))}
            </DetailCard>
          )}

          {/* :1226 — Microsoft Security Headers */}
          <DetailCard title="Microsoft Security Headers" emoji="🛡️">
            <KV label="Authentication-Results" mono copyable>
              spf=fail (45.132.192.14); dkim=fail (0 body hash); dmarc=fail
              header.from=collaborate-youtube[.]com
            </KV>
            <KV label="Received-SPF" mono copyable>
              fail (domain of collaborate-youtube[.]com does not designate 45.132.192.14)
            </KV>
          </DetailCard>

          {/* :1243 renderHopFlow — the received path */}
          <DetailCard title="Received Path" emoji="🌲">
            <div className="flex flex-col">
              {P.hops.map((h, i) => (
                <div key={i} className="flex gap-3">
                  <div className="flex flex-col items-center shrink-0">
                    <span
                      className="w-2.5 h-2.5 rounded-full mt-1.5"
                      style={{
                        background: h.is_internal_hop
                          ? "var(--color-ink-4)"
                          : "var(--tool-accent)",
                      }}
                    />
                    {i < P.hops.length - 1 && (
                      <span
                        className="flex-1 w-px my-1"
                        style={{ background: "var(--color-line)" }}
                      />
                    )}
                  </div>
                  <div className="pb-4 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span
                        className="text-[11px] mono"
                        style={{ color: "var(--color-ink-4)" }}
                      >
                        #{h.hop ?? i + 1}
                      </span>
                      <span className="text-[13px] font-semibold">{h.from}</span>
                      {h.id && (
                        <span className="mono text-[11px]" style={{ color: "var(--color-ink-4)" }}>
                          [{h.id}]
                        </span>
                      )}
                    </div>
                    <div
                      className="text-[11.5px] mt-1 flex items-center gap-1.5 flex-wrap"
                      style={{ color: "var(--color-ink-4)" }}
                    >
                      <span>by {h.by}</span>
                      <span>· with {h.with}</span>
                      {h.protocol && <span>· {h.protocol}</span>}
                      {h.cipher && <span>· cipher: {h.cipher}</span>}
                      {h["for"] && <span>· for: {h["for"]}</span>}
                      {h.tls_version && <HopBadge>{`TLS: ${h.tls_version}`}</HopBadge>}
                      {h.delay_seconds != null && (
                        <HopBadge tone="warn">{`${h.delay_seconds}s`}</HopBadge>
                      )}
                      {h.is_internal_hop && (
                        <HopBadge dim>internal</HopBadge>
                      )}
                      {h.ips.length > 0 && (
                        <span className="flex gap-1">
                          {h.ips.map((ip) => (
                            <span
                              key={ip}
                              className="mono text-[10px] px-1 rounded-[3px]"
                              style={{
                                background: "var(--color-surface-3)",
                                color: "var(--color-ink-2)",
                              }}
                            >
                              {ip}
                            </span>
                          ))}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </DetailCard>
        </CardBody>
      </Card>

      <DomainReputation />
    </div>
  );
}

function HopBadge({
  children,
  tone = "info",
  dim,
}: {
  children: React.ReactNode;
  tone?: "info" | "warn";
  dim?: boolean;
}) {
  const tones = {
    info: { bg: "rgb(56 189 248 / 0.14)", fg: "var(--color-info)" },
    warn: { bg: "rgb(251 191 36 / 0.14)", fg: "var(--color-warn)" },
  };
  const t = tones[tone];
  return (
    <span
      className="text-[10px] font-semibold px-1.5 py-0.5 rounded-[4px]"
      style={{
        background: t.bg,
        color: t.fg,
        opacity: dim ? 0.6 : 1,
      }}
    >
      {children}
    </span>
  );
}

function DetailCard({
  title,
  emoji,
  children,
}: {
  title: string;
  emoji: string;
  children: React.ReactNode;
}) {
  return (
    <div
      className="p-3.5 rounded-[var(--radius-md)]"
      style={{ background: "var(--color-surface-2)", border: "1px solid var(--color-line)" }}
    >
      <h3 className="text-[13px] font-bold mb-2 flex items-center gap-2">
        <span aria-hidden>{emoji}</span>
        {title}
      </h3>
      {children}
    </div>
  );
}

function DomainReputation() {
  const items = [
    { label: "Domain age", value: "9 days", tone: "bad" as const },
    { label: "MX records", value: "3 found", tone: "ok" as const },
    { label: "Reputation", value: "poor", tone: "bad" as const },
    { label: "First seen", value: "2026-09-19", tone: "warn" as const },
  ];
  return (
    <Card>
      <CardHead title="Domain Reputation" icon="globe" />
      <CardBody>
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {items.map((i) => (
            <div
              key={i.label}
              className="p-3 rounded-[var(--radius-md)]"
              style={{ background: "var(--color-surface-2)", border: "1px solid var(--color-line)" }}
            >
              <div
                className="text-[11px] font-bold uppercase tracking-[0.06em]"
                style={{ color: "var(--color-ink-4)" }}
              >
                {i.label}
              </div>
              <div
                className="text-[15px] font-bold mt-1"
                style={{
                  color:
                    i.tone === "bad"
                      ? "var(--color-bad)"
                      : i.tone === "warn"
                        ? "var(--color-warn)"
                        : "var(--color-ok)",
                }}
              >
                {i.value}
              </div>
            </div>
          ))}
        </div>
      </CardBody>
    </Card>
  );
}

/* =============================================================
   ARTIFACTS
   ============================================================= */

/** Defang a URL so it cannot be clicked by accident.
 *
 *  Only the HOST is defanged, and the host:port colon is bracketed. An
 *  earlier version rewrote every dot in the string and turned `:8080` into
 *  `[ :]8080`, which mangled the path and the query into noise:
 *  `https://accounts[.]google[.]com/...?redirect_uri=http://185[.]220[.]101[.]44`
 *  is unreadable, and an analyst cannot check a destination they cannot
 *  read. Bracketing the host alone is the standard and keeps the rest
 *  legible. */
function defang(url: string): string {
  return url.replace(/^(https?:\/\/)([^/?#:]+)/i, (_m, scheme: string, host: string) => {
    const bracketed = host.replace(/\./g, "[.]");
    const port = url.slice(scheme.length + host.length).match(/^(:\d+)/)?.[1];
    return `${scheme}${bracketed}${port ? `[${port}]` : ""}`;
  });
}

export function ArtifactsPanel({ navigate }: { navigate: (to: string) => void }) {
  const [openUrl, setOpenUrl] = useState<number | null>(null);
  const [iocQ, setIocQ] = useState("");

  const iocGroups = P.observables.map((g) => ({
    ...g,
    values: g.values.filter(
      (v) => !iocQ || v.value.toLowerCase().includes(iocQ.toLowerCase()),
    ),
  }));


  return (
    <div className="flex flex-col gap-4">
      {/* :997 — URLs Detected, expandable url cards */}
      <Card>
        <CardHead title="URLs Detected" icon="link" count={P.links.length} />
        <CardBody className="flex flex-col gap-2.5">
          {P.links.map((u, i) => {
            const isOpen = openUrl === i;
            return (
              <div
                key={i}
                className="rounded-[var(--radius-md)] overflow-hidden"
                style={{ border: "1px solid var(--color-line)", background: "var(--color-surface-2)" }}
              >
                <button
                  onClick={() => setOpenUrl(isOpen ? null : i)}
                  className="w-full flex items-center gap-3 px-3.5 py-3 text-left"
                >
                  <span
                    className="mono text-[12.5px] font-semibold truncate flex-1"
                    style={{ color: "var(--color-ink-2)" }}
                  >
                    {defang(u.url)}
                  </span>
                  {u.kind === "malicious" && <Badge tone="bad">malicious</Badge>}
                  {u.kind === "suspicious" && <Badge tone="warn">suspicious</Badge>}
                  <Icon
                    name="chevron-right"
                    size={14}
                    style={{
                      color: "var(--color-ink-4)",
                      transform: isOpen ? "rotate(90deg)" : undefined,
                      transition: "transform 150ms",
                    }}
                  />
                </button>
                {isOpen && (
                  <div
                    className="px-3.5 pb-3.5 pt-1 border-t"
                    style={{ borderColor: "var(--color-line)" }}
                  >
                    <KV label="Defanged" mono copyable>{defang(u.url)}</KV>
                    <KV label="Displayed URL">{u.text || "N/A"}</KV>
                    <KV label="Deceptive">
                      {u.kind === "malicious"
                        ? "Yes — matches display text but a different destination"
                        : "No"}
                    </KV>
                    <KV label="Anchor text">{u.text || "—"}</KV>
                    <KV label="Finding">{u.target}</KV>
                  </div>
                )}
              </div>
            );
          })}
        </CardBody>
      </Card>

      {/* :998 renderUrlscanSection */}
      <Card>
        <CardHead
          title="urlscan.io"
          icon="globe"
          action={
            <Badge tone="bad">
              {P.urlscan.malicious ? "malicious" : "clean"} · score {P.urlscan.score}
            </Badge>
          }
        />
        <CardBody>
          <KV label="Scan" mono copyable>{P.urlscan.scan_id}</KV>
          {P.urlscan.categories.map((c) => (
            <div key={c} className="py-1.5 flex items-center gap-2">
              <span className="text-[12.5px] w-28 shrink-0" style={{ color: "var(--color-ink-4)" }}>
                Categories
              </span>
              <Badge key={c} tone="bad">{c}</Badge>
            </div>
          ))}
          <div className="py-1.5 flex items-center gap-2">
            <span className="text-[12.5px] w-28 shrink-0" style={{ color: "var(--color-ink-4)" }}>
              Brands
            </span>
            {P.urlscan.brands.map((b) => (
              <Badge key={b} tone="warn">{b}</Badge>
            ))}
          </div>
        </CardBody>
      </Card>

      {/* :1000 — Attachments */}
      <Card>
        <CardHead title="Attachments" icon="file" count={P.attachments.length} />
        <CardBody className="flex flex-col gap-2.5">
          {P.attachments.map((a) => {
            const bad = a.verdict === "malicious";
            return (
              <div
                key={a.name}
                className="p-3.5 rounded-[var(--radius-md)]"
                style={{
                  background: "var(--color-surface-2)",
                  border: "1px solid var(--color-line)",
                  borderLeft: `3px solid ${bad ? "var(--color-bad)" : "var(--color-ok)"}`,
                }}
              >
                <div className="flex items-center gap-2.5 mb-1.5">
                  <Icon name="file" size={14} style={{ color: bad ? "var(--color-bad)" : "var(--color-ink-3)" }} />
                  <span className="mono text-[12.5px] font-bold flex-1 truncate">
                    {a.name}
                  </span>
                  <Badge tone={bad ? "bad" : "ok"}>{a.verdict}</Badge>
                </div>
                <div className="text-[11.5px] mono" style={{ color: "var(--color-ink-4)" }}>
                  {a.type}
                </div>
                <div className="text-[12.5px] mt-1.5">{a.detail}</div>
              </div>
            );
          })}
          <Button
            variant="subtle"
            size="sm"
            icon="bug"
            className="self-start"
            onClick={() => navigate("/t/malware")}
          >
            Scan these attachments with Malware Analyzer
          </Button>
        </CardBody>
      </Card>

      {/* :1001 — Email Content Analysis */}
      <Card>
        <CardHead title="Email Content Analysis" icon="eye" />
        <CardBody className="flex flex-col gap-2.5">
          {[
            { label: "Forms", value: P.artefacts.forms, bad: true as boolean | null },
            { label: "Hidden iframes", value: P.artefacts.iframes, bad: true as boolean | null },
            { label: "Inline scripts", value: P.artefacts.scripts, bad: true as boolean | null },
            { label: "External resources", value: P.artefacts.externalResources, bad: null },
            { label: "Redirects", value: P.artefacts.redirects, bad: true as boolean | null },
          ].map((s) => (
            <div key={s.label} className="flex items-center gap-3">
              <span className="text-[12.5px] w-32 shrink-0" style={{ color: "var(--color-ink-3)" }}>
                {s.label}
              </span>
              <span
                className="mono text-[13px] font-bold"
                style={{ color: s.bad && s.value > 0 ? "var(--color-bad)" : "var(--color-ink-2)" }}
              >
                {s.value}
              </span>
              <span
                className="flex-1 h-1.5 rounded-full"
                style={{ background: "var(--color-surface-4)" }}
              >
                <span
                  className="block h-full rounded-full"
                  style={{
                    width: `${Math.min(100, (s.value / 12) * 100)}%`,
                    background:
                      s.bad === null
                        ? "var(--color-info)"
                        : s.bad && s.value > 0
                          ? "var(--color-bad)"
                          : "var(--color-ok)",
                  }}
                />
              </span>
            </div>
          ))}
          <Callout tone="warn" title="Obfuscation">
            {P.artefacts.obfuscation}. Entity encoding is not malicious on its
            own, and plenty of legitimate mail uses it. It is flagged here
            because it is combined with every other indicator on this message.
          </Callout>
        </CardBody>
      </Card>

      {/* :1002 — Technical Observables with a search box */}
      <Card>
        <CardHead
          title="Technical Observables (IOCs)"
          icon="target"
          count={P.observables.reduce((a, g) => a + g.values.length, 0)}
          action={
            <div className="w-[220px]">
              <input
                value={iocQ}
                onChange={(e) => setIocQ(e.target.value)}
                placeholder="Search indicators…"
                className="w-full h-8 px-2.5 rounded-[var(--radius-sm)] text-[12.5px] bg-[var(--color-surface-2)] border border-[var(--color-line-2)] focus:outline-none focus:border-[var(--tool-accent)]"
              />
            </div>
          }
        />
        <CardBody className="flex flex-col gap-4">
          {iocGroups.map((g) =>
            g.values.length === 0 ? null : (
              <div key={g.type}>
                <div className="flex items-center gap-2 mb-2">
                  <span
                    className="text-[11px] font-bold uppercase tracking-[0.06em]"
                    style={{ color: "var(--color-ink-4)" }}
                  >
                    {g.label}
                  </span>
                  <Badge>{g.values.length}</Badge>
                </div>
                <div className="flex flex-col gap-1.5">
                  {g.values.map((v) => (
                    <div
                      key={v.value}
                      className="flex items-center gap-2.5 px-2.5 py-2 rounded-[var(--radius-sm)] cursor-pointer hover:bg-[var(--color-surface-3)] transition-colors"
                      style={{ background: "var(--color-surface-2)" }}
                      onClick={async () => {
                        if (await copyText(v.value)) toast(`Copied ${truncate(v.value, 40)}`);
                      }}
                      title="Click to copy"
                    >
                      <span
                        className="mono text-[10px] px-1.5 py-0.5 rounded-[4px] shrink-0"
                        style={{ background: "var(--tool-tint)", color: "var(--tool-accent)" }}
                      >
                        {g.type}
                      </span>
                      <span className="mono text-[12px] truncate flex-1">{v.value}</span>
                      <Badge>{v.source}</Badge>
                      <span
                        className="mono text-[11px] font-bold shrink-0"
                        style={{ color: v.count > 1 ? "var(--color-warn)" : "var(--color-ink-4)" }}
                      >
                        {v.count}
                      </span>
                      <Icon name="copy" size={12} style={{ color: "var(--color-ink-4)" }} />
                    </div>
                  ))}
                </div>
              </div>
            ),
          )}
        </CardBody>
      </Card>

      {/* :1002 — QR codes */}
      <Card>
        <CardHead title="QR codes" icon="grid" count={P.artefacts.qrCodes.length} />
        <CardBody className="flex flex-col gap-2.5">
          {P.artefacts.qrCodes.map((q, i) => (
            <div
              key={i}
              className="p-3.5 rounded-[var(--radius-md)]"
              style={{
                background: "rgb(248 113 113 / 0.06)",
                border: "1px solid rgb(248 113 113 / 0.25)",
              }}
            >
              <Badge tone="bad" className="mb-2">decoded</Badge>
              <div className="mono text-[12.5px] break-all">{q.decoded}</div>
              <div className="text-[11.5px] mt-1.5" style={{ color: "var(--color-ink-4)" }}>
                {q.location}
              </div>
            </div>
          ))}
        </CardBody>
      </Card>

      {/* :970 — MITRE ATT&CK */}
      <Card>
        <CardHead title="MITRE ATT&CK" icon="sparkles" count={P.mitre.length} />
        <CardBody className="flex flex-col gap-2.5">
          {P.mitre.map((m) => (
            <div key={m.id} className="flex items-center gap-3">
              <span
                className="mono text-[11.5px] font-bold px-1.5 py-0.5 rounded-[4px] shrink-0"
                style={{ background: "rgb(168 85 247 / 0.12)", color: "var(--color-magic)" }}
              >
                {m.id}
              </span>
              <span className="text-[13px] font-semibold min-w-0 flex-1 truncate">
                {m.name}
              </span>
              <span className="text-[11.5px]" style={{ color: "var(--color-ink-4)" }}>
                {m.tactic}
              </span>
            </div>
          ))}
        </CardBody>
      </Card>

      {/* :975 — Recommendations with priority chips */}
      <Card>
        <CardHead title="Recommendations" icon="shield" count={P.recommendations.length} />
        <CardBody className="grid sm:grid-cols-2 gap-3">
          {P.recommendations.map((r, i) => (
            <div
              key={i}
              className="p-3.5 rounded-[var(--radius-md)]"
              style={{ background: "var(--color-surface-2)", border: "1px solid var(--color-line)" }}
            >
              <Badge tone={i === 0 ? "bad" : "warn"} className="mb-2">
                {i === 0 ? "high" : "medium"}
              </Badge>
              <div className="text-[13px]">{r}</div>
            </div>
          ))}
        </CardBody>
      </Card>
    </div>
  );
}
