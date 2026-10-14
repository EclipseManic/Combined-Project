import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Icon } from "../../lib/icons";
import { Card, CardHead, CardBody, Button, Badge, VerdictBadge, ScoreRing, ProgressBar, StatTile, Table, Th, Td, KV, CodeBlock, DropZone, Modal, Toggle, Callout, Input } from "../../ui";
import { PHISHING_REPORT, PHISHING_HISTORY } from "../../data/fixtures";
import { verdictForScore, VERDICT_STYLE } from "../../lib/tools";
import { formatBytes, relativeTime } from "../../lib/utils";
import { toast } from "../../shell/chrome";
import { useShell } from "../../lib/shell-context";
import { ToolLanding, NextStepNote } from "./ToolLanding";
import { SenderAuth, ArtifactsPanel } from "./PhishingPanels";


export function PhishingPage({ navigate }: { navigate: (to: string) => void }) {
  const { mainTab, setMainTab, subTab, setSubTab, actionsSlot } = useShell();
  /* `has` starts FALSE. It used to start true, which meant the message was
     already loaded on arrival — and since the overview page is only rendered
     when there is no message, Phishing Detector had no home page at all. The
     tool opened straight into a report for a message you had never chosen. */
  /* index.html persists the scan list and the active selection, so a reload
     lands you back on the message you were triaging rather than on an empty
     prompt. Modelled here with the same history the Dashboard uses. */
  const [has, setHas] = useState(() => {
    try {
      return sessionStorage.getItem("secconflux.activeMessage") === "1";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    try {
      if (has) sessionStorage.setItem("secconflux.activeMessage", "1");
      else sessionStorage.removeItem("secconflux.activeMessage");
    } catch {
      /* non-fatal */
    }
  }, [has]);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState("");
  const [resolve, setResolve] = useState(true);
  const [enrich, setEnrich] = useState(true);
  const [switcher, setSwitcher] = useState(false);
  const timers = useRef<number[]>([]);

  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  function runScan(name: string) {
    const label = name;
    setRunning(true);
    setHas(false);
    setProgress(0);
    const stages = PHISHING_REPORT.stages;
    timers.current.forEach(clearTimeout);
    timers.current = [];
    stages.forEach((s, i) => {
      timers.current.push(
        window.setTimeout(() => {
          setStage(s);
          setProgress(Math.round(((i + 1) / stages.length) * 100));
        }, i * 320),
      );
    });
    timers.current.push(
      window.setTimeout(() => {
        setRunning(false);
        setHas(true);
        setSubTab("overview");
        toast(`Triage complete · ${label} · ${PHISHING_REPORT.score}/100`, "bad");
      }, stages.length * 320 + 400),
    );
  }

  const verdict = verdictForScore(PHISHING_REPORT.score);

  const headerAction = actionsSlot
    ? createPortal(
        <>
          <div className="relative">
            <Button variant="secondary" size="sm" icon="clock" onClick={() => setSwitcher((v) => !v)}>
              {PHISHING_HISTORY.length} past scans
              <Icon name="chevron-down" size={12} />
            </Button>
            {switcher && (
              <>
                <div className="fixed inset-0 z-[140]" onClick={() => setSwitcher(false)} aria-hidden />
                <div
                  className="sc-anim-pop absolute right-0 top-[calc(100%+8px)] z-[150] w-[320px] p-1.5"
                  style={{
                    background: "var(--color-surface)",
                    border: "1px solid var(--color-line-2)",
                    borderRadius: "var(--radius-lg)",
                    boxShadow: "var(--shadow-lg)",
                  }}
                >
                {PHISHING_HISTORY.map((h) => {
                  const v = verdictForScore(h.score);
                  return (
                    <button
                      key={h.id}
                      onClick={() => {
                        setSwitcher(false);
                        setHas(true);
                        setSubTab("overview");
                        toast(`Loaded ${h.filename}`);
                      }}
                      className="w-full flex items-center gap-2.5 px-2.5 py-2 rounded-[var(--radius-sm)] text-left hover:bg-[var(--color-surface-3)]"
                    >
                      <span
                        className="w-1.5 h-1.5 rounded-full shrink-0"
                        style={{
                          background:
                            v === "malicious" ? "var(--color-bad)" : v === "suspicious" ? "var(--color-warn)" : "var(--color-ok)",
                        }}
                      />
                      <span className="min-w-0 flex-1">
                        <span className="block text-[12.5px] font-semibold truncate">{h.filename}</span>
                        <span className="block text-[11px]" style={{ color: "var(--color-ink-4)" }}>
                          {h.verdict} · {relativeTime(h.timestamp)}
                        </span>
                      </span>
                      <span className="mono text-[12px] font-bold">{h.score}</span>
                    </button>
                  );
                })}
              </div>
            </>
          )}
          </div>

          <Button
            variant="primary"
            size="sm"
            icon="plus"
            onClick={() => setUploadOpen(true)}
          >
            New Analysis
          </Button>
        </>,
        actionsSlot,
      )
    : null;

  return (
    <div className="sc-anim-in">
      {headerAction}

      <div className="max-w-[1400px] mx-auto px-5 py-6">
        {running && (
          <Card glow className="p-5 mb-5">
            <div className="flex items-center gap-4 mb-4">
              <span
                className="grid place-items-center w-11 h-11 rounded-[var(--radius-md)]"
                style={{ background: "var(--tool-tint)", color: "var(--tool-accent)" }}
              >
                <span
                  className="w-5 h-5 rounded-full border-2 border-current border-t-transparent"
                  style={{ animation: "sc-spin 0.7s linear infinite" }}
                />
              </span>
              <div className="flex-1 min-w-0">
                <div className="text-[15px] font-bold">Triaging message</div>
                <div className="text-[12.5px]" style={{ color: "var(--color-ink-4)" }}>
                  {stage}
                </div>
              </div>
              <span className="text-[22px] font-black tabular-nums" style={{ color: "var(--tool-accent)" }}>
                {progress}%
              </span>
            </div>
            <ProgressBar value={progress} striped height={7} />
            <div className="flex flex-wrap gap-1.5 mt-4">
              {PHISHING_REPORT.stages.map((s) => {
                const idx = PHISHING_REPORT.stages.indexOf(s);
                const done = progress >= ((idx + 1) / PHISHING_REPORT.stages.length) * 100;
                const active = stage === s;
                return (
                  <span
                    key={s}
                    className="px-1.5 py-0.5 rounded-[4px] text-[10.5px] font-semibold border"
                    style={{
                      background: active ? "var(--tool-tint)" : done ? "var(--color-surface-2)" : "transparent",
                      borderColor: active ? "var(--tool-tint-2)" : done ? "var(--color-line)" : "transparent",
                      color: active ? "var(--tool-accent)" : done ? "var(--color-ink-3)" : "var(--color-ink-4)",
                      opacity: done || active ? 1 : 0.45,
                    }}
                  >
                    {s}
                  </span>
                );
              })}
            </div>
          </Card>
        )}

        {mainTab === "overview" && (
              <ToolLanding
                toolId="phishing"
                copy={{
                  eyebrow: "Phishing & Email Forensics",
                  headline: ["Detect phishing before anyone", "acts on it."],
                  subtext:
                    "Upload any .eml file and get a full forensic breakdown — sender authentication, header anomalies, URL inspection, attachment hashing, VirusTotal enrichment, and technical IOC extraction — all in one structured dashboard.",
                  primaryCta: "Upload & Analyze",
                  onPrimary: () => setUploadOpen(true),
                  secondaryCta: "Past Scans",
                  onSecondary: () => {
                    setHas(true);
                    setSubTab("dashboard");
                    setMainTab("analysis");
                  },
                  terminal: {
                    file: "suspicious_invoice_2025.eml",
                    body: "rows",
                    rows: [
                      { label: "Phishing Score: 10 / 10", value: "UNSAFE", tone: "bad" },
                      { label: "Reply-To mismatch", value: "[!!!] DETECTED", tone: "bad" },
                      { label: "SPF / DKIM / DMARC", value: "[OK] ALL PASS", tone: "ok" },
                      { label: "Attachment VT scan", value: "1 of 76 flagged", tone: "bad" },
                      { label: "Urgency language", value: "[!] DETECTED", tone: "warn" },
                      { label: "Domain age", value: "10,111 days", tone: "ok" },
                      { label: "IOCs extracted", value: "7 observables", tone: "ok" },
                    ],
                  },
                  stats: [
                    { value: "5", label: "Auth checks" },
                    { value: "50+", label: "URL platforms" },
                    { value: "76", label: "VT engines" },
                    { value: "4", label: "Keyword classes" },
                  ],
                  sectionEyebrow: "What it analyzes",
                  sectionTitle: "Every layer of the email — fully exposed",
                  sectionBody:
                    "The platform parses every technical layer, cross-references against VirusTotal and urlscan.io, extracts all IOCs, maps findings to MITRE ATT&CK, and explains every finding in plain language. All capabilities are verified through unit and integration tests.",
                  features: [
                    {
                      title: "Authentication & header forensics",
                      body: "Validates SPF, DKIM, DMARC and ARC with alignment checks. Detects Reply-To, Return-Path and Sender mismatches, display-name spoofing, homograph and punycode attacks, and traces the full received-hop chain with TLS and timing details.",
                      tags: ["SPF", "DKIM", "DMARC", "ARC", "Alignment", "Hop Path", "Mismatch", "Homograph"],
                      tagTone: "ok",
                    },
                    {
                      title: "URL inspection",
                      body: "Extracts, defangs and analyses every URL from the HTML and text bodies. Checks host reputation, deception indicators, shortener bypass, redirect chains, tracking pixels, JWT extraction, AMP redirects, and legitimate-service abuse across fifty-plus platforms.",
                      tags: ["Defanged", "Redirect chain", "Shortener", "JWT", "AMP", "Tracking pixel", "urlscan.io", "VirusTotal"],
                      tagTone: "info",
                    },
                    {
                      title: "Attachment analysis",
                      body: "Detects true file types by magic bytes rather than by extension, computes SHA-256, SHA-1 and MD5, scans for embedded URLs, macros, JavaScript and OLE objects, and parses PDF, OOXML and OLE structures.",
                      tags: ["magic bytes", "SHA-256", "macros", "OLE", "PDF"],
                      tagTone: "neutral",
                    },
                    {
                      title: "Email content & preview",
                      body: "Renders HTML, plain text and raw views side by side. Detects forms, iframes, hidden elements, password fields and meta-refresh redirects, and finds phishing keywords across financial, credential, urgency and social-engineering categories.",
                      tags: ["HTML render", "iframes", "hidden elements", "meta refresh"],
                      tagTone: "neutral",
                    },
                    {
                      title: "QR code extraction",
                      body: "Decodes QR codes embedded in images, including the invisible one-pixel trackers used to smuggle a destination past a link scanner and into a phone camera.",
                      tags: ["QR", "tracking pixels", "image decode"],
                      tagTone: "warn",
                    },
                    {
                      title: "Verdict with reasoning",
                      body: "Every score is broken into the specific findings that produced it, so the number can be argued with rather than accepted on trust, and mapped to MITRE ATT&CK for the write-up.",
                      tags: ["scoring", "ATT&CK", "plain language"],
                      tagTone: "info",
                    },
                  ],
                  workflow: {
                    eyebrow: "How To Use It",
                    layout: "cards",
                    title: "Four steps from email sample to filed report",
                    steps: [
                      { num: "01", title: "Export the email", body: "Save the suspicious message as an .eml file from the mail client or helpdesk case." },
                      { num: "02", title: "Upload & configure", body: "Drag-and-drop the file. Enable external enrichment or redirect resolution if needed." },
                      { num: "03", title: "Review all evidence", body: "Inspect the verdict, authentication state, URL analysis, attachments, IOCs, and received path." },
                      { num: "04", title: "Export the report", body: "Download the full JSON report for documentation, SIEM ingestion, or leadership briefings." },
                    ],
                  },
                  after: (
                    <div className="mt-14">
                      <NextStepNote
                        toolId="phishing"
                        links={[
                          { to: "malware", text: "attachment hashes, checked against the malware corpus" },
                          { to: "ioc", text: "sender domains and link hosts, resolved" },
                        ]}
                      />
                    </div>
                  ),
}}
              />
        )}

        {has && !running && mainTab === "analysis" && (
          <div className="sc-anim-in flex flex-col gap-5">
            {subTab === "dashboard" && <Overview navigate={navigate} verdict={verdict} />}
            {subTab === "sender-auth" && <SenderAuth />}
            {subTab === "preview" && <Preview />}
            {subTab === "artifacts" && <ArtifactsPanel navigate={navigate} />}
          </div>
        )}

        {/* Analysis with no message loaded. The overview page carries the
            primary call to action, so this only has to offer a way in. */}
        {!has && !running && mainTab === "analysis" && (
          <Card>
            <CardHead
              title="Messages"
              icon="mail"
              count={PHISHING_HISTORY.length}
              subtitle="Open a previous triage, or analyse a new message"
              action={
                <Button
                  variant="primary"
                  size="xs"
                  icon="plus"
                  onClick={() => setUploadOpen(true)}
                >
                  New analysis
                </Button>
              }
            />
            <CardBody className="p-2 flex flex-col gap-1">
              {PHISHING_HISTORY.map((h) => {
                const v = verdictForScore(h.score);
                return (
                  <button
                    key={h.id}
                    onClick={() => {
                      setHas(true);
                      setSubTab("summary");
                    }}
                    className="flex items-center gap-3 px-3 py-3 rounded-[var(--radius-md)] text-left hover:bg-[var(--color-surface-3)] transition-colors"
                  >
                    <span
                      className="w-2 h-2 rounded-full shrink-0"
                      style={{ background: VERDICT_STYLE[v].color }}
                    />
                    <span className="min-w-0 flex-1">
                      <span className="block text-[13.5px] font-semibold truncate">
                        {h.filename}
                      </span>
                      <span
                        className="block text-[11.5px]"
                        style={{ color: "var(--color-ink-4)" }}
                      >
                        {h.verdict} · {relativeTime(h.timestamp)}
                      </span>
                    </span>
                    <span
                      className="mono text-[13px] font-bold shrink-0"
                      style={{ color: VERDICT_STYLE[v].color }}
                    >
                      {h.score}
                    </span>
                    <Icon name="chevron-right" size={14} style={{ color: "var(--color-ink-4)" }} />
                  </button>
                );
              })}
            </CardBody>
          </Card>
        )}
      </div>

      <Modal
        open={uploadOpen}
        onClose={() => setUploadOpen(false)}
        title="New Email Analysis"
        subtitle="Upload a raw .eml file. Nothing is sent anywhere."
        width={600}
        footer={
          <>
            <Button variant="ghost" onClick={() => setUploadOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={() => {
                setUploadOpen(false);
                runScan("RE_Collab_for_Your_YT_Channel.eml");
              }}
            >
              Analyze message
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <DropZone
            icon="mail"
            title="Drop an .eml file here or click to browse"
            hint="RFC 822 message files. Export from your mail client with 'Save as EML'."
            accept=".eml,message/rfc822"
            onFile={(f) => {
              setUploadOpen(false);
              runScan(f.name);
            }}
          />
          <div
            className="flex flex-col gap-2.5 p-3.5 rounded-[var(--radius-md)]"
            style={{ background: "var(--color-surface-2)", border: "1px solid var(--color-line)" }}
          >
            <Toggle
              id="resolve-redirects"
              checked={resolve}
              onChange={setResolve}
              label="Resolve shortened links"
              hint="Follow URL shorteners to their real destination before scoring them"
            />
            <div className="h-px" style={{ background: "var(--color-line)" }} />
            <Toggle
              id="external-enrichment"
              checked={enrich}
              onChange={setEnrich}
              label="External enrichment"
              hint="VirusTotal reputation on URLs and attachment hashes"
            />
          </div>
        </div>
      </Modal>
    </div>
  );
}

/* =============================================================
   OVERVIEW
   ============================================================= */

function Overview({ navigate, verdict }: { navigate: (to: string) => void; verdict: ReturnType<typeof verdictForScore> }) {
  const r = PHISHING_REPORT;
  return (
    <div className="flex flex-col gap-5">
      <Card glow className="overflow-hidden">
        <div className="flex flex-col lg:flex-row gap-6 p-5">
          <div className="flex items-start gap-5 min-w-0 flex-1">
            <ScoreRing score={r.score} label={r.severity.toUpperCase()} sublabel="PHISH" />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2.5 flex-wrap mb-2">
                <VerdictBadge verdict={verdict} />
                <Badge tone="bad">SPF fail</Badge>
                <Badge tone="bad">DKIM fail</Badge>
                <Badge tone="bad">DMARC fail</Badge>
              </div>
              <h1 className="text-[19px] font-extrabold tracking-[-0.01em] leading-snug">
                {r.subject}
              </h1>
              <div className="mt-2.5 text-[12.5px] flex flex-col gap-1">
                <div className="flex items-start gap-2">
                  <span className="text-[var(--color-ink-4)] w-16 shrink-0">From</span>
                  <span className="font-mono text-[var(--color-ink-2)] break-all">{r.from}</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="text-[var(--color-ink-4)] w-16 shrink-0">Reply-To</span>
                  <span className="font-mono break-all" style={{ color: "var(--color-bad)" }}>
                    {r.replyTo}
                  </span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="text-[var(--color-ink-4)] w-16 shrink-0">To</span>
                  <span className="font-mono text-[var(--color-ink-2)]">{r.to}</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="text-[var(--color-ink-4)] w-16 shrink-0">Date</span>
                  <span className="font-mono text-[var(--color-ink-3)]">{r.date}</span>
                </div>
              </div>
              <div className="flex flex-wrap gap-1.5 mt-3.5">
                {r.mitre.map((m) => (
                  <Badge key={m.id} tone="info" mono>
                    {m.id} {m.name}
                  </Badge>
                ))}
              </div>
            </div>
          </div>
          <div className="flex lg:flex-col gap-2 shrink-0">
            <Button variant="secondary" size="sm" icon="download" onClick={() => toast("Report exported as JSON", "ok")}>
              Export report
            </Button>
            <Button variant="secondary" size="sm" icon="eye" onClick={() => toast("Opened in safe render", "info")}>
              Safe render
            </Button>
            <Button variant="subtle" size="sm" icon="target" onClick={() => navigate("/t/ioc")}>
              Enrich sender
            </Button>
          </div>
        </div>

        <div
          className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 border-t"
          style={{ borderColor: "var(--color-line)", background: "var(--color-surface-2)" }}
        >
          {r.indicators.slice(0, 6).map((i) => (
            <div key={i.label} className="px-4 py-3.5 border-r last:border-r-0" style={{ borderColor: "var(--color-line)" }}>
              <div className="text-[10.5px] font-bold tracking-[0.05em] uppercase text-[var(--color-ink-4)]">
                {i.label}
              </div>
              <div
                className="text-[14px] font-bold mt-1"
                style={{
                  color:
                    i.tone === "bad" ? "var(--color-bad)" : i.tone === "warn" ? "var(--color-warn)" : "var(--color-ink-2)",
                }}
              >
                {i.value}
              </div>
            </div>
          ))}
        </div>
      </Card>

      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatTile label="Attachments" value={r.attachments.length} icon="file" tone="bad" sub={`${r.attachments.filter((a) => a.verdict === "malicious").length} malicious`} />
        <StatTile label="Links" value={r.links.length} icon="link" tone="warn" sub={`${r.links.filter((l) => l.kind !== "benign").length} suspicious`} />
        <StatTile label="QR codes" value={r.artefacts.qrCodes.length} icon="grid" tone="bad" sub="Decoded from images" />
        <StatTile label="Sender domain age" value="9 days" icon="clock" tone="bad" />
      </div>

      <div className="grid lg:grid-cols-2 gap-5">
        <Card>
          <CardHead title="Why this scored what it scored" icon="activity" count={r.feedback.length} />
          <CardBody className="flex flex-col gap-2.5">
            {r.feedback.map((f) => (
              <div key={f.id} className="flex gap-3">
                <span
                  className="shrink-0 mono text-[12px] font-black w-11 text-right pt-0.5"
                  style={{ color: "var(--color-bad)" }}
                >
                  +{f.weight}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-[12.5px] leading-relaxed" style={{ color: "var(--color-ink-2)" }}>
                    {f.text}
                  </p>
                  <ProgressBar value={(f.weight / 24) * 100} height={3} color="var(--color-bad)" />
                </div>
              </div>
            ))}
            <div
              className="flex items-center justify-between pt-3 mt-1 border-t"
              style={{ borderColor: "var(--color-line)" }}
            >
              <span className="text-[13px] font-bold">Total score</span>
              <span className="text-[24px] font-black" style={{ color: "var(--color-bad)" }}>
                {r.score}
                <span className="text-[13px] text-[var(--color-ink-4)]">/100</span>
              </span>
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardHead title="Recommended actions" icon="shield" count={r.recommendations.length} />
          <CardBody className="flex flex-col gap-2.5">
            {r.recommendations.map((rec, i) => (
              <div key={i} className="flex gap-2.5">
                <span
                  className="shrink-0 w-5 h-5 grid place-items-center rounded-full text-[10.5px] font-black mt-0.5"
                  style={{ background: "rgb(248 113 113 / 0.14)", color: "var(--color-bad)" }}
                >
                  {i + 1}
                </span>
                <p className="text-[13px] leading-relaxed" style={{ color: "var(--color-ink-2)" }}>
                  {rec}
                </p>
              </div>
            ))}
          </CardBody>
        </Card>
      </div>

      {/* index.html reportMetaHtml — the reproducibility record. Which APIs
          were configured decides whether a "clean" verdict means "looked
          everywhere and found nothing" or "nothing was available to look at",
          and six weeks later nobody remembers which. */}
      <Card>
        <CardHead
          title="Report Information"
          icon="file"
          subtitle="The settings that were in force when this file was analysed"
        />
        <CardBody>
          <KV label="File" mono copyable>
            {r.reportMeta.file.name}
          </KV>
          <KV label="Size">{formatBytes(r.reportMeta.file.sizeBytes)}</KV>
          <KV label="Analysis time" mono>
            {new Date(r.reportMeta.analysisTimeUtc).toLocaleString()}
          </KV>
          <KV label="Analysis version" mono>
            {r.reportMeta.analysisVersion}
          </KV>
          <div
            className="grid sm:grid-cols-2 gap-x-6 gap-y-0 mt-3 pt-3 border-t"
            style={{ borderColor: "var(--color-line)" }}
          >
            {r.reportMeta.options.map((o) => (
              <KV key={o.label} label={o.label}>
                <span style={{ color: "var(--color-ok)" }}>{o.value}</span>
              </KV>
            ))}
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHead
          title="Attachments"
          icon="file"
          count={r.attachments.length}
          subtitle="Hashed and matched before anyone opens them"
          action={
            <Button variant="subtle" size="xs" icon="bug" onClick={() => navigate("/t/malware")}>
              Scan with Malware Analyzer
            </Button>
          }
        />
        <Table>
          <thead>
            <tr>
              <Th>File</Th>
              <Th align="right">Size</Th>
              <Th>Type</Th>
              <Th align="center">Verdict</Th>
              <Th>Detail</Th>
            </tr>
          </thead>
          <tbody>
            {r.attachments.map((a) => (
              <tr key={a.name} className="hover:bg-[var(--color-surface-2)]">
                <Td mono className="font-semibold">{a.name}</Td>
                <Td align="right" mono>{formatBytes(a.size)}</Td>
                <Td mono className="max-w-[220px]">
                  {/* `line-clamp-*` sets `display: -webkit-box` on the element
                      it is applied to. On an inline <span> that is ignored, so
                      the text wraps to a second line inside a cell sized for
                      one, and the row silently grows. The clamp has to be on
                      the block, not wrapped around one. */}
                  <span className="block line-clamp-1 text-[11.5px]">
                    {a.type}
                  </span>
                </Td>
                <Td align="center">
                  <VerdictBadge verdict={a.verdict === "malicious" ? "malicious" : a.verdict === "benign" ? "clean" : "suspicious"} />
                </Td>
                <Td className="text-[12px] text-[var(--color-ink-3)]">{a.detail}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
    </div>
  );
}

/* The body as the original renders it: markup with <script> removed and
   every URL defanged, so the frame cannot fetch anything. */
/* The body as the original renders it: markup with <script> removed and
   every URL neutralised, so the frame cannot fetch anything. */
const SANITISED_BODY = `<!doctype html><html><head><meta charset="utf-8">
<style>body{font-family:system-ui,sans-serif;margin:0;padding:24px;background:#fff;color:#111}
.brand-row{display:flex;align-items:center;gap:10px;margin-bottom:18px}
.brand-row h1{font-size:18px;margin:0}
.cta{display:inline-block;background:#3b82f6;color:#fff;padding:10px 18px;border-radius:6px;text-decoration:none;font-weight:600;margin:8px 8px 0 0}
.alt{display:inline-block;border:1px solid #d0d7de;padding:9px 16px;border-radius:6px;text-decoration:none;color:#111}
.note{color:#6b7280;font-size:12px;margin-top:20px;border-top:1px solid #e5e7eb;padding-top:12px}
</style></head><body>
<div class="brand-row"><h1>Collab Invitation</h1></div>
<p>Hi <b>A. Raman</b>,</p>
<p>Your channel has been <b>selected</b> for the YouTube Partner Monetisation
   programme. This is a limited offer closing in <b>24 hours</b>.</p>
<a class="cta" href="#">Confirm your channel</a>
<a class="alt" href="#">Sign in with Google</a>
<p class="note">If you did not request this, simply ignore this email.<br>
Unsubscribe &middot; update preferences &middot; collaborate-youtube[.]com</p>
</body></html>`;
/* Headers the original treats as worth reading, and marks "checked" in the
   raw-header view. */
const RISKY_HEADERS = [
  "return-path",
  "reply-to",
  "from",
  "received-spf",
  "authentication-results",
  "dkim-signature",
];

/* index.html:1468 — the active preview tab is written to sessionStorage, so
   the view you were reading is still there after a reload. */
const PREVIEW_TAB_KEY = "secconflux.previewTab";

function Preview() {
  const [view, setView] = useState<"html" | "text" | "headers">(() => {
    try {
      const v = sessionStorage.getItem(PREVIEW_TAB_KEY);
      if (v === "html" || v === "text" || v === "headers") return v;
    } catch {
      /* fall through to the default */
    }
    return "html";
  });
  /* index.html:1005 — the raw-headers view carries its own filter box. */
  const [headerQ, setHeaderQ] = useState("");

  function pick(next: typeof view) {
    setView(next);
    try {
      sessionStorage.setItem(PREVIEW_TAB_KEY, next);
    } catch {
      /* non-fatal: it just will not survive a reload */
    }
  }

  const headers = PHISHING_REPORT.rawHeaders.filter(
    (h) =>
      !headerQ ||
      h.name.toLowerCase().includes(headerQ.toLowerCase()) ||
      h.value.toLowerCase().includes(headerQ.toLowerCase()),
  );

  const TABS = [
    { id: "html" as const, label: "HTML" },
    { id: "text" as const, label: "Plain Text" },
    { id: "headers" as const, label: "Raw Headers" },
  ];

  return (
    <Card>
      <CardHead
        title="Email Preview"
        icon="eye"
        subtitle="The sanitised render, the plain-text part, and the raw source"
        action={
          <div
            className="flex gap-0.5 p-1 rounded-[var(--radius-sm)]"
            style={{ background: "var(--color-surface-2)" }}
          >
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => pick(t.id)}
                aria-pressed={view === t.id}
                className="h-7 px-2.5 rounded-[4px] text-[12.5px] font-semibold transition-colors whitespace-nowrap"
                style={{
                  background: view === t.id ? "var(--tool-tint)" : "transparent",
                  color: view === t.id ? "var(--tool-accent)" : "var(--color-ink-4)",
                }}
              >
                {t.label}
              </button>
            ))}
          </div>
        }
      />
      <CardBody>
        {view === "html" && (
          <>
            <Callout tone="warn" title="Sanitised render">
              Scripts and styles are stripped before this frame is built, and
              the frame is sandboxed to{" "}
              <code className="mono">allow-same-origin</code> — so nothing here
              executes and the tracking pixel is never fetched.
            </Callout>
            {/* index.html:1005 — the original renders the sanitised body in a
                sandboxed <iframe srcdoc>. A code block shows the markup as
                text, which is not the same thing: it does not let you see
                what the recipient would have seen. */}
            <iframe
              title="Sanitised HTML preview"
              sandbox="allow-same-origin"
              srcDoc={SANITISED_BODY}
              className="w-full mt-3 rounded-[var(--radius-md)] border bg-white"
              style={{ height: 420, borderColor: "var(--color-line)" }}
            />
          </>
        )}

        {view === "text" && (
          <CodeBlock
            language="text"
            maxHeight={440}
            code={[
              "Hi A. Raman,",
              "",
              "Your channel has been selected for the YouTube Partner",
              "Monetisation programme. This is a limited offer closing in",
              "24 hours.",
              "",
              "Confirm your channel:",
              "http://185.220.101.44:8080/verify?token=8f2ac1",
              "",
              "If you did not request this, simply ignore this email.",
              "",
              "--",
              "Collab Support",
              "unsubscribe@collaborate-youtube[.]com",
            ].join("\n")}
          />
        )}

        {view === "headers" && (
          <div className="flex flex-col gap-3">
            <Input
              dense
              icon="search"
              placeholder="Search headers…"
              value={headerQ}
              onChange={(e) => setHeaderQ(e.target.value)}
            />
            <div className="flex flex-col gap-1 max-h-[360px] overflow-y-auto sc-overscroll">
              {headers.length === 0 && (
                <p className="text-[13px] px-1" style={{ color: "var(--color-ink-4)" }}>
                  No header matches “{headerQ}”.
                </p>
              )}
              {headers.map((h, i) => (
                <div
                  key={i}
                  className="px-2.5 py-1.5 rounded-[5px]"
                  style={{ background: "var(--color-surface-2)" }}
                >
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="mono text-[11.5px] font-bold">{h.name}</span>
                    {RISKY_HEADERS.includes(h.name.toLowerCase()) && (
                      <Badge tone="warn">checked</Badge>
                    )}
                  </div>
                  <div
                    className="mono text-[11px] break-all leading-relaxed"
                    style={{ color: "var(--color-ink-3)" }}
                  >
                    {h.value}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardBody>
    </Card>
  );
}
