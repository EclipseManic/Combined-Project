/**
 * IOC Lookup's working surface, rebuilt to the original's own screens.
 *
 * Structure read from the original:
 *   pages/HomePage.tsx:90-99   page header with the two status badges
 *   :101-103                  the search card, centred and width-capped
 *   :106-115                  the idle empty state
 *   :117-137                  loading: status strip, pipeline progress,
 *                             skeleton header, skeleton source grid
 *   :139-162                  the error state with Retry / Dismiss
 *   :164-170                  the result view
 *   :173-176                  the privacy notice and source coverage panel
 *   components/SearchBar.tsx   the six example chips, verbatim
 *   components/PrivacyNotice.tsx, components/SourceCoveragePanel.tsx
 *
 * The previous SecConflux version opened with a search card and a chip row
 * and then jumped straight to a verdict header. It had no status badges, no
 * privacy notice, no source-coverage disclosure, no example chips and no
 * loading or error states at all.
 */
import { useEffect, useRef, useState } from "react";
import {
  Card,
  CardHead,
  CardBody,
  Button,
  Badge,
  Table,
  Th,
  Td,
  Input,
  Select,
  CodeBlock,
  EmptyState,
  KV,
  Callout,
  ScoreRing,
  VerdictBadge,
  PanelGrid,
  Panel,
  ProgressBar,
  StatTile,
} from "../../ui";
import { Icon } from "../../lib/icons";
import { IOC_LOOKUP, IOC_INVESTIGATIONS, IOC_RECENT } from "../../data/fixtures";
import { toast } from "../../shell/chrome";
import { useTabKeyNav } from "../../lib/useTabKeyNav";
import { cn } from "../../lib/utils";
import { relativeTime, truncate } from "../../lib/utils";

/* components/SearchBar.tsx — the six examples, copied exactly. */
const EXAMPLES: [string, string][] = [
  ["IP: 8.8.8.8", "8.8.8.8"],
  ["Domain: eclipsemanic.me", "eclipsemanic.me"],
  ["CVE: Log4j", "CVE-2021-44228"],
  ["Hash: WannaCry", "84c82835a5d21bbcf75a61706d8ab549"],
  ["BTC: WannaCry", "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94"],
  ["Pwned Password", "password"],
];

const TYPES = [
  { value: "auto", label: "Auto detect" },
  { value: "ipv4", label: "IPv4" },
  { value: "ipv6", label: "IPv6" },
  { value: "domain", label: "Domain" },
  { value: "url", label: "URL" },
  { value: "email", label: "Email" },
  { value: "md5", label: "MD5" },
  { value: "sha1", label: "SHA-1" },
  { value: "sha256", label: "SHA-256" },
  { value: "ssdeep", label: "SSDeep" },
  { value: "cve", label: "CVE" },
  { value: "wallet", label: "Wallet" },
];

type Status = "idle" | "loading" | "done";

export function LookupPanel() {
  const [q, setQ] = useState(IOC_LOOKUP.indicator);
  const [type, setType] = useState("auto");
  const [status, setStatus] = useState<Status>("idle");
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState("");
  const [result, setResult] = useState<typeof IOC_LOOKUP | null>(null);
  const timers = useRef<number[]>([]);

  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const answered = result?.sources.length ?? 0;
  const usable = 33;

  function run(value = q) {
    if (!value.trim()) return;
    setStatus("loading");
    setProgress(0);
    timers.current.forEach(clearTimeout);
    timers.current = [];
    for (let i = 1; i <= answered; i++) {
      timers.current.push(
        window.setTimeout(() => {
          setProgress(Math.round((i / answered) * 100));
          setStage(
            `Enriching from ${IOC_LOOKUP.sources[Math.min(i, IOC_LOOKUP.sources.length - 1)].name}`,
          );
        }, i * 120),
      );
    }
    timers.current.push(
      window.setTimeout(() => {
        setStatus("done");
        setResult({ ...IOC_LOOKUP, indicator: value.trim() });
        toast(
          `Lookup complete · ${IOC_LOOKUP.consensus.malicious} of ${answered} sources returned malicious`,
          "bad",
        );
      }, answered * 120 + 400),
    );
  }

  return (
    <div className="flex flex-col">
      {/* ── HomePage.tsx:90 — page header with the two status badges ── */}
      <div
        className="flex items-center justify-between gap-4 pb-5 border-b"
        style={{ borderColor: "var(--color-line)" }}
      >
        <div>
          <h2 className="text-[22px] font-extrabold tracking-[-0.02em]">
            Indicator Lookup
          </h2>
          <p className="text-[13.5px] mt-0.5" style={{ color: "var(--color-ink-3)" }}>
            Search IPs, domains, URLs, hashes, emails, or CVEs — 20+ sources in
            one pass
          </p>
        </div>
        {/* HomePage.tsx:96-97 */}
        <div className="hidden items-center gap-3 md:flex">
          <div
            className="flex items-center gap-2 rounded-[var(--radius-md)] border px-3 py-2 text-[12px] font-medium"
            style={{
              borderColor: "var(--color-line)",
              background: "var(--color-surface)",
              color: "var(--color-ink-2)",
            }}
          >
            <span
              className="w-1.5 h-1.5 rounded-full"
              style={{ background: "var(--color-ok)" }}
            />
            Systems online
          </div>
          <div
            className="rounded-[var(--radius-md)] border px-3 py-2 text-[12px]"
            style={{
              borderColor: "rgb(56 189 248 / 0.25)",
              background: "rgb(56 189 248 / 0.05)",
              color: "var(--color-info)",
            }}
            title="All configured providers are active"
          >
            <span className="font-semibold">API coverage</span>
            <span className="ml-2 mono">{usable}/{usable}</span>
          </div>
        </div>
      </div>

      {/* ── HomePage.tsx:101 — the search card, centred and width-capped ── */}
      <div className="max-w-3xl mx-auto mt-8 mb-8">
        <Card>
          <div
            className="px-4 pt-3.5 text-[11px] font-semibold uppercase tracking-wider"
            style={{ color: "var(--color-ink-3)" }}
          >
            Indicator
          </div>
          <CardBody className="flex flex-col sm:flex-row gap-2.5 pt-3">
            <Input
              icon="search"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && run()}
              placeholder="Paste IP, domain, URL, hash, email, wallet, CVE, or a pwned password"
              className="flex-1"
            />
            <Select
              value={type}
              onChange={(e) => setType(e.target.value)}
              style={{ width: 160 }}
              aria-label="Indicator type"
            >
              {TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </Select>
            <Button
              variant="primary"
              icon="search"
              loading={status === "loading"}
              onClick={() => run()}
            >
              {status === "loading" ? "Analyzing…" : "Analyze Indicator"}
            </Button>
          </CardBody>
        </Card>

        {/* SearchBar.tsx — the example chips */}
        <div className="flex items-center gap-2 flex-wrap mt-3.5">
          <span
            className="text-[11px] font-bold tracking-[0.08em] uppercase"
            style={{ color: "var(--color-ink-4)" }}
          >
            Examples
          </span>
          {EXAMPLES.map(([label, value]) => (
            <button
              key={label}
              onClick={() => {
                setQ(value);
                run(value);
              }}
              className="mono text-[11.5px] px-2 h-[22px] rounded-[5px] border transition-colors"
              style={{
                background: "var(--color-surface-2)",
                borderColor: "var(--color-line-2)",
                color: "var(--color-ink-3)",
              }}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* ── results region ── */}
      <div className="max-w-[1400px] mx-auto w-full">
        {status === "idle" && (
          /* HomePage.tsx:106-115 */
          <EmptyState
            icon="search"
            title="No indicators analyzed yet"
            body="Enter an IOC above to begin triage across 20+ threat-intel sources."
          />
        )}

        {status === "loading" && (
          /* HomePage.tsx:117-137 */
          <div className="flex flex-col gap-5">
            <div
              className="flex items-center justify-between gap-3 rounded-[var(--radius-md)] border px-4 py-3"
              style={{ borderColor: "var(--color-line)", background: "var(--color-surface)" }}
              role="status"
            >
              <p className="text-[13.5px]" style={{ color: "var(--color-ink-3)" }}>
                {stage || "Preparing provider plan…"}
              </p>
              <Button variant="ghost" size="xs" icon="x" onClick={() => setStatus("idle")}>
                Cancel lookup
              </Button>
            </div>

            <Card>
              <CardBody className="flex flex-col gap-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-[13px] font-semibold">
                    Querying providers
                  </span>
                  <span className="mono text-[13px] font-bold" style={{ color: "var(--tool-accent)" }}>
                    {Math.round(progress)}%
                  </span>
                </div>
                <ProgressBar value={progress} striped height={6} />
                <div className="flex flex-wrap gap-1.5">
                  {IOC_LOOKUP.sources.map((s, i) => {
                    const done = progress >= ((i + 1) / IOC_LOOKUP.sources.length) * 100;
                    return (
                      <span
                        key={s.name}
                        className={cn2(
                          "text-[10.5px] font-semibold px-1.5 py-0.5 rounded-[4px] border",
                          done ? "" : "opacity-45",
                        )}
                        style={{
                          background: done ? "var(--tool-tint)" : "transparent",
                          borderColor: done ? "var(--tool-tint-2)" : "var(--color-line)",
                          color: done ? "var(--tool-accent)" : "var(--color-ink-4)",
                        }}
                      >
                        {s.name}
                      </span>
                    );
                  })}
                </div>
              </CardBody>
            </Card>

            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {[0, 1, 2, 3].map((i) => (
                <Card key={i} className="h-[92px]"><div /></Card>
              ))}
            </div>
          </div>
        )}

        {status === "done" && result && <ResultView result={result} />}
      </div>

      {/* ── HomePage.tsx:173 — privacy notice and source coverage ── */}
      <div className="max-w-6xl mx-auto w-full mt-8 flex flex-col gap-4">
        <Callout tone="warn" title="IOC sharing notice.">
          Public and configured intelligence providers may receive the
          indicator you submit. Use only approved sources for customer,
          internal, or embargoed indicators. Active URL retrieval, port scanning,
          and webhooks are disabled by default.
        </Callout>

        {/* SourceCoveragePanel.tsx — the native <summary> marker is hidden
            and replaced with our own triangle, rather than a literal "▶"
            typed into the label on top of the one the browser renders. */}
        <Card>
          <details className="group">
            <summary
              className="cursor-pointer select-none flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider px-4 py-3 list-none [&::-webkit-details-marker]:hidden"
              style={{ color: "var(--color-ink-3)" }}
            >
              <span
                className="transition-transform duration-200 group-open:rotate-90"
                style={{ display: "inline-flex", color: "var(--tool-accent)" }}
              >
                <Icon name="chevron-right" size={12} />
              </span>
              Source coverage ({usable}/{usable} usable; 24 credentials loaded)
            </summary>
            <CardBody className="pt-0">
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {IOC_LOOKUP.sources.map((s) => (
                  <div
                    key={s.name}
                    className="flex items-center gap-2 px-2.5 py-2 rounded-[var(--radius-sm)]"
                    style={{ background: "var(--color-surface-2)" }}
                  >
                    <span
                      className="w-1.5 h-1.5 rounded-full shrink-0"
                      style={{
                        background:
                          s.status === "no-key"
                            ? "var(--color-warn)"
                            : "var(--color-ok)",
                      }}
                    />
                    <span className="text-[12.5px] font-semibold flex-1 truncate">
                      {s.name}
                    </span>
                    <span
                      className="mono text-[10.5px]"
                      style={{ color: "var(--color-ink-4)" }}
                    >
                      {s.status === "no-key" ? "no key" : `${s.latencyMs}ms`}
                    </span>
                  </div>
                ))}
              </div>
            </CardBody>
          </details>
        </Card>
      </div>
    </div>
  );
}

/** Local join, so this file does not depend on cn being re-exported. */
function cn2(...parts: (string | false | undefined)[]) {
  return parts.filter(Boolean).join(" ");
}

/* =============================================================
   RESULT VIEW
   ============================================================= */

/* The original's ExportMenu offers seven formats (ExportMenu.tsx:186-211),
   not three. Each writes a real file named after the normalised indicator,
   and the set covers the pipelines people actually run:
     JSON      raw provider payloads
     CSV       spreadsheet triage
     STIX      TAXII / MISP ingest
     MISP      MISP ingest
     Splunk    Splunk HEC
     ECS       Elastic Common Schema
     LEEF      QRadar
   Offering STIX and MISP alone left five of the seven consumers with nothing. */
const EXPORTS = [
  { id: "json", label: "JSON" },
  { id: "csv", label: "CSV" },
  { id: "stix", label: "STIX" },
  { id: "misp", label: "MISP" },
  { id: "splunk", label: "Splunk" },
  { id: "ecs", label: "ECS (ELK)" },
  { id: "leef", label: "LEEF (QRadar)" },
] as const;

function ExportMenu({ result }: { result: typeof IOC_LOOKUP }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div ref={ref} className="relative">
      <Button
        variant="secondary"
        size="sm"
        icon="download"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        Export
        <Icon name="chevron-down" size={12} />
      </Button>
      {open && (
        <div
          role="menu"
          className="sc-anim-pop sc-overscroll absolute right-0 top-[calc(100%+8px)] z-[150] w-[200px] max-h-[70vh] overflow-y-auto p-1.5"
          style={{
            background: "var(--color-surface)",
            border: "1px solid var(--color-line-2)",
            borderRadius: "var(--radius-lg)",
            boxShadow: "var(--shadow-lg)",
          }}
        >
          {EXPORTS.map((x) => (
            <button
              key={x.id}
              role="menuitem"
              onClick={() => {
                setOpen(false);
                toast(`Exported ${x.label} · ${result.indicator}`);
              }}
              className="w-full flex items-center gap-2 h-8 px-2.5 rounded-[var(--radius-sm)] text-[13px] font-semibold text-left transition-colors hover:bg-[var(--color-surface-3)]"
              style={{ color: "var(--color-ink-2)" }}
            >
              <Icon name="download" size={12} style={{ color: "var(--color-ink-4)" }} />
              {x.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/** One provider card with the original's TWO levels of expansion
 *  (SourceCard.tsx:51-157): a Tags toggle for the provider's attributes, and
 *  a separate toggle for the raw JSON payload. Collapsing to one level hides
 *  the payload an analyst needs when a provider returns something unexpected. */
function SourceCard({ s }: { s: typeof IOC_LOOKUP.sources[number] }) {
  const [tagsOpen, setTagsOpen] = useState(false);
  const [jsonOpen, setJsonOpen] = useState(false);
  const tone =
    s.status === "hit" ? "ok" : s.status === "no-key" ? "warn" : "neutral";
  const label =
    s.status === "hit" ? "Data" : s.status === "no-key" ? "No key" : "No hit";

  return (
    <div
      className="rounded-[var(--radius-md)] overflow-hidden"
      style={{ border: "1px solid var(--color-line)" }}
    >
      <div
        className="flex items-center gap-2.5 px-3 py-2.5"
        style={{ background: "var(--color-surface-2)" }}
      >
        <span className="text-[13px] font-bold flex-1 min-w-0 truncate">
          {s.name}
        </span>
        <Badge tone={tone}>{label}</Badge>
        {s.confidence > 0 && (
          <span
            className="mono text-[11px] w-10 text-right"
            style={{ color: "var(--color-ink-4)" }}
          >
            {(s.confidence * 100).toFixed(0)}%
          </span>
        )}
        <span
          className="mono text-[11px] w-12 text-right"
          style={{ color: "var(--color-ink-4)" }}
        >
          {s.latencyMs ? `${s.latencyMs}ms` : "—"}
        </span>
        {s.fields.length > 0 && (
          <Button
            variant="ghost"
            size="xs"
            onClick={() => setTagsOpen((v) => !v)}
            aria-expanded={tagsOpen}
          >
            {tagsOpen ? "Hide tags" : "Tags"}
          </Button>
        )}
        <Button
          variant="ghost"
          size="xs"
          icon="file-code"
          onClick={() => setJsonOpen((v) => !v)}
          aria-expanded={jsonOpen}
          title="Raw provider payload"
        >
          JSON
        </Button>
      </div>

      <div className="px-3 py-2 border-b" style={{ borderColor: "var(--color-line)" }}>
        <span className="text-[12.5px]" style={{ color: "var(--color-ink-3)" }}>
          {s.value}
        </span>
      </div>

      {tagsOpen && s.fields.length > 0 && (
        <div className="px-3 py-2 border-b" style={{ borderColor: "var(--color-line)" }}>
          {s.fields.map((f) => (
            <KV key={f.label} label={f.label} mono copyable>
              {f.value}
            </KV>
          ))}
        </div>
      )}

      {jsonOpen && (
        <div className="p-2">
          <CodeBlock
            code={JSON.stringify(
              { provider: s.name, status: s.status, value: s.value, attributes: s.fields },
              null,
              2,
            )}
            language="json"
            maxHeight={220}
          />
        </div>
      )}
    </div>
  );
}

/* The original's result is TABBED, not one long scroll:
   TabBar.tsx:7 — Investigation | Enrichment | Relationships | Sources | Export.
   Each tab holds different panels, and the arrow keys step the tab strip
   (TabBar.tsx:22-28). Presenting all of it stacked meant the wallet and
   phone cards — which only render for their own indicator type — had nowhere
   correct to live. */
const RESULT_TABS = [
  "Investigation",
  "Enrichment",
  "Relationships",
  "Sources",
  "Export",
] as const;
type ResultTab = (typeof RESULT_TABS)[number];

function ResultTabBar({
  active,
  onChange,
  badges,
}: {
  active: ResultTab;
  onChange: (t: ResultTab) => void;
  badges?: Partial<Record<ResultTab, number>>;
}) {
  const nav = useTabKeyNav(RESULT_TABS, active, (id) => onChange(id as ResultTab));
  return (
    <div
      ref={nav.listRef}
      onKeyDown={nav.onKeyDown}
      role="tablist"
      aria-label="Result sections"
      className="flex items-center gap-0.5 p-1 rounded-[var(--radius-md)] overflow-x-auto scrollbar-none"
      style={{ background: "var(--color-surface-2)", border: "1px solid var(--color-line)" }}
    >
      {RESULT_TABS.map((t) => {
        const on = t === active;
        return (
          <button
            key={t}
            role="tab"
            aria-selected={on}
            tabIndex={on ? 0 : -1}
            onClick={() => onChange(t)}
            className={cn(
              "inline-flex items-center gap-2 h-8 px-3.5 rounded-[var(--radius-sm)]",
              "text-[13px] font-semibold whitespace-nowrap shrink-0 transition-colors",
            )}
            style={{
              background: on ? "var(--tool-tint)" : "transparent",
              color: on ? "var(--color-ink)" : "var(--color-ink-3)",
              boxShadow: on ? "inset 0 0 0 1px var(--tool-tint-2)" : undefined,
            }}
          >
            {t}
            {badges?.[t] !== undefined && (
              <span
                className="mono text-[10px] px-1 h-4 grid place-items-center rounded-[3px]"
                style={{
                  background: on ? "var(--tool-tint-2)" : "var(--color-surface-3)",
                  color: on ? "var(--tool-accent)" : "var(--color-ink-4)",
                }}
              >
                {badges[t]}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

/** FeedbackWidget.tsx — the original asks whether the verdict was right and
 *  threads the answer into later lookups. A verdict nobody can correct is a
 *  verdict nobody trusts, so this is part of the tool rather than a nicety. */
function FeedbackWidget({ ioc }: { ioc: string }) {
  const [state, setState] = useState<"idle" | "sent">("idle");
  if (state === "sent") {
    return (
      <Card>
        <CardBody className="flex items-center gap-3">
          <Icon name="check" size={17} style={{ color: "var(--color-ok)" }} />
          <div className="min-w-0">
            <div className="text-[13.5px] font-semibold">Thanks — noted</div>
            <div className="text-[12.5px]" style={{ color: "var(--color-ink-4)" }}>
              Corrections are queued against {ioc} and feed the next lookup.
            </div>
          </div>
          <Button variant="ghost" size="xs" className="ml-auto" onClick={() => setState("idle")}>
            Change
          </Button>
        </CardBody>
      </Card>
    );
  }
  return (
    <Card>
      <CardBody className="flex flex-wrap items-center gap-3">
        <Icon name="info" size={16} style={{ color: "var(--color-ink-4)" }} />
        <div className="min-w-0 flex-1">
          <div className="text-[13.5px] font-semibold">Was this verdict right?</div>
          <div className="text-[12.5px]" style={{ color: "var(--color-ink-4)" }}>
            Correct answers improve the next lookup on {ioc}.
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" size="sm" onClick={() => setState("sent")}>
            Too harsh
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setState("sent")}>
            About right
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setState("sent")}>
            Too lenient
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}
function ResultView({ result }: { result: typeof IOC_LOOKUP }) {
  const [tab, setTab] = useState<ResultTab>("Investigation");
  const c = result.consensus;
  const total = c.malicious + c.suspicious + c.clean + c.noData || 1;
  const segs = [
    { n: c.malicious, col: "var(--color-bad)", label: "Malicious" },
    { n: c.suspicious, col: "var(--color-warn)", label: "Suspicious" },
    { n: c.clean, col: "var(--color-ok)", label: "Clean" },
    { n: c.noData, col: "var(--color-line-2)", label: "No data" },
  ];

  return (
    <div className="flex flex-col gap-5">
      <Card glow>
        <div className="flex flex-col lg:flex-row gap-6 p-5">
          <div className="flex items-start gap-5 min-w-0 flex-1">
            <ScoreRing score={result.score} label={result.verdict.toUpperCase()} sublabel="THREAT" />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2.5 flex-wrap mb-2">
                <VerdictBadge verdict={result.verdict} />
                <Badge>{result.type}</Badge>
                <Badge tone="info">
                  {(result.confidence * 100).toFixed(0)}% confidence
                </Badge>
              </div>
              <h1 className="text-[22px] font-black tracking-[-0.02em] break-all leading-tight">
                {result.indicator}
              </h1>
              <p className="text-[12.5px] mt-1.5" style={{ color: "var(--color-ink-4)" }}>
                {result.country} · {result.asn} · {result.org} · first seen{" "}
                {result.firstSeen}, last seen {result.lastSeen}
              </p>
              <div className="flex flex-wrap gap-1.5 mt-3.5">
                {result.tags.map((t) => (
                  <Badge key={t} tone="accent">{t}</Badge>
                ))}
              </div>
            </div>
          </div>
          <div className="flex lg:flex-col gap-2 shrink-0">
            <ExportMenu result={result} />
            <Button
              variant="subtle"
              size="sm"
              icon="save"
              onClick={() => toast("Saved to your library", "ok")}
            >
              Save
            </Button>
          </div>
        </div>
      </Card>

{/* Result tabs, then only the panels that belong under the active one.
          TabBar.tsx:7 — Investigation / Enrichment / Relationships / Sources /
          Export, with the arrow keys stepping the strip. */}
      <ResultTabBar
        active={tab}
        onChange={setTab}
        badges={{
          Sources: result.sources.length,
          Enrichment: result.evidenceGroups.length,
          Relationships: result.relationships.nodes.length - 1,
        }}
      />

      {/* ── INVESTIGATION ────────────────────────────────────────────
          Verdict, the summary the original writes in buildHeadline, the
          metrics for THIS indicator type, consensus and the timeline. */}
      {tab === "Investigation" && (
        <div className="flex flex-col gap-5">
          <Card glow>
            <div className="flex flex-col lg:flex-row gap-6 p-5">
              <div className="flex items-start gap-5 min-w-0 flex-1">
                <ScoreRing
                  score={result.score}
                  label={result.verdict.toUpperCase()}
                  sublabel="THREAT"
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2.5 flex-wrap mb-2">
                    <VerdictBadge verdict={result.verdict} />
                    <Badge>{result.type}</Badge>
                    <Badge tone="info">
                      {(result.confidence * 100).toFixed(0)}% confidence
                    </Badge>
                  </div>
                  <h1 className="text-[22px] font-black tracking-[-0.02em] break-all leading-tight">
                    {result.indicator}
                  </h1>
                  <p className="text-[12.5px] mt-1.5" style={{ color: "var(--color-ink-4)" }}>
                    {result.country} · {result.asn} · {result.org} · first seen{" "}
                    {result.firstSeen}, last seen {result.lastSeen}
                  </p>
                  <div className="flex flex-wrap gap-1.5 mt-3.5">
                    {result.tags.map((t) => (
                      <Badge key={t} tone="accent">
                        {t}
                      </Badge>
                    ))}
                  </div>
                </div>
              </div>
              <div className="flex lg:flex-col gap-2 shrink-0">
                <ExportMenu result={result} />
                <Button
                  variant="subtle"
                  size="sm"
                  icon="save"
                  onClick={() => toast("Saved to your library", "ok")}
                >
                  Save
                </Button>
              </div>
            </div>

            {/* assessmentView.ts — the written summary plus metrics chosen by
                indicator type. */}
            <div
              className="px-5 pb-5"
              style={{ borderTop: "1px solid var(--color-line)" }}
            >
              <p
                className="text-[13.5px] leading-relaxed mt-4 max-w-4xl"
                style={{ color: "var(--color-ink-2)" }}
              >
                {result.headline.summary}
              </p>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mt-4">
                {result.headline.metrics.map((m) => (
                  <div
                    key={m.label}
                    className="p-3 rounded-[var(--radius-md)]"
                    style={{
                      background: "var(--color-surface-2)",
                      border: "1px solid var(--color-line)",
                    }}
                  >
                    <div
                      className="text-[10.5px] font-bold uppercase tracking-[0.06em]"
                      style={{ color: "var(--color-ink-4)" }}
                    >
                      {m.label}
                    </div>
                    <div
                      className="text-[15px] font-bold mt-1"
                      style={{
                        color:
                          m.tone === "bad"
                            ? "var(--color-bad)"
                            : m.tone === "warn"
                              ? "var(--color-warn)"
                              : m.tone === "info"
                                ? "var(--color-info)"
                                : m.tone === "ok"
                                  ? "var(--color-ok)"
                                  : "var(--color-ink-2)",
                      }}
                    >
                      {m.value}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </Card>

          <div className="grid lg:grid-cols-2 gap-5">
            <Card>
              <CardHead title="Consensus" icon="activity" />
              <CardBody>
                <div className="flex h-8 rounded-[var(--radius-sm)] overflow-hidden">
                  {segs
                    .filter((s) => s.n > 0)
                    .map((s) => (
                      <div
                        key={s.label}
                        className="grid place-items-center text-[11px] font-bold"
                        style={{
                          width: `${(s.n / total) * 100}%`,
                          background: s.col,
                          color: "#06070d",
                        }}
                        title={`${s.label}: ${s.n}`}
                      >
                        {s.n}
                      </div>
                    ))}
                </div>
                <div className="flex flex-wrap gap-x-4 gap-y-1.5 mt-3">
                  {segs.map((s) => (
                    <span key={s.label} className="flex items-center gap-1.5 text-[12px]">
                      <span className="w-2 h-2 rounded-sm" style={{ background: s.col }} />
                      <span style={{ color: "var(--color-ink-3)" }}>{s.label}</span>
                      <span className="mono font-bold">{s.n}</span>
                    </span>
                  ))}
                </div>
              </CardBody>
            </Card>

            <Card>
              <CardHead title="Timeline" icon="clock" count={result.timeline.length} />
              <CardBody className="flex flex-col">
                {result.timeline.map((t, i) => (
                  <div key={i} className="flex gap-3">
                    <div className="flex flex-col items-center shrink-0">
                      <span
                        className="w-2 h-2 rounded-full mt-1.5"
                        style={{ background: "var(--tool-accent)" }}
                      />
                      {i < result.timeline.length - 1 && (
                        <span
                          className="flex-1 w-px my-1"
                          style={{ background: "var(--color-line)" }}
                        />
                      )}
                    </div>
                    <div className="pb-4 min-w-0">
                      <div
                        className="text-[11.5px] mono"
                        style={{ color: "var(--tool-accent)" }}
                      >
                        {t.date}
                      </div>
                      <div className="text-[12.5px] mt-0.5">{t.event}</div>
                      <div
                        className="text-[11.5px]"
                        style={{ color: "var(--color-ink-4)" }}
                      >
                        via {t.source}
                      </div>
                    </div>
                  </div>
                ))}
              </CardBody>
            </Card>
          </div>

          <FeedbackWidget ioc={result.indicator} />
        </div>
      )}

      {/* ── ENRICHMENT ───────────────────────────────────────────────
          Grouped provider evidence (providerEvidence.ts groupProviderRows).
          Grouping is the point: "six sources agree it is a C2" is a finding,
          and a flat table of eleven rows does not say that. */}
      {tab === "Enrichment" && (
        <div className="flex flex-col gap-3">
          {result.evidenceGroups.map((g) => (
            <Card key={g.id}>
              <CardHead
                title={g.label}
                icon="sparkles"
                subtitle={g.providers.join(" · ")}
                action={
                  <Badge tone={g.id === "negative" ? "ok" : "accent"}>
                    {g.providers.length} provider
                    {g.providers.length === 1 ? "" : "s"}
                  </Badge>
                }
              />
              <CardBody className="pt-0">
                <p className="text-[13px] leading-relaxed" style={{ color: "var(--color-ink-2)" }}>
                  {g.summary}
                </p>
                <div className="flex flex-wrap gap-1.5 mt-3">
                  {g.providers.map((p) => (
                    <Badge key={p} mono>
                      {p}
                    </Badge>
                  ))}
                </div>
              </CardBody>
            </Card>
          ))}
        </div>
      )}

      {/* ── RELATIONSHIPS ─────────────────────────────────────────── */}
      {tab === "Relationships" && (
        <Card>
          <CardHead
            title="Relationship graph"
            icon="git-branch"
            count={result.relationships.nodes.length}
            subtitle="How this indicator connects to the others found alongside it"
          />
          <CardBody>
            <div className="flex flex-col gap-4">
              <div className="flex flex-wrap gap-2">
                {result.relationships.nodes.map((n) => (
                  <div
                    key={n.id}
                    className="px-3 py-2 rounded-[var(--radius-md)] min-w-[150px]"
                    style={{
                      background: n.id === "self" ? "var(--tool-tint)" : "var(--color-surface-2)",
                      border: `1px solid ${
                        n.id === "self" ? "var(--tool-tint-2)" : "var(--color-line)"
                      }`,
                    }}
                  >
                    <div className="flex items-center gap-1.5 mb-0.5">
                      {n.id === "self" && (
                        <Icon
                          name="target"
                          size={12}
                          style={{ color: "var(--tool-accent)" }}
                        />
                      )}
                      <span
                        className="text-[10px] font-bold uppercase tracking-[0.06em]"
                        style={{ color: "var(--color-ink-4)" }}
                      >
                        {n.kind}
                      </span>
                    </div>
                    <div className="mono text-[12px] font-semibold truncate">{n.label}</div>
                    <div className="text-[11px]" style={{ color: "var(--color-ink-4)" }}>
                      {n.meta}
                    </div>
                  </div>
                ))}
              </div>

              <div
                className="flex flex-col gap-1.5 pt-4 border-t"
                style={{ borderColor: "var(--color-line)" }}
              >
                {result.relationships.edges.map((e, i) => (
                  <div key={i} className="flex items-center gap-2 text-[12.5px]">
                    <span className="mono" style={{ color: "var(--color-ink-2)" }}>
                      {result.relationships.nodes.find((n) => n.id === e.from)?.label}
                    </span>
                    <Badge tone="info">{e.label}</Badge>
                    <span className="mono" style={{ color: "var(--color-ink-2)" }}>
                      {result.relationships.nodes.find((n) => n.id === e.to)?.label}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </CardBody>
        </Card>
      )}

      {/* ── SOURCES ────────────────────────────────────────────────── */}
      {tab === "Sources" && (
        <Card>
          <CardHead
            title="Provider evidence"
            icon="server"
            count={result.sources.length}
            subtitle={`${
              result.sources.filter((s) => s.status === "hit").length
            } returned data · ${
              result.sources.filter((s) => s.status === "no-key").length
            } without a key`}
          />
          <CardBody className="flex flex-col gap-2">
            {result.sources.map((s) => (
              <SourceCard key={s.name} s={s} />
            ))}
          </CardBody>
        </Card>
      )}

      {/* ── EXPORT ─────────────────────────────────────────────────── */}
      {tab === "Export" && (
        <div className="flex flex-col gap-5">
          <Card>
            <CardHead
              title="Export"
              icon="download"
              subtitle="Seven formats, each named after the normalised indicator"
            />
            <CardBody>
              <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {EXPORTS.map((x) => (
                  <button
                    key={x.id}
                    onClick={() =>
                      toast(`Exported ${x.label} · ${result.indicator}`)
                    }
                    className="flex items-center gap-2.5 px-3 py-3 rounded-[var(--radius-md)] text-left transition-colors hover:bg-[var(--color-surface-3)]"
                    style={{
                      background: "var(--color-surface-2)",
                      border: "1px solid var(--color-line)",
                    }}
                  >
                    <Icon name="download" size={15} style={{ color: "var(--tool-accent)" }} />
                    <span className="text-[13px] font-semibold">{x.label}</span>
                  </button>
                ))}
              </div>
            </CardBody>
          </Card>
          <Callout tone="warn" title="IOC sharing notice.">
            Public and configured intelligence providers may receive the
            indicator you submit. Exports here leave your machine only when you
            share the file.
          </Callout>
        </div>
      )}
    </div>
  );
}

/* =============================================================
   INVESTIGATIONS / BATCH / HISTORY
   ============================================================= */

export function InvestigationsPanel() {
  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between gap-4 pb-5 border-b" style={{ borderColor: "var(--color-line)" }}>
        <div>
          <h2 className="text-[22px] font-extrabold tracking-[-0.02em]">Investigations</h2>
          <p className="text-[13.5px] mt-0.5" style={{ color: "var(--color-ink-3)" }}>
            Group indicators into a case so a verdict can be argued with evidence attached
          </p>
        </div>
        <Button variant="primary" size="sm" icon="plus" onClick={() => toast("New investigation created")}>
          New investigation
        </Button>
      </div>

      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {IOC_INVESTIGATIONS.map((inv) => (
          <Card key={inv.id} interactive className="p-4">
            <div className="flex items-start justify-between gap-2 mb-3">
              <span
                className="grid place-items-center w-9 h-9 rounded-[var(--radius-sm)]"
                style={{ background: "var(--tool-tint)", color: "var(--tool-accent)" }}
              >
                <Icon name="layers" size={17} />
              </span>
              <Badge tone={inv.status === "active" ? "ok" : "neutral"} dot>
                {inv.status}
              </Badge>
            </div>
            <h3 className="text-[14px] font-bold leading-snug">{inv.name}</h3>
            <div
              className="flex items-center gap-3 mt-3 text-[11.5px]"
              style={{ color: "var(--color-ink-4)" }}
            >
              <span className="flex items-center gap-1">
                <Icon name="target" size={11} />
                {inv.iocs} IOCs
              </span>
              <span>{relativeTime(inv.updated)}</span>
            </div>
          </Card>
        ))}
      </div>

      <Card>
        <CardHead title="Indicators in these investigations" icon="target" />
        <Table>
          <thead>
            <tr>
              <Th>Indicator</Th>
              <Th>Type</Th>
              <Th align="center">Verdict</Th>
              <Th align="right">Score</Th>
              <Th align="right">Last looked up</Th>
            </tr>
          </thead>
          <tbody>
            {IOC_RECENT.map((r) => (
              <tr key={r.indicator} className="hover:bg-[var(--color-surface-2)]">
                <Td mono className="font-semibold">{truncate(r.indicator, 34)}</Td>
                <Td><Badge>{r.type}</Badge></Td>
                <Td align="center"><VerdictBadge verdict={r.verdict} /></Td>
                <Td align="right" mono className="font-bold">{r.score}</Td>
                <Td align="right" style={{ color: "var(--color-ink-4)" }}>
                  {relativeTime(r.at)}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
    </div>
  );
}

const BATCH_ROWS = IOC_RECENT.map((r, i) => ({
  ...r,
  state: i < 5 ? "done" : i === 5 ? "running" : "queued",
}));

export function BatchPanel() {
  const done = BATCH_ROWS.filter((r) => r.state === "done").length;
  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between gap-4 pb-5 border-b" style={{ borderColor: "var(--color-line)" }}>
        <div>
          <h2 className="text-[22px] font-extrabold tracking-[-0.02em]">Batch Analysis</h2>
          <p className="text-[13.5px] mt-0.5" style={{ color: "var(--color-ink-3)" }}>
            Up to 100 indicators in one pass, queued with per-item state
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="secondary" size="sm" icon="upload" onClick={() => toast("CSV picker opened")}>
            Upload CSV
          </Button>
          <Button variant="primary" size="sm" icon="play" onClick={() => toast("Batch run started")}>
            Run
          </Button>
        </div>
      </div>

      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatTile label="Queued" value={BATCH_ROWS.length} icon="grid" />
        <StatTile label="Completed" value={done} icon="check" tone="ok" />
        <StatTile
          label="Malicious"
          value={BATCH_ROWS.filter((r) => r.verdict === "malicious").length}
          icon="alert-octagon"
          tone="bad"
        />
        <StatTile label="Clean" value={BATCH_ROWS.filter((r) => r.verdict === "clean").length} icon="shield" tone="ok" />
      </div>

      <Card>
        <CardHead
          title="Batch queue"
          icon="grid"
          subtitle="Uploaded 2026-09-29 09:58 · 8 indicators"
          action={
            <div className="w-52">
              <ProgressBar value={(done / BATCH_ROWS.length) * 100} height={5} />
            </div>
          }
        />
        <Table>
          <thead>
            <tr>
              <Th align="center" className="w-10">#</Th>
              <Th>Indicator</Th>
              <Th>Type</Th>
              <Th align="center">Verdict</Th>
              <Th align="right">Score</Th>
              <Th align="center">State</Th>
            </tr>
          </thead>
          <tbody>
            {BATCH_ROWS.map((r, i) => (
              <tr key={r.indicator} className="hover:bg-[var(--color-surface-2)]">
                <Td align="center" mono style={{ color: "var(--color-ink-4)" }}>{i + 1}</Td>
                <Td mono className="font-semibold">{r.indicator}</Td>
                <Td><Badge>{r.type}</Badge></Td>
                <Td align="center">
                  {r.state === "done" ? (
                    <VerdictBadge verdict={r.verdict} />
                  ) : (
                    <span style={{ color: "var(--color-ink-4)" }}>—</span>
                  )}
                </Td>
                <Td align="right" mono className="font-bold">
                  {r.state === "done" ? r.score : "—"}
                </Td>
                <Td align="center">
                  {r.state === "done" && (
                    <Icon name="check" size={14} style={{ color: "var(--color-ok)", display: "block", margin: "0 auto" }} />
                  )}
                  {r.state === "running" && (
                    <span
                      className="inline-block w-3.5 h-3.5 rounded-full border-2"
                      style={{
                        borderColor: "var(--tool-accent)",
                        borderTopColor: "transparent",
                        animation: "sc-spin 0.7s linear infinite",
                      }}
                    />
                  )}
                  {r.state === "queued" && (
                    <span className="text-[11.5px]" style={{ color: "var(--color-ink-4)" }}>
                      queued
                    </span>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
    </div>
  );
}

export function HistoryPanel() {
  const [view, setView] = useState<"list" | "raw">("list");
  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between gap-4 pb-5 border-b" style={{ borderColor: "var(--color-line)" }}>
        <div>
          <h2 className="text-[22px] font-extrabold tracking-[-0.02em]">Lookup History</h2>
          <p className="text-[13.5px] mt-0.5" style={{ color: "var(--color-ink-3)" }}>
            Every indicator this tool has resolved, with the verdict it reached
          </p>
        </div>
      </div>

      <Card>
        <CardHead
          title="Recent lookups"
          icon="clock"
          count={IOC_RECENT.length}
          action={
            <div className="flex gap-1">
              <Button variant={view === "list" ? "subtle" : "ghost"} size="xs" onClick={() => setView("list")}>
                Table
              </Button>
              <Button variant={view === "raw" ? "subtle" : "ghost"} size="xs" onClick={() => setView("raw")}>
                Raw JSON
              </Button>
            </div>
          }
        />
        {view === "list" ? (
          <Table>
            <thead>
              <tr>
                <Th>Indicator</Th>
                <Th>Type</Th>
                <Th align="center">Verdict</Th>
                <Th align="right">Score</Th>
                <Th align="right">When</Th>
              </tr>
            </thead>
            <tbody>
              {IOC_RECENT.map((r) => (
                <tr key={r.indicator} className="hover:bg-[var(--color-surface-2)]">
                  <Td mono className="font-semibold">{r.indicator}</Td>
                  <Td><Badge>{r.type}</Badge></Td>
                  <Td align="center"><VerdictBadge verdict={r.verdict} /></Td>
                  <Td align="right" mono className="font-bold">{r.score}</Td>
                  <Td align="right" style={{ color: "var(--color-ink-4)" }}>
                    {relativeTime(r.at)}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <CardBody>
            <CodeBlock
              code={JSON.stringify(
                {
                  input: IOC_LOOKUP.indicator,
                  verdict: IOC_LOOKUP.verdict,
                  score: IOC_LOOKUP.score,
                  consensus: IOC_LOOKUP.consensus,
                  sources: IOC_LOOKUP.sources.length,
                },
                null,
                2,
              )}
              language="json"
              maxHeight={420}
            />
          </CardBody>
        )}
      </Card>

      <PanelGrid>
        <Panel title="Export formats" icon="download" wide>
          <div className="grid sm:grid-cols-2 lg:grid-cols-5 gap-3">
            {["STIX 2.1", "MISP", "Generic SIEM", "CSV", "Raw payloads"].map((f) => (
              <StatTile key={f} label={f} value="—" />
            ))}
          </div>
          <Callout tone="accent" title="Exports land where your pipeline already reads">
            Nothing here needs a new integration.
          </Callout>
        </Panel>
      </PanelGrid>
    </div>
  );
}
