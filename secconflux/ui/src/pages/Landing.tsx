import { useState } from "react";
import { Icon } from "../lib/icons";
import { TOOLS } from "../lib/tools";
import { SHARED_IOCS, ACTIVITY } from "../data/fixtures";
import { useShell } from "../lib/shell-context";
import {
  Button,
  Card,
  VerdictBadge,
  Badge,
  SectionTitle,
  Divider,
} from "../ui";
import { cn, formatNumber } from "../lib/utils";
import { TOOL_ICON } from "../shell/chrome";

/* =============================================================
   HERO
   ============================================================= */

function Hero({ navigate }: { navigate: (to: string) => void }) {
  /* "Browse all five tools" scrolls to the cards. It used to navigate to IOC
     Lookup, so a button whose label promised five tools delivered one of
     them — and the five cards it was describing were below the fold. */
  const scrollToTools = () => {
    document
      .getElementById("sc-tools")
      ?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <section className="relative overflow-hidden">
      <div className="sc-grid-bg" />
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            "radial-gradient(ellipse 70% 50% at 50% -8%, var(--tool-tint-2), transparent 70%)",
        }}
      />

      <div className="relative max-w-6xl mx-auto px-6 pt-20 pb-16 text-center">
        <div
          className="sc-anim-up inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full mb-7"
          style={{
            background: "var(--tool-tint)",
            border: "1px solid var(--tool-tint-2)",
          }}
        >
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{ background: "var(--color-ok)", animation: "sc-pulse-ring 2s infinite" }}
          />
          <span
            className="text-[12px] font-bold tracking-[0.06em] uppercase"
            style={{ color: "var(--tool-accent)" }}
          >
            Five tools · one platform · one bill of work
          </span>
        </div>

        <h1
          className="sc-anim-up text-[clamp(2.4rem,6vw,4.2rem)] font-black leading-[1.05] tracking-[-0.035em]"
          style={{ animationDelay: "60ms" }}
        >
          Every security tool you need,
          <br />
          <span
            style={{
              background:
                "linear-gradient(120deg, var(--tool-accent), var(--tool-accent-2))",
              WebkitBackgroundClip: "text",
              backgroundClip: "text",
              color: "transparent",
            }}
          >
            in one console
          </span>
        </h1>

        <p
          className="sc-anim-up mt-6 text-[17px] leading-relaxed max-w-2xl mx-auto"
          style={{ animationDelay: "120ms", color: "var(--color-ink-3)" }}
        >
          SecConflux is a unified SecOps utility. Binary analysis, indicator enrichment, event
          log forensics, phishing triage and detection engineering — five tools that used to
          live in five tabs, now sharing one interface, one design language and one body of
          evidence.
        </p>

        <div
          className="sc-anim-up mt-9 flex flex-wrap items-center justify-center gap-3"
          style={{ animationDelay: "180ms" }}
        >
          <Button
            variant="primary"
            size="lg"
            icon="sparkles"
            onClick={() => navigate("/t/malware")}
          >
            Start with Malware Analyzer
          </Button>
          <Button variant="secondary" size="lg" icon="grid" onClick={() => scrollToTools()}>
            Browse all five tools
          </Button>
        </div>

        <p
          className="sc-anim-up mt-5 text-[12.5px] flex items-center justify-center gap-2"
          style={{ animationDelay: "220ms", color: "var(--color-ink-4)" }}
        >
          <Icon name="lock" size={12} />
          Runs entirely on your machine. No data leaves the host.
        </p>
      </div>

      <Marquee />
    </section>
  );
}

/** A slow horizontal scroll of real capability counts. *
 *  The track is rendered TWICE as two sibling elements, each carrying its own
 *  internal gap. Animating one element that contains `[...items, ...items]`
 *  by -50% does not loop seamlessly, because a flex `gap` also sits after the
 *  LAST child: the second copy is therefore one gap longer than the first,
 *  and the loop jumps by that gap on every cycle. Two equal tracks removes
 *  the arithmetic entirely. */
function Marquee() {
  const items = [
    "812+ YARA rules",
    "40+ intel sources",
    "41k events per investigation",
    "8 SIEM dialects",
    "SPF · DKIM · DMARC",
    "5 threat feeds",
    "468 backend tests",
    "STIX · MISP · SIEM export",
    "FTS5 full-text search",
    "MITRE ATT&CK mapped",
  ];
  const track = (
    <div className="flex items-center gap-8 pr-8 py-3.5 shrink-0">
      {items.map((t) => (
        <span
          key={t}
          className="flex items-center gap-2.5 text-[12.5px] font-semibold whitespace-nowrap"
          style={{ color: "var(--color-ink-4)" }}
        >
          <span
            className="w-1 h-1 rounded-full"
            style={{ background: "var(--tool-accent)", opacity: 0.6 }}
          />
          {t}
        </span>
      ))}
    </div>
  );
  return (
    <div
      className="relative border-y overflow-hidden sc-fade-both"
      style={{
        borderColor: "var(--color-line)",
        background: "var(--color-canvas-2)",
      }}
    >
      <div
        className="flex items-center w-max"
        style={{ animation: "sc-marquee 42s linear infinite" }}
      >
        {track}
        {track}
      </div>
      <style>{`@keyframes sc-marquee{from{transform:translateX(0)}to{transform:translateX(-50%)}}`}</style>
    </div>
  );
}

/* =============================================================
   TOOL CARDS
   ============================================================= */

function ToolCard({ tool, navigate }: { tool: (typeof TOOLS)[number]; navigate: (to: string) => void }) {
  return (
    <Card
      interactive
      onClick={() => navigate(tool.path)}
      className="sc-accent-edge group overflow-hidden"
    >
      <div className="p-5">
        <div className="flex items-start justify-between gap-3 mb-4">
          <span
            className="grid place-items-center w-11 h-11 rounded-[var(--radius-md)] transition-transform duration-300 group-hover:scale-105"
            style={{
              background: `color-mix(in srgb, ${tool.accent} 14%, transparent)`,
              border: `1px solid color-mix(in srgb, ${tool.accent} 30%, transparent)`,
              color: tool.accent,
            }}
          >
            <Icon name={TOOL_ICON[tool.id]} size={21} strokeWidth={1.6} />
          </span>
          <kbd
            className="px-2 h-6 grid place-items-center rounded-[5px] mono text-[11px]"
            style={{
              background: "var(--color-surface-2)",
              border: "1px solid var(--color-line-2)",
              color: "var(--color-ink-4)",
            }}
          >
            {tool.hotkey}
          </kbd>
        </div>

        <h3 className="text-[17px] font-extrabold tracking-[-0.01em]">{tool.name}</h3>
        <p
          className="text-[12.5px] font-semibold mt-0.5 mb-3"
          style={{ color: tool.accent }}
        >
          {tool.tagline}
        </p>
        <p className="text-[13px] leading-relaxed" style={{ color: "var(--color-ink-3)" }}>
          {tool.blurb}
        </p>

        <div className="flex flex-wrap gap-1.5 mt-4">
          {tool.tags.slice(0, 3).map((t) => (
            <Badge key={t}>{t}</Badge>
          ))}
          {tool.tags.length > 3 && (
            <Badge tone="accent">+{tool.tags.length - 3} more</Badge>
          )}
        </div>

        <div
          className="flex items-center gap-4 mt-5 pt-4 flex-wrap"
          style={{ borderTop: "1px solid var(--color-line)" }}
        >
          {tool.stats.map((s) => (
            <div key={s.label} className="min-w-0">
              <div className="text-[15px] font-extrabold leading-none">{s.value}</div>
              <div
                className="text-[10.5px] font-semibold tracking-[0.05em] uppercase mt-1 truncate"
                style={{ color: "var(--color-ink-4)" }}
              >
                {s.label}
              </div>
            </div>
          ))}
          <span
            className="ml-auto inline-flex items-center gap-1.5 text-[13px] font-bold shrink-0"
            style={{ color: tool.accent }}
          >
            Open
            <Icon
              name="arrow-right"
              size={14}
              className="transition-transform duration-200 group-hover:translate-x-0.5"
            />
          </span>
        </div>
      </div>
    </Card>
  );
}

/* =============================================================
   HOW SWITCHING WORKS
   ============================================================= */

const SWITCH_STEPS = [
  {
    icon: "grid" as const,
    title: "Two main tabs, always centred",
    body: "Every tool has exactly two main tabs in the centre of the header: the surface you are on, and the working surface. Overview and Investigation, Dashboard and Investigation, Studio and History. The positions never move, so you always know what half of the header means.",
  },
  {
    icon: "layers" as const,
    title: "Everything else becomes a chip",
    body: "The sections inside a tool — Static Analysis, Threat Intel, Behavioral, the IOCs — are chips on the right of the same header, next to that tool's own action button. Nothing gets a second strip below the header, so the only thing on screen that moves is the header.",
  },
  {
    icon: "home" as const,
    title: "The brand is the tool list",
    body: "SecConflux and SecOps Utility at the top left open the full list on click: Home first, then all five tools, with the current one ticked. There is no second control beside it, because two buttons opening the same menu is one button too many.",
  },
  {
    icon: "command" as const,
    title: "Ctrl+M from anywhere",
    body: "The command palette reaches every tool, every section and the platform actions without touching the mouse. It filters as you type, and the number key for each tool is shown on the right.",
  },
  {
    icon: "zap" as const,
    title: "Number keys 1 to 5",
    body: "Press 1 for Malware Analyzer, 2 for IOC Lookup, 3 for Event Analyzer, 4 for Phishing Detector, 5 for RuleForge. Switching is one keystroke from any screen, not just from the overview.",
  },
  {
    icon: "git-branch" as const,
    title: "Evidence is shared",
    body: "An indicator found by one tool is available to the others. An IOC in a malware scan can be enriched in IOC Lookup without retyping it, and an email attachment hash can be looked up directly.",
  },
];

function HowItWorks() {
  return (
    <section className="max-w-6xl mx-auto px-6 py-20">
      <div className="text-center mb-12">
        <Badge tone="accent" className="mb-4 inline-flex">
          Getting around
        </Badge>
        <h2 className="text-[clamp(1.6rem,3.4vw,2.3rem)] font-extrabold tracking-[-0.025em]">
          How switching between tools works
        </h2>
        <p className="mt-3 text-[15px] max-w-2xl mx-auto" style={{ color: "var(--color-ink-3)" }}>
          Six ways to move between five tools. Pick whichever one you already have in your
          hands.
        </p>
      </div>

      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {SWITCH_STEPS.map((s) => (
          <Card key={s.title} className="p-5">
            <span
              className="grid place-items-center w-10 h-10 rounded-[var(--radius-md)] mb-3.5"
              style={{
                background: "var(--tool-tint)",
                border: "1px solid var(--tool-tint-2)",
                color: "var(--tool-accent)",
              }}
            >
              <Icon name={s.icon} size={19} strokeWidth={1.6} />
            </span>
            <h3 className="text-[14.5px] font-bold">{s.title}</h3>
            <p
              className="mt-1.5 text-[13px] leading-relaxed"
              style={{ color: "var(--color-ink-3)" }}
            >
              {s.body}
            </p>
          </Card>
        ))}
      </div>

      <div
        className="mt-6 p-5 rounded-[var(--radius-lg)]"
        style={{
          background: "var(--color-surface-2)",
          border: "1px solid var(--color-line)",
        }}
      >
        <div className="flex items-start gap-3.5">
          <span
            className="grid place-items-center w-9 h-9 rounded-[var(--radius-sm)] shrink-0"
            style={{ background: "var(--tool-tint)", color: "var(--tool-accent)" }}
          >
            <Icon name="info" size={17} />
          </span>
          <div>
            <h4 className="text-[14px] font-bold mb-1.5">
              What SecConflux is, in one paragraph
            </h4>
            <p className="text-[13.5px] leading-relaxed" style={{ color: "var(--color-ink-2)" }}>
              SecConflux is the consolidated front end for five independent security tools
              built by the same team. It does not replace them or merge their logic. It gives
              them one shell, one design language, one way to be reached, and a shared
              evidence trail. When you open SecConflux you get one product; when you leave, you
              get five tools that are still five tools.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

/* =============================================================
   SHARED EVIDENCE  —  the argument for one platform
   ============================================================= */

function SharedEvidence() {
  const [active, setActive] = useState(0);
  const row = SHARED_IOCS[active];

  return (
    <section className="py-20" style={{ background: "var(--color-canvas-2)", borderBlock: "1px solid var(--color-line)" }}>
      <div className="max-w-6xl mx-auto px-6">
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <div>
            <Badge tone="accent" className="mb-4 inline-flex">
              Why one platform
            </Badge>
            <h2 className="text-[clamp(1.6rem,3.4vw,2.3rem)] font-extrabold tracking-[-0.025em]">
              The same indicator, seen by four tools
            </h2>
            <p className="mt-3.5 text-[15px] leading-relaxed" style={{ color: "var(--color-ink-3)" }}>
              An analyst investigating a suspicious email ends up with an IP address. That same
              address turns up in a malware sample, in Windows event logs, and in an
              enrichment run. Four tools, four verdicts, one conclusion.
            </p>
            <p
              className="mt-3.5 text-[15px] leading-relaxed"
              style={{ color: "var(--color-ink-3)" }}
            >
              SecConflux keeps those findings connected instead of leaving them in four
              browser tabs. Pick an indicator to see which tools contributed to it.
            </p>

            <div className="mt-6 flex flex-col gap-1.5">
              {SHARED_IOCS.map((s, i) => (
                <button
                  key={s.value}
                  onClick={() => setActive(i)}
                  className={cn(
                    "flex items-center gap-3 px-3.5 py-2.5 rounded-[var(--radius-md)] text-left transition-colors",
                    i === active ? "" : "hover:bg-[var(--color-surface-2)]",
                  )}
                  style={
                    i === active
                      ? { background: "var(--tool-tint)", border: "1px solid var(--tool-tint-2)" }
                      : { border: "1px solid transparent" }
                  }
                >
                  <Badge tone="neutral" mono>
                    {s.type}
                  </Badge>
                  <span className="font-mono text-[13px] font-semibold truncate flex-1 min-w-0">
                    {s.value}
                  </span>
                  <span className="flex items-center gap-1 shrink-0">
                    {s.tools.map((t) => (
                      <span
                        key={t}
                        title={TOOLS.find((x) => x.id === t)?.name}
                        className="grid place-items-center w-6 h-6 rounded-[5px]"
                        style={{
                          background: `color-mix(in srgb, ${
                            TOOLS.find((x) => x.id === t)?.accent
                          } 16%, transparent)`,
                          color: TOOLS.find((x) => x.id === t)?.accent,
                        }}
                      >
                        <Icon name={TOOL_ICON[t]} size={12} />
                      </span>
                    ))}
                  </span>
                </button>
              ))}
            </div>
          </div>

          <Card glow className="overflow-hidden">
            <div
              className="px-4 py-3 border-b flex items-center justify-between"
              style={{ borderColor: "var(--color-line)", background: "var(--color-surface-2)" }}
            >
              <span className="flex items-center gap-2 text-[13px] font-bold">
                <span style={{ color: "var(--tool-accent)", display: "flex" }}>
                  <Icon name="git-branch" size={14} />
                </span>
                Contributing tools
              </span>
              <VerdictBadge verdict={row.verdict} />
            </div>
            <div className="p-5">
              <div className="font-mono text-[15px] font-bold mb-1 break-all">{row.value}</div>
              <div
                className="text-[12px] font-semibold mb-5"
                style={{ color: "var(--color-ink-4)" }}
              >
                {row.type} · observed {row.hits} times
              </div>

              <div className="flex flex-col gap-2.5">
                {row.tools.map((t) => {
                  const tool = TOOLS.find((x) => x.id === t)!;
                  return (
                    <div
                      key={t}
                      className="flex items-center gap-3 p-3 rounded-[var(--radius-md)]"
                      style={{ background: "var(--color-surface-2)", border: "1px solid var(--color-line)" }}
                    >
                      <span
                        className="grid place-items-center w-8 h-8 rounded-[var(--radius-sm)] shrink-0"
                        style={{
                          background: `color-mix(in srgb, ${tool.accent} 14%, transparent)`,
                          color: tool.accent,
                        }}
                      >
                        <Icon name={TOOL_ICON[t]} size={15} />
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="text-[13px] font-bold truncate">{tool.name}</div>
                        <div
                          className="text-[12px] truncate"
                          style={{ color: "var(--color-ink-4)" }}
                        >
                          {t === "malware" && "Extracted from the sample string table"}
                          {t === "ioc" && "Enriched against 33 sources, 27 returned malicious"}
                          {t === "events" && "Seen in Sysmon NetworkConnect and a certutil fetch"}
                          {t === "phishing" && "C2 host in the confirm link and the QR payload"}
                        </div>
                      </div>
                      <span
                        className="w-1.5 h-1.5 rounded-full shrink-0"
                        style={{ background: tool.accent }}
                      />
                    </div>
                  );
                })}
              </div>
            </div>
          </Card>
        </div>
      </div>
    </section>
  );
}

/* =============================================================
   ACTIVITY
   ============================================================= */

function Activity() {
  return (
    <section className="max-w-6xl mx-auto px-6 py-20">
      <SectionTitle
        sub="Every tool writes to the same activity trail, so a single view shows what has been looked at across the platform."
        right={
          <Button variant="ghost" size="sm" icon="refresh">
            Refresh
          </Button>
        }
      >
        Platform activity
      </SectionTitle>

      <Card className="overflow-hidden">
        {ACTIVITY.map((a, i) => {
          const tool = TOOLS.find((t) => t.id === a.tool)!;
          const dots: Record<string, string> = {
            ok: "var(--color-ok)",
            warn: "var(--color-warn)",
            bad: "var(--color-bad)",
            info: "var(--color-info)",
          };
          return (
            <div
              key={a.id}
              className="flex items-start gap-3.5 px-4 py-3.5"
              style={{
                borderTop: i === 0 ? "none" : "1px solid var(--color-line)",
              }}
            >
              <span
                className="grid place-items-center w-8 h-8 rounded-[var(--radius-sm)] shrink-0 mt-0.5"
                style={{
                  background: `color-mix(in srgb, ${tool.accent} 13%, transparent)`,
                  color: tool.accent,
                }}
              >
                <Icon name={TOOL_ICON[a.tool]} size={15} />
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[13.5px] font-bold">{a.title}</span>
                  <span
                    className="w-1.5 h-1.5 rounded-full"
                    style={{ background: dots[a.tone] }}
                  />
                </div>
                <div className="text-[12.5px] mt-0.5" style={{ color: "var(--color-ink-3)" }}>
                  {a.detail}
                </div>
              </div>
              <div className="text-right shrink-0">
                <div
                  className="text-[11.5px] font-semibold"
                  style={{ color: "var(--color-ink-4)" }}
                >
                  {tool.name}
                </div>
              </div>
            </div>
          );
        })}
      </Card>
    </section>
  );
}

/* =============================================================
   FINAL CTA
   ============================================================= */

function FinalCta({ navigate }: { navigate: (to: string) => void }) {
  const { setTourOpen } = useShell();
  return (
    <section className="max-w-6xl mx-auto px-6 pb-24">
      <Card glow className="relative overflow-hidden">
        <div className="sc-grid-bg opacity-40" />
        <div className="relative p-10 md:p-14 text-center">
          <h2 className="text-[clamp(1.5rem,3.2vw,2.15rem)] font-extrabold tracking-[-0.025em]">
            Five tools are installed and ready
          </h2>
          <p
            className="mt-3.5 text-[15px] max-w-2xl mx-auto leading-relaxed"
            style={{ color: "var(--color-ink-3)" }}
          >
            SecConflux has already indexed {formatNumber(5)} tools,
            {" "}{formatNumber(4_882)} historical records and
            {" "}{formatNumber(SHARED_IOCS.length)} shared indicators. Nothing is left to
            configure.
          </p>
          <div className="mt-7 flex flex-wrap items-center justify-center gap-3">
<Button variant="primary" size="lg" icon="sparkles" onClick={() => navigate("/t/malware")}>
          Open the platform
        </Button>
        <Button variant="secondary" size="lg" icon="play" onClick={() => setTourOpen(true)}>
          Take the guided tour
        </Button>
          </div>
        </div>
      </Card>
    </section>
  );
}

/* =============================================================
   PAGE
   ============================================================= */

export function Landing({ navigate }: { navigate: (to: string) => void }) {
  const { setTourOpen } = useShell();
  return (
    <div className="sc-anim-in">
      <Hero navigate={navigate} />

      <section id="sc-tools" className="max-w-6xl mx-auto px-6 py-20 scroll-mt-28">
        <div className="text-center mb-12">
          <Badge tone="accent" className="mb-4 inline-flex">
            The toolbox
          </Badge>
          <h2 className="text-[clamp(1.6rem,3.4vw,2.3rem)] font-extrabold tracking-[-0.025em]">
            Five tools, one console
          </h2>
          <p
            className="mt-3 text-[15px] max-w-2xl mx-auto"
            style={{ color: "var(--color-ink-3)" }}
          >
            Each one is a complete tool. The point of SecConflux is that you do not have to
            choose between them.
          </p>
        </div>

        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {TOOLS.map((t) => (
            <ToolCard key={t.id} tool={t} navigate={navigate} />
          ))}

          <Card
            interactive
            onClick={() => {
              setTourOpen(true);
            }}
            className="flex flex-col items-center justify-center text-center p-8"
            style={{ borderStyle: "dashed" }}
          >
            <span
              className="grid place-items-center w-12 h-12 rounded-[var(--radius-lg)] mb-4"
              style={{
                background: "var(--tool-tint)",
                border: "1px solid var(--tool-tint-2)",
                color: "var(--tool-accent)",
              }}
            >
              <Icon name="help" size={22} strokeWidth={1.5} />
            </span>
            <h3 className="text-[15.5px] font-bold">New to SecConflux?</h3>
            <p
              className="mt-1.5 text-[13px] max-w-[220px] leading-relaxed"
              style={{ color: "var(--color-ink-4)" }}
            >
              Take a 90-second tour of the switcher, the shared evidence and the export
              options.
            </p>
            <span
              className="mt-4 inline-flex items-center gap-1.5 text-[13px] font-bold"
              style={{ color: "var(--tool-accent)" }}
            >
              Start the tour
              <Icon name="arrow-right" size={14} />
            </span>
          </Card>
        </div>

        <Divider />
        <div
          className="grid sm:grid-cols-4 gap-4 text-center"
        >
          {[
            { v: "5", l: "Tools unified" },
            { v: "40+", l: "Intel sources" },
            { v: "8", l: "SIEM dialects" },
            { v: "0", l: "Data leaves the host" },
          ].map((s) => (
            <div key={s.l}>
              <div className="text-[30px] font-black tracking-tight leading-none">{s.v}</div>
              <div
                className="text-[12px] font-semibold tracking-[0.05em] uppercase mt-1.5"
                style={{ color: "var(--color-ink-4)" }}
              >
                {s.l}
              </div>
            </div>
          ))}
        </div>
      </section>

      <HowItWorks />
      <SharedEvidence />
      <Activity />
      <FinalCta navigate={navigate} />
    </div>
  );
}
