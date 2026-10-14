import { useEffect, useState } from "react";
import { Icon } from "../lib/icons";
import { TOOLS, LANDING_ORDER, MAIN_TABS, SUB_TABS } from "../lib/tools";
import { useShell } from "../lib/shell-context";
import { Button } from "../ui";
import { TOOL_ICON } from "./chrome";
import { useScrollLock } from "../lib/useScrollLock";

interface Slide {
  kicker: string;
  title: string;
  body: string;
  visual?: React.ReactNode;
}

export function Tour({ navigate }: { navigate: (to: string) => void }) {
  const { tourOpen, setTourOpen } = useShell();
  const [step, setStep] = useState(0);

  useEffect(() => {
    if (tourOpen) setStep(0);
  }, [tourOpen]);

  useEffect(() => {
    if (!tourOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setTourOpen(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [tourOpen, setTourOpen]);

  useScrollLock(tourOpen);

  if (!tourOpen) return null;

const slides: Slide[] = [
    {
      kicker: "Welcome",
      title: "This is SecConflux",
      body: "Five security tools that used to be five separate applications now share one interface, one design language and one body of evidence. This tour takes about ninety seconds and you can leave at any point with Escape.",
      visual: <BrandStack />,
    },
    {
      kicker: "Step 1 of 5",
      title: "The brand opens the tool list",
      body: "SecConflux and SecOps Utility sit at the top left of every screen, and clicking them drops the full list: Home first, then all five tools, with the one you are on already ticked. The mark keeps its own colour everywhere, so you can always tell the platform from the tool you are in.",
      visual: <SwitcherDemo />,
    },
    {
      kicker: "Step 2 of 5",
      title: "Two main tabs, centred",
      body: "Every tool has exactly two main tabs in the centre of the header: the first describes the tool, the second is where the work happens. Malware Analyzer calls them Overview and Investigation, IOC Lookup Overview and Lookup, Event Analyzer Overview and Investigation, Phishing Detector Overview and Analysis, RuleForge Overview and Workshop.",
      visual: <HeaderDemo />,
    },
    {
      kicker: "Step 3 of 5",
      title: "Sections become chips on the right",
      body: "The second row of the header is the tool's own tab list — its real tabs, in its own order — plus that tool's action button on the far right. This row only exists on the second tab, because those sections belong to the work, not to the description.",
      visual: <ChipDemo />,
    },
    {
      kicker: "Step 4 of 5",
      title: "Every tool opens by explaining itself",
      body: "The first tab is a landing page for that tool: what it is, the terminal window showing the JSON it returns, the numbers it works to, the capabilities, and a numbered workflow of how to use it. Four of the five share this shape; RuleForge has its own because its job is authoring rather than inspection.",
      visual: <LandingDemo />,
    },
    {
      kicker: "Step 5 of 5",
      title: "Or reach anything with Ctrl+M",
      body: "The command palette filters as you type, wraps at both ends with the arrow keys, and scrolls the highlighted row into view. On a number pad, 0 goes Home and 1 through 5 reach the five tools from any screen.",
      visual: <PaletteDemo />,
    },
    {
      kicker: "Also worth knowing",
      title: "Findings stay connected",
      body: "An indicator found by one tool is available to the others. The same IP address can appear in a malware scan, in Windows event logs and in an enrichment run, and SecConflux shows you all of them together instead of four separate answers.",
      visual: <ShareDemo />,
    },
  ];

  const s = slides[step];
  const last = step === slides.length - 1;

  return (
    <div
      className="fixed inset-0 z-[350] flex items-center justify-center p-4 sc-anim-in"
      style={{ background: "rgb(0 0 0 / 0.66)", backdropFilter: "blur(7px)" }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) setTourOpen(false);
      }}
    >
      <div
        className="sc-anim-pop w-full overflow-hidden"
        style={{
          maxWidth: 720,
          background: "var(--color-surface)",
          border: "1px solid var(--color-line-2)",
          borderRadius: "var(--radius-xl)",
          boxShadow: "var(--shadow-lg)",
        }}
      >
        <div
          className="flex items-center justify-between px-6 py-4 border-b"
          style={{ borderColor: "var(--color-line)" }}
        >
          <div className="flex items-center gap-3">
            <span
              className="grid place-items-center w-9 h-9 rounded-[var(--radius-md)]"
              style={{
                background: "var(--tool-tint)",
                border: "1px solid var(--tool-tint-2)",
                color: "var(--tool-accent)",
              }}
            >
              <Icon name="sparkles" size={18} />
            </span>
            <div>
              <div
                className="text-[10.5px] font-bold tracking-[0.1em] uppercase"
                style={{ color: "var(--tool-accent)" }}
              >
                {s.kicker}
              </div>
              <div
                className="text-[12px] font-semibold"
                style={{ color: "var(--color-ink-4)" }}
              >
                SecConflux guided tour
              </div>
            </div>
          </div>
          <button
            onClick={() => setTourOpen(false)}
            className="p-1.5 -m-1 rounded-[var(--radius-sm)] text-[var(--color-ink-4)] hover:text-[var(--color-ink)] hover:bg-[var(--color-surface-3)] transition-colors"
            aria-label="Close tour"
          >
            <Icon name="x" size={17} />
          </button>
        </div>

        <div className="p-6">
          <h2 className="text-[21px] font-extrabold tracking-[-0.02em]">{s.title}</h2>
          <p
            className="mt-2.5 text-[14px] leading-relaxed"
            style={{ color: "var(--color-ink-3)" }}
          >
            {s.body}
          </p>

          <div className="mt-6">{s.visual}</div>
        </div>

        <div
          className="flex items-center justify-between gap-4 px-6 py-4"
          style={{ background: "var(--color-surface-2)", borderTop: "1px solid var(--color-line)" }}
        >
          <div className="flex items-center gap-1.5">
            {slides.map((_, i) => (
              <button
                key={i}
                onClick={() => setStep(i)}
                aria-label={`Slide ${i + 1}`}
                className="h-1.5 rounded-full transition-all duration-300"
                style={{
                  width: i === step ? 22 : 6,
                  background: i === step ? "var(--tool-accent)" : "var(--color-line-2)",
                }}
              />
            ))}
          </div>

          <div className="flex items-center gap-2">
            {step > 0 && (
              <Button variant="ghost" size="sm" onClick={() => setStep((v) => v - 1)}>
                Back
              </Button>
            )}
            {last ? (
              <Button
                variant="primary"
                size="sm"
                iconRight="arrow-right"
                onClick={() => {
                  setTourOpen(false);
                  navigate(TOOLS[0].path);
                }}
              >
                Open Malware Analyzer
              </Button>
            ) : (
              <Button
                variant="primary"
                size="sm"
                iconRight="chevron-right"
                onClick={() => setStep((v) => v + 1)}
              >
                Next
              </Button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

/* =============================================================
   TOUR VISUALS

   These are miniature reproductions of the real chrome, not illustrations
   of it. If the header changes, these change with it, because they render
   the same components.
   ============================================================= */

function BrandStack() {
  return (
    <div
      className="rounded-[var(--radius-lg)] overflow-hidden"
      style={{ border: "1px solid var(--color-line)" }}
    >
      <div
        className="flex items-center gap-2.5 px-3.5 h-11"
        style={{ background: "var(--color-canvas-2)", borderBottom: "1px solid var(--color-line)" }}
      >
        <span
          className="grid place-items-center w-6 h-6 rounded-[5px]"
          style={{ background: "var(--tool-tint)", color: "var(--tool-accent)" }}
        >
          <Icon name="home" size={13} />
        </span>
        <span className="text-[12.5px] font-bold">Home</span>
        <Icon name="chevron-down" size={12} className="text-[var(--color-ink-4)]" />
      </div>
      <div className="p-2.5 flex flex-col gap-1.5">
        {TOOLS.map((t, i) => (
          <div
            key={t.id}
            className="flex items-center gap-2.5 px-2.5 py-2 rounded-[var(--radius-sm)]"
            style={{
              background: i === 0 ? "var(--tool-tint)" : "var(--color-surface-2)",
            }}
          >
            <span
              className="grid place-items-center w-6 h-6 rounded-[4px]"
              style={{
                background: `color-mix(in srgb, ${t.accent} 14%, transparent)`,
                color: t.accent,
              }}
            >
              <Icon name={TOOL_ICON[t.id]} size={12} />
            </span>
            <span className="text-[12.5px] font-semibold flex-1">{t.name}</span>
            <span
              className="mono text-[10px] px-1.5 h-5 grid place-items-center rounded-[4px]"
              style={{
                background: "var(--color-surface-3)",
                border: "1px solid var(--color-line)",
                color: "var(--color-ink-4)",
              }}
            >
              {i + 1}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function SwitcherDemo() {
  return (
    <div
      className="rounded-[var(--radius-lg)] overflow-hidden"
      style={{ border: "1px solid var(--color-line)" }}
    >
      <div
        className="flex items-center gap-2.5 px-3.5 h-12"
        style={{ background: "var(--color-canvas-2)", borderBottom: "1px solid var(--color-line)" }}
      >
        <span style={{ color: "var(--tool-accent)", display: "flex" }}>
          <Icon name="zap" size={16} />
        </span>
        <div className="leading-none">
          <div className="text-[13px] font-extrabold">SecConflux</div>
          <div
            className="text-[9px] font-bold tracking-[0.1em] uppercase"
            style={{ color: "var(--color-ink-4)" }}
          >
            SecOps Utility
          </div>
        </div>
        <Icon name="chevron-down" size={12} style={{ color: "var(--color-ink-4)", marginLeft: 2 }} />
        <span
          className="ml-1 px-2 py-0.5 rounded-[5px] text-[10.5px] font-bold"
          style={{ background: "var(--tool-tint)", color: "var(--tool-accent)" }}
        >
          click here
        </span>
      </div>
      <div
        className="px-4 py-3 text-[12px]"
        style={{ background: "var(--color-surface)", color: "var(--color-ink-4)" }}
      >
        One control opens the whole list. This is it.
      </div>
    </div>
  );
}

/** A faithful miniature of the real header: brand left, Home plus the five
 *  tools centred, theme toggle alone on the right, and the active tool's
 *  sections on a second row inside the same bar. */
function HeaderDemo() {
  const sections = [...MAIN_TABS.malware, ...SUB_TABS.malware];
  return (
    <div
      className="rounded-[var(--radius-lg)] overflow-hidden"
      style={{ border: "1px solid var(--color-line-2)", boxShadow: "var(--shadow-md)" }}
    >
      <div
        className="flex items-center gap-2 px-3 h-11"
        style={{ background: "var(--color-canvas-2)", borderBottom: "1px solid var(--color-line)" }}
      >
        <span style={{ color: "var(--tool-accent)", display: "flex" }}>
          <Icon name="zap" size={14} />
        </span>
        <div className="leading-none shrink-0">
          <div className="text-[11.5px] font-extrabold">SecConflux</div>
          <div
            className="text-[8px] font-bold tracking-[0.12em] uppercase"
            style={{ color: "var(--color-ink-4)" }}
          >
            SecOps Utility
          </div>
        </div>

        <div className="flex-1 flex justify-center min-w-0">
          <div
            className="flex items-center gap-0.5 p-0.5 rounded-[6px]"
            style={{ background: "var(--color-surface-2)", border: "1px solid var(--color-line)" }}
          >
            <span
              className="inline-flex items-center gap-1 h-6 px-2 rounded-[4px] text-[11px] font-semibold shrink-0"
              style={{
                background: "var(--tool-tint)",
                color: "var(--color-ink)",
                boxShadow: "inset 0 0 0 1px var(--tool-tint-2)",
              }}
            >
              <Icon name="home" size={11} />
              Home
            </span>
            <span className="w-px h-4 mx-0.5" style={{ background: "var(--color-line-2)" }} />
            {TOOLS.map((t, i) => (
              <span
                key={t.id}
                className="inline-flex items-center gap-1 h-6 px-2 rounded-[4px] text-[11px] font-semibold shrink-0"
                style={
                  i === 0
                    ? {
                        background: "var(--tool-tint)",
                        color: "var(--color-ink)",
                        boxShadow: "inset 0 0 0 1px var(--tool-tint-2)",
                      }
                    : { color: "var(--color-ink-3)" }
                }
              >
                <span style={{ color: i === 0 ? t.accent : "var(--color-ink-4)" }}>
                  <Icon name={TOOL_ICON[t.id]} size={11} />
                </span>
                {t.name.split(" ")[0]}
                <span
                  className="mono text-[9px] px-1 h-3.5 grid place-items-center rounded-[2px]"
                  style={{ background: "var(--color-surface-3)", color: "var(--color-ink-4)" }}
                >
                  {i + 1}
                </span>
              </span>
            ))}
          </div>
        </div>

        <span style={{ color: "var(--color-ink-4)", display: "flex" }}>
          <Icon name="moon" size={13} />
        </span>
      </div>

      <div
        className="flex items-center justify-center h-9 border-t"
        style={{ borderColor: "var(--color-line)", background: "var(--color-canvas-2)" }}
      >
        <div className="flex items-center gap-0.5">
          {sections.map((s, i) => (
            <span
              key={s.id}
              className="relative inline-flex items-center gap-1 px-2.5 h-full text-[11px] font-semibold"
              style={{ color: i === 0 ? "var(--tool-accent)" : "var(--color-ink-3)" }}
            >
              <Icon name={(s.icon ?? "grid") as never} size={11} />
              {s.label}
              {i === 0 && (
                <span
                  className="absolute inset-x-1.5 bottom-0 h-[2px] rounded-full"
                  style={{ background: "var(--tool-accent)" }}
                />
              )}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

/** A miniature of the header's right rail: the tool's section chips, its own
 *  action button, then the theme toggle. */
function ChipDemo() {
  const chips = [
    ["Events", "list"],
    ["Timeline", "activity"],
    ["IOCs", "target"],
    ["Sigma", "check"],
    ["Channels", "server"],
  ] as const;
  return (
    <div
      className="rounded-[var(--radius-lg)] overflow-hidden"
      style={{ border: "1px solid var(--color-line-2)", boxShadow: "var(--shadow-md)" }}
    >
      <div
        className="flex items-center gap-1.5 px-3 h-11 justify-end"
        style={{ background: "var(--color-canvas-2)", borderBottom: "1px solid var(--color-line)" }}
      >
        {chips.map(([label, ic], i) => (
          <span
            key={label}
            className="inline-flex items-center gap-1.5 h-7 px-2.5 rounded-[6px] text-[12.5px] font-semibold leading-none border"
            style={{
              background: i === 0 ? "var(--tool-tint)" : "transparent",
              borderColor: i === 0 ? "var(--tool-tint-2)" : "transparent",
              color: i === 0 ? "var(--tool-accent)" : "var(--color-ink-3)",
            }}
          >
            <Icon name={ic as never} size={13} />
            {label}
          </span>
        ))}
        <span
          className="ml-1.5 inline-flex items-center gap-1.5 h-8 px-3 rounded-[6px] text-[13px] font-bold text-white"
          style={{ background: "linear-gradient(135deg, var(--tool-accent), var(--tool-accent-2))" }}
        >
          <Icon name="upload" size={14} />
          Ingest EVTX
        </span>
        <span style={{ color: "var(--color-ink-4)", display: "flex" }}>
          <Icon name="moon" size={15} />
        </span>
      </div>
      <div
        className="px-4 py-3 text-[12px]"
        style={{ background: "var(--color-surface)", color: "var(--color-ink-4)" }}
      >
        Event Analyzer's sections, its action, and the theme toggle. One row, nothing below it.
      </div>
    </div>
  );
}

/** A miniature of a tool's landing page, because slide 4 is about that
 *  shape and a description of it is weaker than the thing itself. */
function LandingDemo() {
  return (
    <div
      className="rounded-[var(--radius-lg)] overflow-hidden"
      style={{ border: "1px solid var(--color-line-2)", boxShadow: "var(--shadow-md)" }}
    >
      <div className="flex items-center gap-2 px-3 h-9" style={{ background: "var(--color-canvas-2)", borderBottom: "1px solid var(--color-line)" }}>
        <span className="w-1.5 h-1.5 rounded-full" style={{ background: "var(--tool-accent)" }} />
        <span className="text-[11px] font-bold tracking-[0.1em] uppercase" style={{ color: "var(--tool-accent)" }}>
          Binary threat analysis platform
        </span>
      </div>
      <div className="p-4 grid sm:grid-cols-[1fr_180px] gap-4 items-center">
        <div className="min-w-0">
          <div className="text-[19px] font-black leading-[1.05] tracking-[-0.03em]">
            Dissect. Detect.{" "}
            <span
              style={{
                background: "linear-gradient(100deg, var(--tool-accent), var(--tool-accent-2))",
                WebkitBackgroundClip: "text",
                backgroundClip: "text",
                color: "transparent",
              }}
            >
              Defend.
            </span>
          </div>
          <p className="mt-2 text-[11.5px] leading-relaxed" style={{ color: "var(--color-ink-4)" }}>
            Upload a file. Get a full threat report in seconds — static analysis, YARA, IOCs,
            and threat intel from 5 providers.
          </p>
          <div className="mt-3 flex gap-1.5">
            <span className="text-[10px] font-bold px-2 h-5 inline-flex items-center rounded-[4px] text-white" style={{ background: "var(--tool-accent)" }}>
              Start Scanning
            </span>
            <span className="text-[10px] font-bold px-2 h-5 inline-flex items-center rounded-[4px]" style={{ border: "1px solid var(--color-line-2)", color: "var(--color-ink-2)" }}>
              Past Scans
            </span>
          </div>
        </div>
        <div
          className="rounded-[6px] overflow-hidden shrink-0"
          style={{ background: "var(--color-canvas-2)", border: "1px solid var(--color-line)" }}
        >
          <div className="flex items-center gap-1 px-2 h-5" style={{ background: "var(--color-surface-2)", borderBottom: "1px solid var(--color-line)" }}>
            {["#ff5f57", "#febc2e", "#28c840"].map((c) => (
              <span key={c} className="w-1.5 h-1.5 rounded-full" style={{ background: c }} />
            ))}
            <span className="flex-1 text-center mono text-[7.5px]" style={{ color: "var(--color-ink-4)" }}>
              scan_result.json
            </span>
          </div>
          <pre className="mono text-[7.5px] leading-[1.8] p-2 whitespace-pre" style={{ color: "var(--color-ink-3)" }}>
{`{
  "risk_score": 87,
  "level": "HIGH",
  "yara_hits": 5
}`}
          </pre>
        </div>
      </div>
      <div className="grid grid-cols-5 border-t" style={{ borderColor: "var(--color-line)", background: "var(--color-canvas-2)" }}>
        {[["812+", "YARA"], ["6", "Layers"], ["5", "Feeds"]].map(([v, l]) => (
          <div key={l} className="text-center py-2.5 border-r last:border-r-0" style={{ borderColor: "var(--color-line)" }}>
            <div className="text-[13px] font-black leading-none" style={{ color: "var(--tool-accent)" }}>{v}</div>
            <div className="text-[8px] font-bold tracking-[0.08em] uppercase mt-1" style={{ color: "var(--color-ink-4)" }}>{l}</div>
          </div>
        ))}
        {["WORKFLOW", "CAPS"].map((l) => (
          <div key={l} className="text-center py-2.5 border-r last:border-r-0" style={{ borderColor: "var(--color-line)" }}>
            <div className="text-[8px] font-bold tracking-[0.08em] uppercase" style={{ color: "var(--tool-accent)" }}>{l}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function PaletteDemo() {  return (
    <div
      className="rounded-[var(--radius-lg)] overflow-hidden"
      style={{ border: "1px solid var(--color-line-2)", boxShadow: "var(--shadow-md)" }}
    >
      <div
        className="flex items-center gap-2.5 px-3.5 h-11 border-b"
        style={{ borderColor: "var(--color-line)", background: "var(--color-surface-2)" }}
      >
        <span style={{ color: "var(--tool-accent)", display: "flex" }}>
          <Icon name="search" size={15} />
        </span>
        <span className="text-[13px] flex-1" style={{ color: "var(--color-ink-4)" }}>
          Jump to a tool, or run a command…
        </span>
      </div>
      <div className="p-1.5 flex flex-col gap-1">
        {TOOLS.slice(0, 3).map((t, i) => (
          <div
            key={t.id}
            className="flex items-center gap-2.5 px-2.5 py-2 rounded-[var(--radius-sm)]"
            style={i === 0 ? { background: "var(--tool-tint)" } : undefined}
          >
            <span
              className="grid place-items-center w-6 h-6 rounded-[4px]"
              style={{ background: "var(--color-surface-3)", color: t.accent }}
            >
              <Icon name={TOOL_ICON[t.id]} size={12} />
            </span>
            <span className="text-[12.5px] font-semibold">Open {t.name}</span>
            <span
              className="mono text-[10px] ml-auto px-1.5 h-5 grid place-items-center rounded-[4px]"
              style={{
                background: "var(--color-surface-2)",
                border: "1px solid var(--color-line-2)",
                color: "var(--color-ink-4)",
              }}
            >
              {LANDING_ORDER.indexOf(t.id) + 1}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/** Four tools, one indicator. This is the argument for one platform rather
 *  than five, so it gets a visual rather than a sentence. */
function ShareDemo() {
  const shared = "185.220.101.44";
  return (
    <div
      className="rounded-[var(--radius-lg)] p-4"
      style={{ background: "var(--color-surface-2)", border: "1px solid var(--color-line)" }}
    >
      <div className="flex items-center gap-2.5 mb-3.5">
        <span
          className="px-2 py-0.5 h-[22px] inline-flex items-center rounded-[4px] text-[10.5px] font-bold tracking-[0.06em] uppercase leading-none"
          style={{ background: "var(--color-surface-3)", color: "var(--color-ink-4)" }}
        >
          IPv4
        </span>
        <span className="font-mono text-[14px] font-bold">{shared}</span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {["malware", "ioc", "events", "phishing"].map((id) => {
          const t = TOOLS.find((x) => x.id === id)!;
          return (
            <div
              key={id}
              className="flex items-center gap-2 px-2.5 py-2 rounded-[var(--radius-sm)]"
              style={{ background: "var(--color-surface)", border: "1px solid var(--color-line)" }}
            >
              <span
                className="grid place-items-center w-6 h-6 rounded-[4px] shrink-0"
                style={{
                  background: `color-mix(in srgb, ${t.accent} 14%, transparent)`,
                  color: t.accent,
                }}
              >
                <Icon name={TOOL_ICON[t.id]} size={12} />
              </span>
              <span className="text-[11.5px] font-semibold truncate">{t.name}</span>
            </div>
          );
        })}
      </div>
      <p
        className="mt-3.5 text-[12px] flex items-center gap-1.5"
        style={{ color: "var(--color-ink-4)" }}
      >
        <Icon name="info" size={12} />
        Four tools found this address independently. SecConflux shows them as one finding.
      </p>
    </div>
  );
}