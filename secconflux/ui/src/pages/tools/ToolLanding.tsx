import type { ReactNode } from "react";
import { Icon } from "../../lib/icons";
import { Button, Card } from "../../ui";
import { TOOL_ICON } from "../../shell/chrome";
import type { ToolId } from "../../lib/tools";
import { TOOL_BY_ID as TOOL_META } from "../../lib/tools";
import { TerminalMock, TagChips } from "./TerminalMock";
import type { TerminalRow } from "./TerminalMock";

/**
 * The landing page every tool except RuleForge opens with.
 *
 * Four of the five originals share this structure, and it is a specific one:
 *
 *   eyebrow badge
 *   giant two-line headline, the last words gradiented in the tool's accent
 *   subtext
 *   one or two calls to action
 *   a terminal window showing the JSON this tool actually returns
 *   a divider-separated stats strip
 *   a second eyebrow section, a heading, prose, and feature cards carrying
 *   tag chips
 *
 * The terminal is the part that matters. It is not an illustration: it shows
 * the shape of the answer you are about to get, before you run anything. A
 * generic hero without it says "AI security tool"; this one says "here is a
 * verdict, with a score, and here is the JSON behind it".
 *
 * RuleForge does not use this page. It has its own — a workbench description,
 * four job cards and a syntax table — because its job is authoring, not
 * inspecting an artifact.
 */

export interface LandingStat {
  value: string;
  label: string;
}

export interface LandingFeature {
  title: string;
  body: string;
  /** Short mono labels rendered as chips under the paragraph. */
  tags: string[];
  /** Chip colour family, so a "passing" group reads green and a "detail"
   *  group reads informational. */
  tagTone?: "neutral" | "ok" | "info" | "warn";
}

export interface LandingCopy {
  /** Short eyebrow above the headline, e.g. "EVTX INVESTIGATION VIEWER". */
  eyebrow: string;
  /** Headline split into segments; the last one is gradiented. */
  headline: string[];
  subtext: string;
  primaryCta: string;
  onPrimary: () => void;
  secondaryCta?: string;
  onSecondary?: () => void;
  terminal: {
    file: string;
    body: "json" | "rows";
    json?: string[];
    rows?: TerminalRow[];
    status?: string;
    live?: boolean;
  };
  stats: LandingStat[];
  /** Eyebrow for the section below the strip. */
  sectionEyebrow: string;
  sectionTitle: string;
  sectionBody: string;
  features: LandingFeature[];
  /** The workflow timeline. Present on the three tools whose original has
   *  one — Malware Analyzer (WORKFLOW), Event Analyzer (PIPELINE) and
   *  Phishing Detector (How To Use It).
   *
   *  Two layouts, because the originals use two:
   *    "timeline" — Malware Analyzer and Event Analyzer. A horizontal row of
   *      centred steps, each a 46px gradient circle with a two-digit number,
   *      joined by 60px gradient connectors aligned to the circles' centre.
   *    "cards" — Phishing Detector. A four-up grid where each card carries a
   *      coloured top border and a mono step number instead. */
  workflow?: {
    eyebrow: string;
    title: string;
    layout: "timeline" | "cards";
    steps: { num: string; title: string; body: string }[];
  };
  /** Rendered after the features, if the tool has one. */
  after?: ReactNode;
}

export function ToolLanding({
  toolId,
  copy,
}: {
  toolId: Exclude<ToolId, "home">;
  copy: LandingCopy;
}) {
  const meta = TOOL_META[toolId];

  return (
    <div className="flex flex-col gap-14">
      {/* ── hero ───────────────────────────────────────────────── */}
      <section className="relative pt-4">
        <div className="sc-grid-bg" />
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            background:
              "radial-gradient(ellipse 55% 60% at 22% 10%, var(--tool-tint-2), transparent 68%)",
          }}
        />

        <div className="relative grid lg:grid-cols-[1fr_minmax(0,480px)] gap-10 items-center">
          <div className="min-w-0">
            {/* The originals carry the tool's name in their own header. In
                SecConflux the header's centre holds the two main tabs, so the
                name has to live here or the page has no identity at all. */}
            <div className="flex items-center gap-2.5 mb-6">
              <span
                className="grid place-items-center w-8 h-8 rounded-[var(--radius-sm)]"
                style={{
                  background: "var(--tool-tint)",
                  border: "1px solid var(--tool-tint-2)",
                  color: "var(--tool-accent)",
                }}
              >
                <Icon name={TOOL_ICON[toolId]} size={16} strokeWidth={1.7} />
              </span>
              <span className="text-[17px] font-extrabold tracking-[-0.02em]">
                {meta.name}
              </span>
            </div>

            <span
              className="inline-flex items-center gap-2 px-3 h-7 rounded-full mb-6"
              style={{
                background: "var(--tool-tint)",
                border: "1px solid var(--tool-tint-2)",
              }}
            >
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{ background: "var(--tool-accent)" }}
              />
              <span
                className="text-[11px] font-bold tracking-[0.1em] uppercase"
                style={{ color: "var(--tool-accent)" }}
              >
                {copy.eyebrow}
              </span>
            </span>

            {/* Each headline segment is its own LINE, which is how the
                originals set them: "Dissect. Detect." then "Defend." on the
                next line. Rendered inline they ran together into
                "Dissect. Detect.Defend." */}
            {/* Sized so the LONGEST headline in the platform — Phishing
                Detector's "Detect phishing before anyone" — fits its line at
                1440. At a larger clamp it wrapped to three lines and the
                gradiented phrase was pushed onto a line of its own, which is
                not the two-line setting the originals use. */}
            <h1 className="text-[clamp(2rem,4.2vw,3.35rem)] font-black leading-[1.02] tracking-[-0.035em]">
              {copy.headline.map((seg, i) => {
                const last = i === copy.headline.length - 1;
                return (
                  <span key={i} className="block">
                    {last ? (
                      <span
                        style={{
                          background:
                            "linear-gradient(100deg, var(--tool-accent), var(--tool-accent-2))",
                          WebkitBackgroundClip: "text",
                          backgroundClip: "text",
                          color: "transparent",
                        }}
                      >
                        {seg}
                      </span>
                    ) : (
                      seg
                    )}
                  </span>
                );
              })}
            </h1>

            <p
              className="mt-6 text-[15.5px] leading-relaxed max-w-xl"
              style={{ color: "var(--color-ink-3)" }}
            >
              {copy.subtext}
            </p>

            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Button variant="primary" size="lg" icon="play" onClick={copy.onPrimary}>
                {copy.primaryCta}
              </Button>
              {copy.secondaryCta && copy.onSecondary && (
                <Button variant="secondary" size="lg" onClick={copy.onSecondary}>
                  {copy.secondaryCta}
                </Button>
              )}
            </div>
          </div>

          <div className="min-w-0">
            <TerminalMock
              file={copy.terminal.file}
              body={copy.terminal.body}
              json={copy.terminal.json}
              rows={copy.terminal.rows}
              status={copy.terminal.status}
              live={copy.terminal.live}
            />
          </div>
        </div>
      </section>

      {/* ── stats strip ───────────────────────────────────────── */}
      <section>
        <div
          className="grid border-y"
          style={{
            gridTemplateColumns: `repeat(${copy.stats.length}, minmax(0,1fr))`,
            borderColor: "var(--color-line)",
            background: "var(--color-canvas-2)",
          }}
        >
          {copy.stats.map((s, i) => (
            <div
              key={s.label}
              className="text-center px-4 py-6"
              style={{
                borderLeft: i === 0 ? "none" : "1px solid var(--color-line)",
              }}
            >
              <div
                className="text-[26px] font-black leading-none tracking-[-0.02em]"
                style={{ color: "var(--tool-accent)" }}
              >
                {s.value}
              </div>
              <div
                className="mt-2 text-[11px] font-bold tracking-[0.08em] uppercase"
                style={{ color: "var(--color-ink-4)" }}
              >
                {s.label}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── second section: what it analyses ───────────────────── */}
      <section>
        <div
          className="inline-flex items-center px-2.5 h-6 rounded-[5px] mb-4"
          style={{
            background: "var(--tool-tint)",
            border: "1px solid var(--tool-tint-2)",
          }}
        >
          <span
            className="text-[10.5px] font-bold tracking-[0.1em] uppercase"
            style={{ color: "var(--tool-accent)" }}
          >
            {copy.sectionEyebrow}
          </span>
        </div>

        <h2 className="text-[clamp(1.5rem,3.2vw,2.15rem)] font-extrabold tracking-[-0.028em] max-w-3xl">
          {copy.sectionTitle}
        </h2>
        <p
          className="mt-3.5 text-[14px] leading-relaxed max-w-3xl"
          style={{ color: "var(--color-ink-3)" }}
        >
          {copy.sectionBody}
        </p>

        <div className="grid md:grid-cols-2 gap-4 mt-7">
          {copy.features.map((f) => (
            <Card key={f.title} className="p-5">
              <h3 className="text-[14.5px] font-bold">{f.title}</h3>
              <p
                className="mt-2 text-[13px] leading-relaxed"
                style={{ color: "var(--color-ink-3)" }}
              >
                {f.body}
              </p>
              {f.tags.length > 0 && (
                <div className="mt-4">
                  <TagChips tags={f.tags} tone={f.tagTone ?? "neutral"} />
                </div>
              )}
            </Card>
          ))}
        </div>
      </section>

      {/* ── workflow timeline ─────────────────────────────────────
          The geometry is the originals': a horizontal row of centred steps,
          each a 46px gradient-filled circle holding a two-digit number, a
          title and a short line, joined by 60px gradient connectors aligned
          to the circles' vertical centre. The connector offset is half the
          circle height (23px) — that is what lines it up with the circle
          rather than the text below it. */}
      {copy.workflow && (
        <section>
          <div
            className="inline-flex items-center px-2.5 h-6 rounded-[5px] mb-4"
            style={{
              background: "var(--tool-tint)",
              border: "1px solid var(--tool-tint-2)",
            }}
          >
            <span
              className="text-[10.5px] font-bold tracking-[0.1em] uppercase"
              style={{ color: "var(--tool-accent)" }}
            >
              {copy.workflow.eyebrow}
            </span>
          </div>

          <h2 className="text-[clamp(1.5rem,3.2vw,2.15rem)] font-extrabold tracking-[-0.028em] max-w-3xl">
            {copy.workflow.title}
          </h2>

          {/* The connector offset is half the circle height (23px): that is
              what lines a horizontal rule up with the circle's centre rather
              than with the text below it. */}
          <div
            className={
              copy.workflow.layout === "cards"
                ? "grid sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-9"
                : "flex items-start mt-9"
            }
          >
            {copy.workflow.steps.map((s, i) =>
              copy.workflow!.layout === "cards" ? (
                <div
                  key={s.num}
                  className="p-5"
                  style={{
                    background: "var(--color-surface)",
                    border: "1px solid var(--color-line)",
                    borderRadius: "var(--radius-lg)",
                    // Four steps, four hues — the same progression the
                    // original uses: sky, purple, amber, green.
                    borderTop: `3px solid ${["var(--color-info)", "var(--color-magic)", "var(--color-warn)", "var(--color-ok)"][i % 4]}`,
                  }}
                >
                  <span
                    className="mono block text-[11px] font-semibold mb-3"
                    style={{ color: "var(--color-ink-4)" }}
                  >
                    {s.num}
                  </span>
                  <h3 className="text-[14.5px] font-bold mb-1.5">{s.title}</h3>
                  <p
                    className="text-[13px] leading-relaxed"
                    style={{ color: "var(--color-ink-3)" }}
                  >
                    {s.body}
                  </p>
                </div>
              ) : (
                <div key={s.num} className="flex items-start flex-1 min-w-0">
                  <div className="flex-1 flex flex-col items-center text-center min-w-0">
                    <span
                      className="w-[46px] h-[46px] rounded-full grid place-items-center mb-3.5 shrink-0 font-extrabold text-[17px] text-white"
                      style={{
                        background:
                          "linear-gradient(135deg, var(--tool-accent), var(--tool-accent-2))",
                      }}
                    >
                      {s.num}
                    </span>
                    <h3 className="text-[16px] font-bold mb-1.5">{s.title}</h3>
                    <p
                      className="text-[13.5px] leading-relaxed max-w-[230px]"
                      style={{ color: "var(--color-ink-3)" }}
                    >
                      {s.body}
                    </p>
                  </div>
                  {i < copy.workflow!.steps.length - 1 && (
                    <span
                      className="shrink-0"
                      style={{
                        width: 60,
                        height: 2,
                        marginTop: 23,
                        opacity: 0.4,
                        background:
                          "linear-gradient(90deg, var(--tool-accent), var(--tool-accent-2))",
                      }}
                    />
                  )}
                </div>
              ),
            )}
          </div>
        </section>
      )}

      {copy.after}
    </div>
  );
}

/** A closing note that names the other tools, in the form the originals use:
 *  a short line under the content rather than a section of its own. */
export function NextStepNote({
  toolId,
  links,
}: {
  toolId: Exclude<ToolId, "home">;
  links: { to: ToolId; text: string }[];
}) {
  return (
    <div
      className="flex items-start gap-3.5 p-4 rounded-[var(--radius-lg)]"
      style={{
        background: "var(--color-surface-2)",
        border: "1px solid var(--color-line)",
      }}
    >
      <span
        className="grid place-items-center w-9 h-9 rounded-[var(--radius-sm)] shrink-0"
        style={{ background: "var(--tool-tint)", color: "var(--tool-accent)" }}
      >
        <Icon name={TOOL_ICON[toolId]} size={17} />
      </span>
      <div className="min-w-0 text-[13px] leading-relaxed">
        <span className="font-bold">Where this goes next. </span>
        <span style={{ color: "var(--color-ink-3)" }}>
          {links.map((l, i) => (
            <span key={l.to}>
              {i > 0 && " and "}
              <span
                className="font-semibold"
                style={{ color: TOOL_META[l.to].accent }}
              >
                {TOOL_META[l.to].name}
              </span>{" "}
              {l.text}
            </span>
          ))}
          .
        </span>
      </div>
    </div>
  );
}
