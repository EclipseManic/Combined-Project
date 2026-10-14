import type { ReactNode } from "react";
import { Icon } from "../../lib/icons";
import type { IconName } from "../../lib/icons";
import { Card, CardHead, CardBody, Button, StatTile } from "../../ui";
import { TOOL_ICON } from "../../shell/chrome";
import type { ToolId } from "../../lib/tools";
import { TOOL_BY_ID as TOOL_META } from "../../lib/tools";

/**
 * The first main tab of every tool.
 *
 * A shared component, not five hand-written pages, for the same reason the
 * design system is one file: five separately authored "about" pages drift.
 * They drift in structure first and in tone second, and within two edits the
 * five tools stop reading as one product.
 *
 * It answers four questions in the same order on every tool:
 *
 *   1. what is this thing        — hero, with the name treated as a title
 *   2. what does it actually do  — a card grid, not a bullet list
 *   3. how do I use it           — ordered steps
 *   4. what is already here     — stats, and the way in
 *
 * Plus the section that earns the most trust: what it does NOT do. A tool that
 * states its limits is more usable than one that claims coverage it lacks.
 *
 * The working surface is a separate tab and is not summarised here beyond the
 * entry point, so this page stays a description rather than a second copy of
 * the tool.
 */

export interface ToolIntro {
  /** One sentence, no more. What the tool is. */
  pitch: string;
  /** Two or three paragraphs. How it works and where its limits are. */
  body: string[];
  /** Concrete capabilities. Full sentences — these are prose, not chips. */
  capabilities: { icon: IconName; title: string; detail: string }[];
  /** Ordered, actionable, and short enough to actually follow. */
  steps: string[];
  /** Honest limits. */
  limits?: string[];
  /** At-a-glance numbers, read from the real backend. */
  stats?: { label: string; value: string }[];
  /** Label for the button that opens the working surface. */
  cta: string;
}

export function ToolOverview({
  toolId,
  intro,
  onStart,
  onSecondary,
  secondaryLabel,
  recent,
}: {
  toolId: Exclude<ToolId, "home">;
  intro: ToolIntro;
  onStart: () => void;
  onSecondary?: () => void;
  secondaryLabel?: string;
  /** Optional recent-work block, rendered under the capabilities. */
  recent?: ReactNode;
}) {
  const meta = TOOL_META[toolId];

  return (
    <div className="flex flex-col gap-5">
      {/* ── hero ──────────────────────────────────────────────────
          Treated as a title, not a card heading: a large name, a gradient
          wash behind it and the grid that the platform landing page uses, so
          opening a tool reads as arriving somewhere rather than as a table
          appearing. */}
      <Card glow className="relative overflow-hidden">
        <div className="sc-grid-bg opacity-60" />
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            background:
              "radial-gradient(ellipse 60% 70% at 18% 0%, var(--tool-tint-2), transparent 70%)",
          }}
        />
        <div className="relative p-7">
          <div className="flex items-start gap-5">
            <span
              className="grid place-items-center w-16 h-16 rounded-[var(--radius-lg)] shrink-0"
              style={{
                background: "var(--tool-tint)",
                border: "1px solid var(--tool-tint-2)",
                color: "var(--tool-accent)",
                boxShadow: "0 12px 32px -12px var(--tool-glow)",
              }}
            >
              <Icon name={TOOL_ICON[toolId]} size={30} strokeWidth={1.4} />
            </span>

            <div className="min-w-0 flex-1">
              <div
                className="text-[10.5px] font-bold tracking-[0.14em] uppercase mb-2"
                style={{ color: "var(--tool-accent)" }}
              >
                {meta.tagline}
              </div>
              <h1
                className="text-[clamp(1.8rem,3.6vw,2.6rem)] font-black leading-[1.05] tracking-[-0.035em]"
              >
                {meta.name}
              </h1>
              <p
                className="mt-4 text-[15px] leading-relaxed max-w-3xl"
                style={{ color: "var(--color-ink-2)" }}
              >
                {intro.pitch}
              </p>
              <div className="flex flex-wrap gap-2.5 mt-6">
                <Button variant="primary" size="lg" icon="play" onClick={onStart}>
                  {intro.cta}
                </Button>
                {onSecondary && secondaryLabel && (
                  <Button variant="secondary" size="lg" onClick={onSecondary}>
                    {secondaryLabel}
                  </Button>
                )}
              </div>
            </div>
          </div>

          {intro.stats && (
            <div
              className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-7 pt-6 border-t"
              style={{ borderColor: "var(--color-line)" }}
            >
              {intro.stats.map((s) => (
                <StatTile key={s.label} label={s.label} value={s.value} />
              ))}
            </div>
          )}
        </div>
      </Card>

      {/* ── capabilities: a card grid, not a list ─────────────────── */}
      <section>
        <div className="flex items-end justify-between gap-4 mb-4">
          <div>
            <h2
              className="text-[19px] font-extrabold tracking-[-0.02em]"
            >
              What it does
            </h2>
            <p className="text-[13.5px] mt-1" style={{ color: "var(--color-ink-4)" }}>
              {intro.capabilities.length} things it does that it will not pretend to do
            </p>
          </div>
        </div>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {intro.capabilities.map((c) => (
            <Card key={c.title} interactive className="p-4 h-full">
              <span
                className="grid place-items-center w-10 h-10 rounded-[var(--radius-md)] mb-3.5"
                style={{
                  background: "var(--tool-tint)",
                  border: "1px solid var(--tool-tint-2)",
                  color: "var(--tool-accent)",
                }}
              >
                <Icon name={c.icon} size={19} strokeWidth={1.6} />
              </span>
              <h3 className="text-[14px] font-bold leading-snug">{c.title}</h3>
              <p
                className="mt-1.5 text-[12.5px] leading-relaxed"
                style={{ color: "var(--color-ink-3)" }}
              >
                {c.detail}
              </p>
            </Card>
          ))}
        </div>
      </section>

      <div className="grid lg:grid-cols-2 gap-5">
        {/* ── how it works ─────────────────────────────────────────── */}
        <Card>
          <CardHead title="How it works" icon="layers" />
          <CardBody className="flex flex-col gap-3.5">
            {intro.body.map((p, i) => (
              <p
                key={i}
                className="text-[13.5px] leading-relaxed"
                style={{ color: "var(--color-ink-2)" }}
              >
                {p}
              </p>
            ))}
          </CardBody>
        </Card>

        <div className="flex flex-col gap-5">
          {intro.limits && (
            <Card>
              <CardHead
                title="What it does not do"
                icon="alert-triangle"
                subtitle="Stated up front, so you can decide whether it is the right tool"
              />
              <CardBody className="flex flex-col gap-2.5">
                {intro.limits.map((l) => (
                  <div key={l} className="flex gap-2.5">
                    <span
                      className="shrink-0 w-1.5 h-1.5 rounded-full mt-2"
                      style={{ background: "var(--color-warn)", opacity: 0.8 }}
                    />
                    <span
                      className="text-[13px] leading-relaxed"
                      style={{ color: "var(--color-ink-3)" }}
                    >
                      {l}
                    </span>
                  </div>
                ))}
              </CardBody>
            </Card>
          )}
          {recent}
        </div>
      </div>

      {/* ── how to use it ──────────────────────────────────────────── */}
      <section>
        <div className="mb-4">
          <h2 className="text-[19px] font-extrabold tracking-[-0.02em]">
            How to use it
          </h2>
          <p className="text-[13.5px] mt-1" style={{ color: "var(--color-ink-4)" }}>
            {intro.steps.length} steps, in the order they actually happen
          </p>
        </div>
        <ol className="grid sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {intro.steps.map((s, i) => (
            <li
              key={i}
              className="p-4 rounded-[var(--radius-lg)] relative"
              style={{
                background: "var(--color-surface)",
                border: "1px solid var(--color-line)",
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <span
                  className="grid place-items-center w-6 h-6 rounded-full text-[11px] font-black"
                  style={{
                    background: "var(--tool-tint)",
                    border: "1px solid var(--tool-tint-2)",
                    color: "var(--tool-accent)",
                  }}
                >
                  {i + 1}
                </span>
                {i < intro.steps.length - 1 && (
                  <span
                    className="flex-1 h-px"
                    style={{ background: "var(--color-line)" }}
                  />
                )}
              </div>
              <p
                className="text-[12.5px] leading-relaxed"
                style={{ color: "var(--color-ink-2)" }}
              >
                {s}
              </p>
            </li>
          ))}
        </ol>
      </section>

      <CrossToolNote toolId={toolId} />
    </div>
  );
}

/** A short, honest pointer at the rest of the platform. The whole argument
 *  for one product is that findings move between these tools, so every
 *  "about" page says where its output goes. */
function CrossToolNote({ toolId }: { toolId: Exclude<ToolId, "home"> }) {
  const LINKS: Record<
    Exclude<ToolId, "home">,
    { to: ToolId; text: string }[]
  > = {
    malware: [
      { to: "ioc", text: "every IP, domain and hash a sample reveals, ready to enrich" },
      { to: "events", text: "the C2 addresses, searchable against your Windows event logs" },
    ],
    ioc: [
      { to: "malware", text: "any file hash, straight into static analysis" },
      { to: "events", text: "any address, searched across ingested EVTX" },
    ],
    events: [
      { to: "ioc", text: "every indicator the logs contain, in one enrichment run" },
      { to: "ruleforge", text: "the Sigma rules that matched, ready to tune" },
    ],
    phishing: [
      { to: "malware", text: "attachment hashes, checked against the malware corpus" },
      { to: "ioc", text: "sender domains and link hosts, resolved" },
    ],
    ruleforge: [
      { to: "events", text: "a rule you tune here, validated against real logs" },
      { to: "malware", text: "YARA-L, when the rule needs to reach an endpoint" },
    ],
  };
  return (
    <div
      className="flex items-start gap-3.5 p-4 rounded-[var(--radius-lg)]"
      style={{ background: "var(--color-surface-2)", border: "1px solid var(--color-line)" }}
    >
      <span
        className="grid place-items-center w-9 h-9 rounded-[var(--radius-sm)] shrink-0"
        style={{ background: "var(--tool-tint)", color: "var(--tool-accent)" }}
      >
        <Icon name="git-branch" size={17} />
      </span>
      <div className="min-w-0 text-[13px] leading-relaxed">
        <span className="font-bold">Not a standalone tool. </span>
        <span style={{ color: "var(--color-ink-3)" }}>
          Its output goes straight into{" "}
          {LINKS[toolId].map((l, i) => (
            <span key={l.to}>
              {i > 0 && " and "}
              <span className="font-semibold" style={{ color: TOOL_META[l.to].accent }}>
                {TOOL_META[l.to].name}
              </span>{" "}
              for {l.text}
            </span>
          ))}
          .
        </span>
      </div>
    </div>
  );
}
