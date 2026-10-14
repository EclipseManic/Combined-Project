import { useEffect, useState } from "react";
import { cn } from "../../lib/utils";

/**
 * The terminal window that sits on the right of every tool's landing page.
 *
 * This is not decoration. In the original tools it shows the JSON the tool
 * actually returns — `scan_result.json`, `lookup_result.json`, `events.json` —
 * and IOC Lookup extends it with a LIVE badge and a status footer reading
 * "2.4s · 6 engines · 812 YARA rules". It is the element that tells a visitor
 * what shape of answer they are about to get, before they run anything.
 *
 * Two bodies are supported, because the originals use two:
 *   "json" — syntax-coloured JSON, used by Malware Analyzer, IOC Lookup,
 *            Event Analyzer
 *   "rows" — a findings table with a verdict on the right, used by Phishing
 *            Detector, whose "terminal" is a triage summary rather than a dump
 */

export interface TerminalRow {
  label: string;
  value: string;
  tone: "bad" | "ok" | "warn" | "plain";
}

export interface TerminalMockProps {
  /** Window title, e.g. "scan_result.json". */
  file: string;
  body: "json" | "rows";
  /** For body="json": the lines to type out. */
  json?: string[];
  /** For body="rows": the findings table. */
  rows?: TerminalRow[];
  /** Footer status line, e.g. "2.4s · 6 engines · 812 YARA rules". */
  status?: string;
  /** Shows the LIVE badge and a pulsing dot in the footer. */
  live?: boolean;
  /** Types the content out on first paint. */
  animate?: boolean;
}

const TONE_COLOR: Record<TerminalRow["tone"], string> = {
  bad: "var(--color-bad)",
  ok: "var(--color-ok)",
  warn: "var(--color-warn)",
  plain: "var(--color-ink-3)",
};

export function TerminalMock({
  file,
  body,
  json = [],
  rows = [],
  status,
  live,
  animate = true,
}: TerminalMockProps) {
  const [shown, setShown] = useState(animate ? 0 : json.length);

  /* Value-stable key. Depending on the `json` array itself is the obvious
     thing to do and it is wrong: callers pass an inline literal, so the
     array is a new reference on every render, the effect re-runs, and the
     counter resets to zero forever. The terminal stays permanently blank
     and nothing throws. Joining to a string makes the dependency compare by
     value, which is what "this content changed" actually means. */
  const jsonKey = json.join("\n");

  useEffect(() => {
    if (!animate || body !== "json" || json.length === 0) return;
    setShown(0);
    let line = 0;
    const tick = window.setInterval(() => {
      line += 1;
      setShown(line);
      if (line >= json.length) window.clearInterval(tick);
    }, 190);
    return () => window.clearInterval(tick);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [animate, body, jsonKey]);

  return (
    <div
      className="relative overflow-hidden rounded-[var(--radius-lg)]"
      style={{
        background: "var(--color-canvas-2)",
        border: "1px solid var(--color-line-2)",
        boxShadow: "var(--shadow-lg)",
      }}
    >
      {/* title bar */}
      <div
        className="flex items-center gap-2.5 px-3 h-9"
        style={{
          background: "var(--color-surface-2)",
          borderBottom: "1px solid var(--color-line)",
        }}
      >
        <span className="flex gap-1.5 shrink-0">
          {["#ff5f57", "#febc2e", "#28c840"].map((c) => (
            <span
              key={c}
              className="w-2.5 h-2.5 rounded-full"
              style={{ background: c, opacity: 0.85 }}
            />
          ))}
        </span>
        <span
          className="flex-1 text-center font-mono text-[11.5px] truncate"
          style={{ color: "var(--color-ink-4)" }}
        >
          {file}
        </span>
        {live && (
          <span
            className="shrink-0 px-1.5 h-5 inline-flex items-center rounded-[4px] text-[9.5px] font-bold tracking-[0.08em]"
            style={{
              background: "rgb(52 211 153 / 0.14)",
              border: "1px solid rgb(52 211 153 / 0.35)",
              color: "var(--color-ok)",
            }}
          >
            LIVE
          </span>
        )}
      </div>

      {/* body */}
      {body === "json" ? (
        <pre
          className="mono text-[11.5px] leading-[1.7] p-4 overflow-hidden h-[248px] whitespace-pre"
          style={{ color: "var(--color-ink-2)" }}
        >
          {json.slice(0, shown).map((line, i) => (
            <div key={i}>{colourJson(line)}</div>
          ))}
          {shown < json.length && (
            <span
              className="inline-block w-1.5 h-3.5 align-middle"
              style={{ background: "var(--tool-accent)", animation: "sc-cursor 1s steps(2) infinite" }}
            />
          )}
        </pre>
      ) : (
        <div className="p-3 flex flex-col gap-1 min-h-[248px]">
          {rows.map((r, i) => (
            <div
              key={i}
              className="flex items-center gap-3 px-2.5 py-1.5 rounded-[5px] text-[11.5px]"
              style={{ background: "var(--color-surface)" }}
            >
              <span className="flex-1 truncate" style={{ color: "var(--color-ink-2)" }}>
                {r.label}
              </span>
              <span
                className="mono font-bold shrink-0"
                style={{ color: TONE_COLOR[r.tone] }}
              >
                {r.value}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* status footer */}
      {status && (
        <div
          className="flex items-center gap-2.5 px-3 h-8"
          style={{
            background: "var(--color-surface-2)",
            borderTop: "1px solid var(--color-line)",
          }}
        >
          <span className="mono text-[10.5px] truncate" style={{ color: "var(--color-ink-4)" }}>
            {status}
          </span>
          {live && (
            <span className="ml-auto flex items-center gap-1.5 shrink-0">
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{ background: "var(--color-ok)", animation: "sc-pulse-ring 2s infinite" }}
              />
              <span
                className="mono text-[10.5px] font-bold"
                style={{ color: "var(--color-ok)" }}
              >
                live
              </span>
            </span>
          )}
        </div>
      )}
    </div>
  );
}

/** Minimal JSON colouring. Keys, string values and numbers are told apart by
 *  shape rather than by parsing, because the input is already formatted and
 *  a parser here would be more code than the thing it replaces. */
function colourJson(line: string) {
  const KEY = "var(--color-info)";
  const STR = "var(--color-warn)";
  const NUM = "var(--color-magic)";
  const PUNCT = "var(--color-ink-4)";

  const parts = line.split(/("(?:[^"\\]|\\.)*")(\s*:)?|(\b\d+(?:\.\d+)?\b)|([{}\[\],])/g);
  return parts.map((p, i) => {
    if (!p) return null;
    if (p.startsWith('"') && parts[i + 1] === ":") {
      return (
        <span key={i} style={{ color: KEY }}>
          {p}
          <span style={{ color: PUNCT }}>:</span>
        </span>
      );
    }
    if (p.startsWith('"')) return <span key={i} style={{ color: STR }}>{p}</span>;
    if (/^\d/.test(p)) return <span key={i} style={{ color: NUM }}>{p}</span>;
    if (/^[{}\[\],]$/.test(p)) return <span key={i} style={{ color: PUNCT }}>{p}</span>;
    return <span key={i}>{p}</span>;
  });
}

export function TagChips({
  tags,
  tone = "neutral",
}: {
  tags: string[];
  tone?: "neutral" | "ok" | "info" | "warn";
}) {
  const colours: Record<string, { bg: string; fg: string; bd: string }> = {
    neutral: {
      bg: "var(--color-surface-3)",
      fg: "var(--color-ink-3)",
      bd: "var(--color-line-2)",
    },
    ok: {
      bg: "rgb(52 211 153 / 0.12)",
      fg: "var(--color-ok)",
      bd: "rgb(52 211 153 / 0.3)",
    },
    info: {
      bg: "rgb(56 189 248 / 0.12)",
      fg: "var(--color-info)",
      bd: "rgb(56 189 248 / 0.3)",
    },
    warn: {
      bg: "rgb(251 191 36 / 0.12)",
      fg: "var(--color-warn)",
      bd: "rgb(251 191 36 / 0.3)",
    },
  };
  const t = colours[tone];
  return (
    <div className="flex flex-wrap gap-1.5">
      {tags.map((tag) => (
        <span
          key={tag}
          className={cn(
            "mono inline-flex items-center h-[22px] px-2 rounded-[4px]",
            "text-[10.5px] font-semibold border",
          )}
          style={{ background: t.bg, color: t.fg, borderColor: t.bd }}
        >
          {tag}
        </span>
      ))}
    </div>
  );
}
