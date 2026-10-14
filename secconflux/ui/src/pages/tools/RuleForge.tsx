import { useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { Icon } from "../../lib/icons";
import { Card, CardHead, CardBody, Button, Badge, Table, Th, Td, CodeBlock, EmptyState, Callout, Select, Textarea, Input, StatTile } from "../../ui";
import { RULEFORGE_DIALECTS, RULEFORGE_SAMPLE_SPL, RULEFORGE_UNDERSTAND, RULEFORGE_TUNE, RULEFORGE_HISTORY } from "../../data/fixtures";
import type { Diagnostic } from "../../data/fixtures";
import { cn, relativeTime } from "../../lib/utils";
import { toast } from "../../shell/chrome";
import { useShell } from "../../lib/shell-context";
import { ToolOverview } from "./ToolOverview";

type Job = "author" | "understand" | "tune" | "debug_rule_to_logs" | "debug_logs_to_rule";

const JOBS: { id: Job; label: string; icon: "sparkles" | "eye" | "activity" | "file-code" | "git-branch"; blurb: string }[] = [
  { id: "author", label: "Author", icon: "sparkles", blurb: "Parse a rule and render it into every other dialect" },
  { id: "understand", label: "Understand", icon: "eye", blurb: "Explain what the rule actually means, node by node" },
  { id: "tune", label: "Tune", icon: "activity", blurb: "Score the rule against real sample events" },
  { id: "debug_rule_to_logs", label: "Rule to logs", icon: "file-code", blurb: "Generate the events a rule would have fired on" },
  { id: "debug_logs_to_rule", label: "Logs to rule", icon: "git-branch", blurb: "Build a rule from a set of log lines" },
];

const SEV: Record<Diagnostic["severity"], { tone: "bad" | "warn" | "info" | "ok"; label: string; color: string }> = {
  problem: { tone: "bad", label: "Problem", color: "var(--color-bad)" },
  caution: { tone: "warn", label: "Caution", color: "var(--color-warn)" },
  note: { tone: "info", label: "Note", color: "var(--color-info)" },
  ok: { tone: "ok", label: "Confirmed", color: "var(--color-ok)" },
};

export function RuleForgePage({ navigate }: { navigate: (to: string) => void }) {
  const { mainTab, setMainTab, subTab, setSubTab, actionsSlot } = useShell();

  const headerAction = actionsSlot
    ? createPortal(
        <Button variant="secondary" size="sm" icon="lock">
          offline · no SIEM
        </Button>,
        actionsSlot,
      )
    : null;

  return (
    <div className="sc-anim-in">
      {headerAction}

      <div className="max-w-[1400px] mx-auto px-5 py-6">
        {mainTab === "overview" ? (
          <ToolOverview
            toolId="ruleforge"
            intro={{
              pitch:
                "RuleForge reads a detection rule and tells you what it will actually do. Not that it parses — that it parses. What it will match, what it will miss, and what it means when it fires.",
              body: [
                "A rule is parsed, lowered to a neutral intermediate representation, and validated. That is where the difference from a reformatter comes from: a construct that exists in one dialect and cannot be written in another is named and refused, never quietly dropped.",
                "The Understand job then walks the rule in execution order and explains each stage in plain language, with the diagnostics attached to the stage that caused them. A rule can be syntactically valid, produce no errors, and still have a field that silently became empty — that is the class of defect this exists to find.",
                "Tune scores the rule against events you supply. It is explicit that the result is scoped to those events: a rule that scores well against two thousand samples is not thereby correct against traffic those samples never contained.",
              ],
              capabilities: [
                { icon: "file-code", title: "Eight dialects", detail: "Splunk SPL, Microsoft KQL, Elasticsearch AQL, Elastic EQL, CrowdStrike CQL and FQL, Wazuh XML and YARA-L, each with its own semantics and its own documented traps." },
                { icon: "sparkles", title: "Author across dialects", detail: "Parse a rule in one dialect and render it into the others, so a rule written for one SIEM can be ported without rewriting it from memory." },
                { icon: "eye", title: "Understand", detail: "A plain-language account of every stage in execution order, with a note on what each one costs and which fields it consumes." },
                { icon: "activity", title: "Tune against real events", detail: "Score a rule against sample events, with false positives attributed to the specific condition that caused them." },
                { icon: "git-branch", title: "Both debugging directions", detail: "Generate the events a rule would have fired on, and build a rule from a set of log lines you already have." },
                { icon: "clock", title: "Append-only history", detail: "Every save writes a new entry and never rewrites an older one. There is no delete path, because a tuning session is evidence." },
              ],
              steps: [
                "Pick your dialect and paste a rule.",
                "Run Understand and read the findings by severity.",
                "Fix the problems, not the cautions.",
                "Run Tune against events you actually have.",
                "Port it to another dialect, or validate it against Event Analyzer.",
              ],
              limits: [
                "Everything runs offline. RuleForge never contacts a SIEM, so it cannot confirm that a rule is valid on your specific index or cluster.",
                "A cross-dialect render can lose semantics the target cannot express. Those are reported by name rather than translated approximately.",
                "Tuning results describe the sample you supplied. They are not a false-positive rate for your production traffic.",
              ],
              stats: [
                { label: "Dialects", value: "8" },
                { label: "Jobs", value: "5" },
                { label: "Backend tests", value: "468" },
                { label: "Mutations caught", value: "15/15" },
              ],
              cta: "Open the workshop",
            }}
            onStart={() => {
              setSubTab("author");
              setMainTab("studio");
            }}
            secondaryLabel="Read the dialect reference"
            onSecondary={() => {
              setSubTab("docs");
              setMainTab("studio");
            }}
          />
        ) : (
          <>
            {subTab === "author" && <Workshop section="author" />}
            {subTab === "tune" && <Workshop section="tune" />}
            {subTab === "debug" && <Workshop section="debug" />}
            {subTab === "understand" && <Workshop section="understand" />}
            {subTab === "docs" && <Dialects navigate={navigate} />}
            {subTab === "history" && <History />}
          </>
        )}
      </div>
    </div>
  );
}

/* =============================================================
   WORKSHOP
   ============================================================= */

/* The workshop's four tabs are RuleForge's own (workshop.html:6-9), in its
   own order: Author, Tune, Debug, Understand. The header chips select them.

   This used to carry its own job picker as well, so the same choices were on
   screen twice and could disagree. The chips are the single source, which is
   how the original tool works. */
const JOB_FOR_SECTION: Record<string, Job> = {
  author: "author",
  tune: "tune",
  debug: "debug_rule_to_logs",
  understand: "understand",
};

function Workshop({ section }: { section: string }) {
  const job = JOB_FOR_SECTION[section] ?? "understand";
  const [dialect, setDialect] = useState("splunk");
  const [rule, setRule] = useState(RULEFORGE_SAMPLE_SPL);
  const [events, setEvents] = useState("");
  const [ran, setRan] = useState(true);

  const active = JOBS.find((j) => j.id === job)!;
  const showEvents = job === "tune" || job === "debug_logs_to_rule";

  function run() {
    setRan(false);
    window.setTimeout(() => {
      setRan(true);
      const p = RULEFORGE_UNDERSTAND.findings.filter((f) => f.severity === "problem").length;
      toast(`${active.label} complete · ${p} problems, ${RULEFORGE_UNDERSTAND.findings.length - p} other findings`, p > 0 ? "warn" : "ok");
    }, 620);
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="grid lg:grid-cols-2 gap-5">
        {/* input */}
        <Card className="flex flex-col">
          <CardHead
            title={active.label}
            icon={active.icon}
            action={
              <Select
                value={dialect}
                onChange={(e) => setDialect(e.target.value)}
                dense
                style={{ width: 160 }}
              >
                {RULEFORGE_DIALECTS.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.label}
                  </option>
                ))}
              </Select>
            }
          />
          <CardBody className="flex-1 flex flex-col gap-3">
            <Textarea
              mono
              value={rule}
              onChange={(e) => setRule(e.target.value)}
              rows={12}
              placeholder="Paste a rule in the selected dialect…"
            />
            {showEvents && (
              <>
                <div className="flex items-center gap-2">
                  <span className="text-[12px] font-bold text-[var(--color-ink-4)]">
                    SAMPLE EVENTS
                  </span>
                  <span className="flex-1 h-px" style={{ background: "var(--color-line)" }} />
                </div>
                <Textarea
                  mono
                  value={events}
                  onChange={(e) => setEvents(e.target.value)}
                  rows={6}
                  placeholder='One JSON event per line, e.g. {"user":"a.raman","src_ip":"10.2.4.9","action":4624}'
                />
              </>
            )}
            <div className="flex items-center gap-2">
              <Button variant="primary" icon="play" onClick={run}>
                Run {active.label}
              </Button>
              <Button
                variant="ghost"
                icon="refresh"
                onClick={() => {
                  setRule(RULEFORGE_SAMPLE_SPL);
                  setEvents("");
                  toast("Reset to the sample rule");
                }}
              >
                Reset
              </Button>
            </div>
          </CardBody>
        </Card>

        {/* output */}
        <div className="flex flex-col gap-5">
          {!ran ? (
            <Card className="flex-1">
              <EmptyState icon="activity" title="Running…" body="Parsing, lowering, validating and rendering." />
            </Card>
          ) : (
            <>
              <Card glow>
                <CardHead
                  title="In plain language"
                  icon="eye"
                  action={
                    <Badge tone={RULEFORGE_UNDERSTAND.findings.filter((f) => f.severity === "problem").length > 0 ? "warn" : "ok"}>
                      {RULEFORGE_UNDERSTAND.dialect} · {RULEFORGE_UNDERSTAND.language}
                    </Badge>
                  }
                />
                <CardBody>
                  <p className="text-[13.5px] leading-relaxed" style={{ color: "var(--color-ink-2)" }}>
                    {RULEFORGE_UNDERSTAND.summary}
                  </p>
                </CardBody>
              </Card>

              <Card>
                <CardHead
                  title="Findings"
                  icon="alert-triangle"
                  count={RULEFORGE_UNDERSTAND.findings.length}
                  subtitle="Ordered by severity. Problems change what the rule does; cautions change how much you should trust it."
                />
                <CardBody className="flex flex-col gap-2.5">
                  {RULEFORGE_UNDERSTAND.findings.map((f) => {
                    const s = SEV[f.severity];
                    return (
                      <div
                        key={f.code + f.message.slice(0, 12)}
                        className="p-3 rounded-[var(--radius-md)]"
                        style={{
                          background: "var(--color-surface-2)",
                          borderLeft: `3px solid ${s.color}`,
                          border: "1px solid var(--color-line)",
                          borderLeftColor: s.color,
                        }}
                      >
                        <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                          <Badge tone={s.tone}>{s.label}</Badge>
                          <span className="font-mono text-[11.5px]" style={{ color: "var(--color-ink-4)" }}>
                            {f.code}
                          </span>
                          {f.line !== undefined && (
                            <span className="font-mono text-[11.5px]" style={{ color: "var(--color-ink-4)" }}>
                              line {f.line}
                            </span>
                          )}
                        </div>
                        <p className="text-[12.5px] leading-relaxed" style={{ color: "var(--color-ink-2)" }}>
                          {f.message}
                        </p>
                      </div>
                    );
                  })}
                </CardBody>
              </Card>
            </>
          )}
        </div>
      </div>

      {/* node graph */}
      <Card>
        <CardHead
          title="Rule graph"
          icon="git-branch"
          count={RULEFORGE_UNDERSTAND.nodes.length}
          subtitle="Each stage the rule goes through, in execution order"
        />
        <CardBody>
          <div className="flex flex-col gap-1.5">
            {RULEFORGE_UNDERSTAND.nodes.map((n, i) => (
              <div key={i} className="flex gap-3">
                <div className="flex flex-col items-center shrink-0 w-7">
                  <span
                    className="w-6 h-6 grid place-items-center rounded-full text-[10.5px] font-black shrink-0"
                    style={{
                      background: "var(--tool-tint)",
                      border: "1px solid var(--tool-tint-2)",
                      color: "var(--tool-accent)",
                    }}
                  >
                    {i + 1}
                  </span>
                  {i < RULEFORGE_UNDERSTAND.nodes.length - 1 && (
                    <span className="flex-1 w-px my-1" style={{ background: "var(--color-line)" }} />
                  )}
                </div>
                <div
                  className="flex-1 mb-2 p-3 rounded-[var(--radius-md)] min-w-0"
                  style={{ background: "var(--color-surface-2)", border: "1px solid var(--color-line)" }}
                >
                  <div className="flex items-center gap-2 flex-wrap mb-1.5">
                    <Badge tone="accent">{n.kind}</Badge>
                    <span className="font-mono text-[12px] font-semibold">{n.detail}</span>
                  </div>
                  <p className="text-[12.5px] leading-relaxed" style={{ color: "var(--color-ink-3)" }}>
                    {n.note}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </CardBody>
      </Card>

      <div className="grid lg:grid-cols-2 gap-5">
        <Card>
          <CardHead title="Rendered to KQL" icon="file-code" />
          <CardBody>
            <CodeBlock code={RULEFORGE_UNDERSTAND.translated.kql} language="KQL" maxHeight={240} />
          </CardBody>
        </Card>
        <Card>
          <CardHead title="Rendered to AQL" icon="file-code" />
          <CardBody>
            <CodeBlock code={RULEFORGE_UNDERSTAND.translated.aql} language="AQL" maxHeight={240} />
          </CardBody>
        </Card>
      </div>

      {/* The tuning report belongs to RuleForge's Tune tab, not to every tab. */}
      {job === "tune" && (
        <Card>
          <CardHead
            title="Tuning report"
            icon="activity"
          subtitle="RuleForge evaluated against 2,000 supplied sample events"
          action={
            <Badge tone="warn">
              19% noise removable
            </Badge>
          }
        />
        <CardBody className="flex flex-col gap-4">
          <Callout tone="info" title={RULEFORGE_TUNE.summary}>
            Every finding below is scoped to the 2,000 events you supplied. A rule that scores
            well here can still be wrong against traffic this sample never contained.
          </Callout>
          <div className="grid sm:grid-cols-2 gap-3">
            {RULEFORGE_TUNE.findings.map((f) => {
              const s = SEV[f.severity];
              return (
                <div
                  key={f.code}
                  className="p-3.5 rounded-[var(--radius-md)]"
                  style={{ background: "var(--color-surface-2)", borderLeft: `3px solid ${s.color}` }}
                >
                  <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                    <Badge tone={s.tone}>{s.label}</Badge>
                    <span className="font-mono text-[11px]" style={{ color: "var(--color-ink-4)" }}>
                      {f.code}
                    </span>
                    <span className="text-[11.5px] font-bold ml-auto" style={{ color: s.color }}>
                      {f.impact}
                    </span>
                  </div>
                  <p className="text-[12.5px] leading-relaxed" style={{ color: "var(--color-ink-2)" }}>
                    {f.message}
                  </p>
                </div>
              );
            })}
          </div>
          <div>
            <div className="text-[12px] font-bold text-[var(--color-ink-4)] mb-2">
              SAMPLE CLASSIFICATION
            </div>
            <Table>
              <thead>
                <tr>
                  <Th>Label</Th>
                  <Th>User</Th>
                  <Th align="right">Distinct sources</Th>
                  <Th align="right">Hour</Th>
                  <Th align="right">Event ID</Th>
                  <Th align="center">Rule matched</Th>
                </tr>
              </thead>
              <tbody>
                {RULEFORGE_TUNE.samples.map((s, i) => (
                  <tr key={i} className="hover:bg-[var(--color-surface-2)]">
                    <Td>
                      <Badge tone={s.matched ? "bad" : "warn"}>{s.label}</Badge>
                    </Td>
                    <Td mono className="font-semibold">{s.user}</Td>
                    <Td align="right" mono className="font-bold">{s.distinctSrc}</Td>
                    <Td align="right" mono>{s.hours}</Td>
                    <Td align="right" mono>{s.eventId}</Td>
                    <Td align="center">
                      <Icon
                        name={s.matched ? "alert-triangle" : "check"}
                        size={14}
                        style={{
                          color: s.matched ? "var(--color-bad)" : "var(--color-ok)",
                          display: "block",
                          margin: "0 auto",
                        }}
                      />
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        </CardBody>
      </Card>
      )}
    </div>
  );
}

/* =============================================================
   HISTORY
   ============================================================= */

function History() {
  const [q, setQ] = useState("");
  const rows = useMemo(
    () => RULEFORGE_HISTORY.filter((h) => (h.dialect + h.job + h.text).includes(q)),
    [q],
  );

  return (
    <div className="flex flex-col gap-5">
      <Callout tone="accent" title="Append-only by design">
        Every save writes a new entry and never rewrites an older one. A tuning session is
        evidence: the only way to answer what the rule looked like when it fired 400 times is
        if the earlier version still exists. There is no delete path, here or through the web
        layer.
      </Callout>

      <div className="grid sm:grid-cols-4 gap-4">
        <StatTile label="Entries" value={RULEFORGE_HISTORY.length} icon="clock" />
        <StatTile label="Dialects used" value={new Set(RULEFORGE_HISTORY.map((h) => h.dialect)).size} icon="file-code" tone="accent" />
        <StatTile label="Open problems" value={RULEFORGE_HISTORY.reduce((a, b) => a + b.problems, 0)} icon="alert-triangle" tone="bad" />
        <StatTile label="Storage" value="JSONL" icon="database" tone="info" />
      </div>

      <Card>
        <CardHead
          title="Session history"
          icon="clock"
          count={rows.length}
          action={
            <Input
              icon="search"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Filter…"
              className="w-48"
              dense
            />
          }
        />
        <Table>
          <thead>
            <tr>
              <Th>Dialect</Th>
              <Th>Job</Th>
              <Th>Rule ID</Th>
              <Th>Rule</Th>
              <Th align="center">Problems</Th>
              <Th align="right">When</Th>
            </tr>
          </thead>
          <tbody>
            {rows.map((h) => (
              <tr key={h.id} className="hover:bg-[var(--color-surface-2)]">
                <Td><Badge tone="accent" mono>{h.dialect}</Badge></Td>
                <Td className="font-semibold">{h.job}</Td>
                <Td mono className="text-[var(--color-ink-4)]">{h.ruleId}</Td>
                <Td mono className="max-w-[300px]">
                  <span className="block line-clamp-1">{h.text}</span>
                </Td>
                <Td align="center">
                  {h.problems > 0 ? (
                    <Badge tone="bad">{h.problems}</Badge>
                  ) : (
                    <Badge tone="ok">clean</Badge>
                  )}
                </Td>
                <Td align="right" className="text-[12px] text-[var(--color-ink-4)]">
                  {relativeTime(h.at)}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
    </div>
  );
}

/* =============================================================
   DIALECTS
   ============================================================= */

const DIALECT_DETAIL: Record<string, { target: string; notes: string[] }> = {
  splunk: { target: "Splunk Enterprise Security / Splunk Enterprise", notes: ["Full SPL with subsearches, lookups and macros", "Time modifiers such as earliest=-7d are evaluated at search time", "Field names are case-sensitive after the first command"] },
  kql: { target: "Microsoft Sentinel / Defender XDR", notes: ["summarize is the aggregation verb, not stats", "ago() and bin() for time bucketing, not earliest/latest", "Fields come from the normalized table schema, not raw event names"] },
  aql: { target: "Elasticsearch / OpenSearch", notes: ["Filters come first, aggregations after", "Field names are dotted and fully qualified, e.g. winlogbeat.event.code", "A filter after an aggregation references a bucket, not a document"] },
  eql: { target: "Elastic Endpoint / anyquery", notes: ["Category functions only: process, file, registry, network", "Sequential queries, so ordering is semantic and not stylistic", "No aggregation is expressible in EQL; anything that needs one is a different language"] },
  cql: { target: "CrowdStrike Falcon", notes: ["Repo selectors follow the Obsidian data model", "AGG and SORT are positional and have no expression form", "No free-text search; every field is named"] },
  fql: { target: "CrowdStrike Falcon platform query", notes: ["Newer set-based replacement for CQL", "Supports | groupBy, | join, | orderBy", "Still positional where a CQL query was"] },
  wazuh: { target: "Wazuh manager ruleset", notes: ["XML, one <group> per document", "Correlation rules count the parent, not their own condition", "level is 0-15 and unvalidated input reaches the artifact if nothing checks it"] },
  yaral: { target: "Sigma-style rules compiled to YARA", notes: ["Rules are a strict subset of YARA; a strict comparison is widened, not honoured", "External variables come from a config file, not the rule body", "Package and meta sections are validated on parse"] },
};

function Dialects({ navigate }: { navigate: (to: string) => void }) {
  const [sel, setSel] = useState("splunk");
  const d = RULEFORGE_DIALECTS.find((x) => x.id === sel)!;
  const detail = DIALECT_DETAIL[sel];

  return (
    <div className="flex flex-col gap-5">
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatTile label="Dialects" value={RULEFORGE_DIALECTS.length} icon="file-code" tone="accent" />
        <StatTile label="Backend tests" value="468" icon="check" tone="ok" />
        <StatTile label="Mutations caught" value="15/15" icon="shield" tone="ok" />
        <StatTile label="Telemetry" value="None" icon="lock" tone="info" />
      </div>

      <div className="grid lg:grid-cols-[300px_1fr] gap-5">
        <Card className="h-fit">
          <CardHead title="Dialects" icon="layers" count={RULEFORGE_DIALECTS.length} />
          <CardBody className="p-2 flex flex-col gap-1">
            {RULEFORGE_DIALECTS.map((x) => {
              const on = x.id === sel;
              return (
                <button
                  key={x.id}
                  onClick={() => setSel(x.id)}
                  className={cn(
                    "flex items-center gap-2.5 px-2.5 py-2.5 rounded-[var(--radius-sm)] text-left transition-colors",
                    on ? "" : "hover:bg-[var(--color-surface-3)]",
                  )}
                  style={on ? { background: "var(--tool-tint)" } : undefined}
                >
                  {/* min-w-8 rather than a fixed w-8: "YARA-L" is six
                      characters and wrapped onto two lines inside a 32px
                      square, which made that one row taller than the seven
                      above it. Auto-width with a floor keeps the rhythm
                      without truncating the longest alias. */}
                  <span
                    className="shrink-0 min-w-8 h-8 px-1.5 grid place-items-center rounded-[6px] whitespace-nowrap"
                    style={{
                      background: on ? "var(--tool-tint-2)" : "var(--color-surface-3)",
                      color: on ? "var(--tool-accent)" : "var(--color-ink-3)",
                    }}
                  >
                    <span className="mono text-[10.5px] font-black leading-none">{x.alias}</span>
                  </span>
                  <span className="min-w-0">
                    <span className="block text-[12.5px] font-semibold truncate">{x.label}</span>
                  </span>
                  {on && <Icon name="check" size={12} className="ml-auto" style={{ color: "var(--tool-accent)" }} />}
                </button>
              );
            })}
          </CardBody>
        </Card>

        <Card>
          <CardHead title={d.label} icon="file-code" subtitle={`Target: ${detail.target}`} />
          <CardBody className="flex flex-col gap-4">
            <div>
              <div className="text-[12px] font-bold text-[var(--color-ink-4)] mb-2">
                WHAT TRIPS ANALYSTS UP IN THIS DIALECT
              </div>
              <div className="flex flex-col gap-2">
                {detail.notes.map((n) => (
                  <div key={n} className="flex gap-2.5">
                    <Icon
                      name="alert-triangle"
                      size={13}
                      style={{ color: "var(--color-warn)", marginTop: 3, flexShrink: 0 }}
                    />
                    <p className="text-[13px] leading-relaxed" style={{ color: "var(--color-ink-2)" }}>
                      {n}
                    </p>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <div className="text-[12px] font-bold text-[var(--color-ink-4)] mb-2">
                TRANSLATION STATUS
              </div>
              <div className="flex flex-col gap-2">
                {RULEFORGE_DIALECTS.filter((x) => x.id !== sel).map((x) => (
                  <div key={x.id} className="flex items-center gap-2.5">
                    <Icon name="arrow-right" size={12} style={{ color: "var(--color-ink-4)" }} />
                    <Badge mono>{x.alias}</Badge>
                    <span className="flex-1 h-px" style={{ background: "var(--color-line)" }} />
                    <Badge tone="ok">supported</Badge>
                  </div>
                ))}
              </div>
            </div>
            <Callout tone="accent" title="Cross-tool value">
              A rule you tune here can be the detection you validate against the event logs in
              Event Analyzer.
              <div className="mt-2.5">
                <Button variant="subtle" size="xs" icon="activity" onClick={() => navigate("/t/events")}>
                  Open Event Analyzer
                </Button>
              </div>
            </Callout>
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHead title="Detecting what gets lost in translation" icon="search" />
        <CardBody>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { t: "Silent field drops", b: "A field that exists in one dialect and not another is reported by name, never quietly dropped." },
              { t: "Order-sensitive semantics", b: "Some dialects treat a trailing filter as pre-aggregation and some as post. The tool knows which is which." },
              { t: "Unrenderable nodes", b: "If a construct cannot be written in the target, it is named and refused rather than omitted." },
              { t: "Regex safety", b: "Catastrophic backtracking shapes are refused at parse time, in every dialect, before evaluation." },
            ].map((x) => (
              <div key={x.t}>
                <div className="text-[13px] font-bold mb-1.5 flex items-center gap-2">
                  <Icon name="shield" size={13} style={{ color: "var(--tool-accent)" }} />
                  {x.t}
                </div>
                <p className="text-[12.5px] leading-relaxed" style={{ color: "var(--color-ink-3)" }}>
                  {x.b}
                </p>
              </div>
            ))}
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
