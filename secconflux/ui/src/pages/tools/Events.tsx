import { useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  Card,
  Button,
  Badge,
  Callout,
  DropZone,
  Modal,
  ProgressBar,
} from "../../ui";
import { ToolLanding, NextStepNote } from "./ToolLanding";
import {
  EventsPanel,
  IocsPanel,
  SigmaPanel,
  NotesPanel,
} from "./EventsPanels";
import { useShell } from "../../lib/shell-context";
import { toast } from "../../shell/chrome";
import { relativeTime } from "../../lib/utils";



export function EventsPage(_: { navigate: (to: string) => void }) {
  const { mainTab, subTab, actionsSlot } = useShell();
  const [ingestOpen, setIngestOpen] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const [stage, setStage] = useState("");

  const headerAction = actionsSlot
    ? createPortal(
        <Button
          variant="primary"
          size="sm"
          icon="upload"
          onClick={() => setIngestOpen(true)}
        >
          Ingest EVTX
        </Button>,
        actionsSlot,
      )
    : null;

  return (
    <div className="sc-anim-in">
      {headerAction}

      <div className="max-w-[1400px] mx-auto px-5 py-6">
        {progress !== null && (
          <Card glow className="p-5 mb-5">
            <div className="flex items-center gap-4 mb-3">
              <span
                className="grid place-items-center w-10 h-10 rounded-[var(--radius-md)]"
                style={{ background: "var(--tool-tint)", color: "var(--tool-accent)" }}
              >
                <span
                  className="w-4.5 h-4.5 rounded-full border-2 border-current border-t-transparent"
                  style={{ animation: "sc-spin 0.7s linear infinite" }}
                />
              </span>
              <div className="flex-1 min-w-0">
                <div className="text-[14px] font-bold">{stage}</div>
                <div className="text-[12px]" style={{ color: "var(--color-ink-4)" }}>
                  Parsing EVTX binary records and indexing for full-text search
                </div>
              </div>
              <span className="text-[20px] font-black tabular-nums" style={{ color: "var(--tool-accent)" }}>
                {progress}%
              </span>
            </div>
            <ProgressBar value={progress} striped height={6} />
          </Card>
        )}

        {mainTab === "overview" ? (
          <ToolLanding
            toolId="events"
            copy={{
              eyebrow: "EVTX Investigation Viewer",
              headline: ["Upload. Parse.", "Investigate."],
              subtext:
                "Upload Windows .evtx files, parse them with a Rust backend, and search everything in a local SQLite index. Analysts get details, freshers get structure, leaders get exports.",
              primaryCta: "Start Investigation",
              onPrimary: () => setIngestOpen(true),
              terminal: {
                file: "events.json",
                body: "json",
                json: [
                  "{",
                  '  "timestamp": "2025-11-03T14:22:18",',
                  '  "event_id": 4688,',
                  '  "provider": "Microsoft-Windows-Security-Auditing",',
                  '  "channel": "Security",',
                  '  "computer": "DC-01",',
                  '  "user": "CORP\\\\jdoe",',
                  '  "description": "A new process has been created."',
                  "}",
                ],
              },
              stats: [
                { value: "Rust", label: "Parser backend" },
                { value: "SQLite", label: "Searchable index" },
                { value: "CSV", label: "Export format" },
                { value: "JSON", label: "Export format" },
              ],
              sectionEyebrow: "Workflow",
              sectionTitle: "Four steps from log to insight",
              sectionBody:
                "Ingest an export, search every rendered field, read the indicators that fall out of the text, and write down what you concluded. The index is local, so a log containing someone else's data never leaves the machine.",
              features: [
                {
                  title: "Ingest EVTX exports",
                  body: "Security, System, Sysmon, PowerShell or any other channel, exported with wevtutil epl or from the live event viewer. Progress is reported per parsing stage rather than a single spinner.",
                  tags: ["wevtutil", "sysmon", "security", "powershell"],
                  tagTone: "neutral",
                },
                {
                  title: "Search every field",
                  body: "Event bodies are rendered to text and written into an FTS5 index, so a search runs against the index instead of filtering after loading everything into memory.",
                  tags: ["fts5", "sqlite", "full-text"],
                  tagTone: "info",
                },
                {
                  title: "Extract indicators",
                  body: "Addresses, domains, paths, registry keys and mutexes pulled from the rendered text by pattern, each carrying the event it came from, so a 5145 share access surfaces without anyone searching for it.",
                  tags: ["ips", "domains", "paths", "mutexes"],
                  tagTone: "ok",
                },
                {
                  title: "Match Sigma rules",
                  body: "The bundled ruleset is evaluated against the same rendered text, giving a per-rule hit count and the technique category, rather than a silent pass.",
                  tags: ["sigma", "techniques", "hits"],
                  tagTone: "info",
                },
                {
                  title: "Note your conclusions",
                  body: "Notes live with the investigation, so the reasoning survives after the logs are gone and the next analyst does not start from scratch.",
                  tags: ["notes", "evidence"],
                  tagTone: "neutral",
                },
                {
                  title: "Export what you found",
                  body: "CSV and JSON exports of the events, the indicators and the rule hits, for a ticket or for a pipeline that wants to keep them.",
                  tags: ["csv", "json"],
                  tagTone: "ok",
                },
              ],
              workflow: {
                eyebrow: "Pipeline",
                layout: "timeline",
                title: "From raw logs to actionable results",
                steps: [
                  { num: "01", title: "Upload", body: "Drag-drop .evtx files or folders into the investigation." },
                  { num: "02", title: "Parse", body: "Rust EVTX parser extracts every event into a searchable SQLite index." },
                  { num: "03", title: "Investigate", body: "Search, filter, and review events with full raw data and detail views." },
                  { num: "04", title: "Export", body: "Download CSV or JSON for SIEM ingestion and incident documentation." },
                ],
              },
              after: (
                <div className="mt-14">
                  <NextStepNote
                    toolId="events"
                    links={[
                      { to: "ioc", text: "every indicator the logs contain, in one enrichment run" },
                      { to: "ruleforge", text: "the Sigma rules that matched, ready to tune" },
                    ]}
                  />
                </div>
              ),
            }}
          />
        ) : (
          <InvestigationTab section={subTab} />
        )}
         
      </div>

      <Modal
        open={ingestOpen}
        onClose={() => setIngestOpen(false)}
        title="Ingest Windows event logs"
        subtitle="Upload one or more .evtx exports. They are parsed, indexed and made searchable."
        width={600}
        footer={
          <>
            <Button variant="ghost" onClick={() => setIngestOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={() => {
                setIngestOpen(false);
                runIngest(setProgress, setStage);
              }}
            >
              Start ingestion
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <DropZone
            icon="file"
            title="Drop .evtx files here or click to browse"
            hint="Exports from wevtutil epl, Event Viewer, or the live Security, System and Sysmon channels."
            onFile={(f) => {
              setIngestOpen(false);
              runIngest(setProgress, setStage, f.name);
            }}
          />
          <Callout tone="accent" title="What happens to your upload">
            Files are parsed on this machine. Event bodies are rendered to text and written to
            a local SQLite database with an FTS5 index, which is what makes the search box
            below instant across tens of thousands of events.
          </Callout>
        </div>
      </Modal>
    </div>
  );
}

function runIngest(
  setProgress: (v: number | null) => void,
  setStage: (v: string) => void,
  name = "FIN-WKS-07_2026-09-26.evtx",
) {
  const stages = [
    "Reading EVTX chunk headers",
    "Decoding record templates",
    "Rendering event bodies to text",
    "Building FTS5 search index",
    "Mapping MITRE techniques",
    "Extracting indicators",
    "Running bundled Sigma rules",
  ];
  stages.forEach((s, i) => {
    window.setTimeout(() => {
      setStage(s);
      setProgress(Math.round(((i + 1) / stages.length) * 100));
    }, i * 500);
  });
  window.setTimeout(() => {
    setProgress(100);
    window.setTimeout(() => {
      setProgress(null);
      toast(`${name} ingested · 41,882 events indexed`, "ok");
    }, 900);
  }, stages.length * 500 + 400);
}

/* =============================================================
   OVERVIEW
   ============================================================= */

function InvestigationTab({ section }: { section: string }) {
  /* app.js:321-350 — setSubTab stashes the IOC page and filter, and the Sigma
     page and level, under "<investigationId>-<subtab>" before switching away,
     then restores them when you come back.

     Without it, narrowing the IOC list to one type, reading the Sigma hits
     for one level, and going back to the Events table to check something
     loses both filters — and an analyst who has just been told the filters
     reset will stop trusting the tool. The cache is keyed per investigation,
     so two investigations do not inherit each other's view. */
  const cache = useRef<Record<string, { page: number; filter: string }>>({});

  /* No effect here on purpose.
     An earlier version had one that cleared the outgoing section's entry when
     `section` changed. React runs child effects BEFORE parent effects, so on
     the render that swaps panels the sequence was:
       1. IocsPanel cleanup saves  cache.iocs = { filter: "domain" }
       2. this effect overwrites  cache.iocs = { filter: "" }
     The save was destroyed one step after it happened, which is why the
     filter appeared not to persist. The panels own their own cache; the
     parent only has to keep the same ref alive across the swap. */
  void cache;

  return (
    <div className="flex flex-col gap-5">
      <Card glow className="p-5">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="min-w-0">
            <div className="flex items-center gap-2.5 flex-wrap mb-2">
              <Badge tone="ok" dot>ready</Badge>
              <Badge tone="info">4 files</Badge>
              <Badge>FIN-WKS-07</Badge>
            </div>
            <h1 className="text-[20px] font-extrabold tracking-[-0.02em]">
              FIN-WKS-07 lateral movement
            </h1>
            <p className="text-[12.5px] mt-1" style={{ color: "var(--color-ink-4)" }}>
              Created {relativeTime("2026-09-26T08:12:00Z")} · 41,882 events ·
              12 computers · 34 users · indexed with FTS5
            </p>
          </div>
          <div className="flex gap-2">
            <Button
              variant="secondary"
              size="sm"
              icon="download"
              onClick={() => toast("Exported 41,882 events as CSV")}
            >
              Export
            </Button>
            <Button
              variant="subtle"
              size="sm"
              icon="target"
              onClick={() => toast("Opening 214 IOCs in IOC Lookup")}
            >
              Enrich IOCs
            </Button>
          </div>
        </div>
      </Card>

      {/* The section selector is the header's chip row, not a second tab
          strip. Duplicating it here would give the same four choices two
          different homes, and the two would drift.

          These four are Event Analyzer's OWN sub-tabs — Events, IOCs, Sigma,
          Notes — in its own order. A Timeline, a Channels tab and a Bookmarks
          tab were added in an earlier pass and did not belong to the tool. */}
      {section === "events" && <EventsPanel cache={cache} />}
      {section === "iocs" && <IocsPanel cache={cache} />}
      {section === "sigma" && <SigmaPanel cache={cache} />}
      {section === "notes" && <NotesPanel />}
    </div>
  );
}
