/**
 * Event Analyzer's working surface, rebuilt to the original's own screens.
 *
 * Structure read from templates/index.html:
 *   :348 events — a Filters card with ten controls, a removable
 *          active-filter chip row, then the Events table with exports
 *   :449 iocs   — type filter chips, a search, and a table whose Value cell
 *          copies on click and whose Context cell expands in place
 *   :503 sigma  — level filter chips, a search, and a table whose row opens
 *          a detail view
 *   :557 notes  — free-text notes attached to the investigation
 *
 * The previous SecConflux version had a single search box and a level
 * dropdown. Ten of the original's filters, the removable chips, the
 * per-type and per-level filter bars and the pagination were all missing.
 */
import { useEffect, useMemo, useRef, useState } from "react";
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
  Kbd,
} from "../../ui";
import {
  EVTX_EVENTS,
  EVTX_IOCS,
  EVTX_SIGMA,
  EVTX_CHANNELS,
  EVTX_SOURCE_FILES,

} from "../../data/fixtures";
import { toast } from "../../shell/chrome";
import { Icon } from "../../lib/icons";

import { relativeTime, copyText, cn } from "../../lib/utils";

/* =============================================================
   EVENTS — filters card, active-filter chips, table, inline detail
   ============================================================= */

/* The original's detail is NOT a modal. It is an inline panel below the
   table, resizable by dragging its top edge, stepped through with the
   arrow keys, and reachable in the history stack via a breadcrumb
   (app.js:1530-1571, index.html:336). A modal changes three behaviours:
   the page behind is blocked, Escape is the only exit, and there is no
   "next event" without closing first. */
const MIN_DETAIL_H = 140;
const MAX_DETAIL_H = 620;
const DEFAULT_DETAIL_H = 260;

interface Filters {
  search: string;
  event_id: string;
  channel: string;
  process_name: string;
  command_line: string;
  user_name: string;
  hostname: string;
  source_file: string;
  start_time: string;
  end_time: string;
}

const EMPTY_FILTERS: Filters = {
  search: "",
  event_id: "",
  channel: "",
  process_name: "",
  command_line: "",
  user_name: "",
  hostname: "",
  source_file: "",
  start_time: "",
  end_time: "",
};

const FILTER_LABELS: Record<keyof Filters, string> = {
  search: "Text",
  event_id: "Event ID",
  channel: "Channel",
  process_name: "Process",
  command_line: "Command line",
  user_name: "User",
  hostname: "Hostname",
  source_file: "File",
  start_time: "Start",
  end_time: "End",
};

function EventsPanel(_props: { cache?: React.RefObject<Record<string, { page: number; filter: string }>> }) {
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [sort, setSort] = useState<"asc" | "desc">("asc");
  /* A cursor into the filtered set, not a modal target. -1 means closed. */
  const [cursor, setCursor] = useState(-1);
  const [detailH, setDetailH] = useState(DEFAULT_DETAIL_H);
  const [bookmarks, setBookmarks] = useState<Record<string, boolean>>({});
  const searchRef = useRef<HTMLInputElement>(null);
  const sortAsc = sort === "asc";

  const set = (k: keyof Filters) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setFilters((f) => ({ ...f, [k]: e.target.value }));

  /* The active-filter chips. Anything non-empty becomes a chip that can be
     removed individually, plus a "Clear all". */
  const activeFilters = useMemo(
    () =>
      (Object.keys(filters) as (keyof Filters)[])
        .filter((k) => filters[k])
        .map((k) => ({ key: k, label: FILTER_LABELS[k], value: filters[k] })),
    [filters],
  );

const rows = useMemo(() => {
    const f = filters;
    const out = EVTX_EVENTS.filter((e) => {
      if (f.search && !e.summary.toLowerCase().includes(f.search.toLowerCase())) return false;
      if (f.event_id && !String(e.eventId).includes(f.event_id)) return false;
      if (f.channel && e.channel !== f.channel) return false;
      if (f.process_name && !e.process.toLowerCase().includes(f.process_name.toLowerCase())) return false;
      if (f.command_line && !e.summary.toLowerCase().includes(f.command_line.toLowerCase())) return false;
      if (f.user_name && !e.user.toLowerCase().includes(f.user_name.toLowerCase())) return false;
      if (f.hostname && !e.computer.toLowerCase().includes(f.hostname.toLowerCase())) return false;
      if (f.source_file && e.sourceFile !== f.source_file) return false;
      if (f.start_time && e.timestamp < f.start_time) return false;
      if (f.end_time && e.timestamp > f.end_time) return false;
      return true;
    });
    return [...out].sort((a, b) =>
      sortAsc ? a.timestamp.localeCompare(b.timestamp) : b.timestamp.localeCompare(a.timestamp),
    );
  }, [filters, sortAsc]);

  const selected = cursor >= 0 ? rows[cursor] : null;
  const bookmarkCount = Object.values(bookmarks).filter(Boolean).length;

  /* app.js:1530-1571 — the original's keyboard contract.
     Escape closes the detail; Ctrl+/ or Alt+/ focuses and selects the search
     box; ArrowDown/ArrowUp step through events while the detail stays open,
     carrying across page boundaries in the original. Here the whole filtered
     set is one list, so stepping runs to its ends rather than across pages. */
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const inField =
        e.target instanceof HTMLElement &&
        (e.target.tagName === "INPUT" ||
          e.target.tagName === "TEXTAREA" ||
          e.target.tagName === "SELECT" ||
          e.target.isContentEditable);

      const isSearch =
        (e.key === "/" && e.ctrlKey && !e.shiftKey && !e.metaKey) ||
        (e.key === "/" && e.altKey && !e.shiftKey && !e.metaKey);

      if (isSearch) {
        e.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
        return;
      }
      if (e.key === "Escape" && cursor >= 0) {
        e.preventDefault();
        setCursor(-1);
        return;
      }
      if (cursor < 0 || inField) return;
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setCursor((c) => Math.min(rows.length - 1, c + 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setCursor((c) => Math.max(0, c - 1));
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [cursor, rows.length]);

  /* Drag the detail's top edge. Pointer capture, so the drag survives the
     pointer leaving the handle — otherwise it stalls halfway. */
  function startResize(e: React.PointerEvent<HTMLDivElement>) {
    e.preventDefault();
    const startY = e.clientY;
    const startH = detailH;
    const onMove = (ev: PointerEvent) => {
      const next = startH + (startY - ev.clientY);
      setDetailH(Math.max(MIN_DETAIL_H, Math.min(MAX_DETAIL_H, next)));
    };
    const onUp = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  }

  return (
    <div className="flex flex-col gap-4">
      {/* index.html:349 — the Filters card, ten controls */}
      <Card>
        <CardHead
          title="Filters"
          icon="filter"
          action={
            <>
              <Button
                variant="ghost"
                size="xs"
                icon="refresh"
                onClick={() => {
                  setFilters(EMPTY_FILTERS);
                  setCursor(-1);
                }}
              >
                Reset
              </Button>
              <Button variant="primary" size="xs" icon="check" onClick={() => setCursor(-1)}>
                Apply
              </Button>
            </>
          }
        />
        <CardBody>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            <Input
              dense
              icon="search"
              inputRef={searchRef}
              placeholder="Search text"
              value={filters.search}
              onChange={set("search")}
              aria-label="Search text"
            />
            <Input dense placeholder="Event ID" value={filters.event_id} onChange={set("event_id")} aria-label="Event ID filter" />
            <Select dense value={filters.channel} onChange={set("channel")} aria-label="Filter by channel">
              <option value="">All channels</option>
              {EVTX_CHANNELS.map((c) => (
                <option key={c.channel} value={c.channel}>{c.channel}</option>
              ))}
            </Select>
            <Input dense placeholder="Process name" value={filters.process_name} onChange={set("process_name")} aria-label="Filter by process name" />
            <Input dense placeholder="Command line" value={filters.command_line} onChange={set("command_line")} aria-label="Filter by command line" />
            <Input dense placeholder="User name" value={filters.user_name} onChange={set("user_name")} aria-label="Filter by user name" />
            <Input dense placeholder="Hostname" value={filters.hostname} onChange={set("hostname")} aria-label="Filter by hostname" />
            <Select dense value={filters.source_file} onChange={set("source_file")} aria-label="Filter by source file">
              <option value="">All files</option>
              {EVTX_SOURCE_FILES.map((f) => (
                <option key={f} value={f}>{f}</option>
              ))}
            </Select>
            <Input dense placeholder="Start (YYYY-MM-DD HH:MM:SS)" value={filters.start_time} onChange={set("start_time")} aria-label="Start time" />
            <Input dense placeholder="End (YYYY-MM-DD HH:MM:SS)" value={filters.end_time} onChange={set("end_time")} aria-label="End time" />
            <Select dense value={sort} onChange={(e) => setSort(e.target.value as "asc" | "desc")} aria-label="Sort order">
              <option value="asc">Oldest first</option>
              <option value="desc">Newest first</option>
            </Select>
          </div>
        </CardBody>
      </Card>

      {/* index.html:376 — removable active-filter chips */}
      {activeFilters.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[12px] font-bold" style={{ color: "var(--color-ink-4)" }}>
            Filters:
          </span>
          {activeFilters.map((f) => (
            <button
              key={f.key}
              onClick={() =>
                setFilters((prev) => ({ ...prev, [f.key]: "" }))
              }
              className="h-[22px] px-2 rounded-[5px] text-[11.5px] font-semibold border transition-colors"
              style={{
                background: "var(--tool-tint)",
                borderColor: "var(--tool-tint-2)",
                color: "var(--tool-accent)",
              }}
            >
              {f.label}: {f.value} <span className="opacity-60">×</span>
            </button>
          ))}
          <Button
            variant="ghost"
            size="xs"
            className="ml-auto"
            onClick={() => {
              setFilters(EMPTY_FILTERS);
              setCursor(-1);
            }}
          >
            Clear all
          </Button>
        </div>
      )}

{/* index.html:382 — the Events table with exports and bookmark count */}
      <Card>
        <CardHead
          title="Events"
          icon="list"
          action={
            <div className="flex items-center gap-3">
              <span className="text-[12px]" style={{ color: "var(--color-ink-4)" }}>
                Total: <strong style={{ color: "var(--color-ink-2)" }}>{rows.length}</strong>
              </span>
              {bookmarkCount > 0 && (
                <span className="text-[12px]" style={{ color: "var(--color-ink-4)" }}>
                  Bookmarks:{" "}
                  <strong style={{ color: "var(--tool-accent)" }}>{bookmarkCount}</strong>
                </span>
              )}
              <Button
                variant="ghost"
                size="xs"
                icon="download"
                onClick={() => toast(`Exported ${rows.length} events as CSV`)}
              >
                CSV
              </Button>
              <Button
                variant="ghost"
                size="xs"
                icon="download"
                onClick={() => toast(`Exported ${rows.length} events as JSON`)}
              >
                JSON
              </Button>
            </div>
          }
        />
        <Table>
          <thead>
            <tr>
              <Th align="center" className="w-10"></Th>
              <Th align="right" className="w-14">S.No</Th>
              <Th align="right" className="w-36">Time</Th>
              <Th align="right" className="w-24">Event ID</Th>
              <Th align="left">Computer</Th>
              <Th align="left">User</Th>
              <Th align="left">Summary</Th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <Td colSpan={7} align="center" className="py-8">
                  <span style={{ color: "var(--color-ink-4)" }}>
                    No events match these filters.
                  </span>
                </Td>
              </tr>
            )}
            {rows.map((e, i) => (
              <tr
                key={e.id}
                onClick={() => setCursor(i)}
                className={cn(
                  "cursor-pointer hover:bg-[var(--color-surface-2)]",
                  i === cursor && "bg-[var(--tool-tint)]",
                )}
              >
                <Td align="center">
                  <button
                    onClick={(ev) => {
                      ev.stopPropagation();
                      setBookmarks((b) => ({ ...b, [e.id]: !b[e.id] }));
                    }}
                    aria-label="Bookmark event"
                  >
                    <Icon
                      name="bookmark"
                      size={13}
                      style={{
                        color: bookmarks[e.id]
                          ? "var(--tool-accent)"
                          : "var(--color-ink-4)",
                        display: "block",
                        margin: "0 auto",
                      }}
                    />
                  </button>
                </Td>
                <Td align="right" mono style={{ color: "var(--color-ink-4)" }}>
                  {e.number}
                </Td>
                <Td align="right" mono className="text-[11.5px]">
                  {e.timestamp.slice(11, 23)}
                </Td>
                <Td align="right" mono className="font-bold">
                  {e.eventId}
                </Td>
                <Td mono className="text-[11.5px]">{e.computer}</Td>
                <Td mono className="text-[11.5px]">
                  {e.user.split("\\")[1] ?? e.user}
                </Td>
                <Td>
                  <span className="block max-w-[520px] truncate text-[12.5px]">
                    {e.summary}
                  </span>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>

      {/* index.html:336 — the breadcrumb. Present only while something is
          open, and the root closes it, which is the original's navTo(0). */}
      {selected && (
        <nav
          className="flex items-center gap-2 text-[12.5px] flex-wrap"
          aria-label="Breadcrumb"
        >
          <button
            onClick={() => setCursor(-1)}
            className="font-semibold hover:underline"
            style={{ color: "var(--color-ink-3)" }}
          >
            Investigation
          </button>
          <span style={{ color: "var(--color-line-3)" }}>/</span>
          <span className="font-semibold" style={{ color: "var(--tool-accent)" }}>
            {`Event ${selected.eventId} · ${selected.timestamp.slice(11, 19)}`}
          </span>
          <span className="ml-auto flex items-center gap-1.5">
            <Kbd>↑</Kbd>
            <Kbd>↓</Kbd>
            <span className="text-[11.5px]" style={{ color: "var(--color-ink-4)" }}>
              step
            </span>
            <Kbd>Esc</Kbd>
            <span className="text-[11.5px]" style={{ color: "var(--color-ink-4)" }}>
              close
            </span>
          </span>
        </nav>
      )}

      {/* The inline detail panel — NOT a modal. The original keeps the table
          live above it, which is the entire point of arrow-key stepping
          (app.js:983 openEvent, :1566 stepSelection, :1578 clampDetailHeight). */}
      {selected && (
        <Card className="relative overflow-hidden">
          <div
            onPointerDown={startResize}
            role="separator"
            aria-orientation="horizontal"
            aria-label="Resize detail"
            className="absolute inset-x-0 top-0 h-2 cursor-ns-resize z-10"
            style={{ background: "var(--color-line)" }}
          >
            <span
              className="absolute left-1/2 -translate-x-1/2 top-1/2 -translate-y-1/2 w-9 h-[3px] rounded-full"
              style={{ background: "var(--color-line-3)" }}
            />
          </div>

          <div className="overflow-y-auto px-4 pt-5 pb-4" style={{ height: detailH }}>
            <div className="grid md:grid-cols-2 gap-x-6">
              <div>
                <KV label="Event ID" mono copyable>
                  {selected.eventId}
                </KV>
                <KV label="Provider" mono copyable>
                  {selected.provider}
                </KV>
                <KV label="Channel" mono copyable>
                  {selected.channel}
                </KV>
                <KV label="Computer" mono copyable>
                  {selected.computer}
                </KV>
                <KV label="User" mono copyable>
                  {selected.user}
                </KV>
              </div>
              <div>
                <KV label="Process" mono copyable>
                  {selected.process}
                </KV>
                <KV label="Source file" mono copyable>
                  {selected.sourceFile}
                </KV>
                <KV label="Level">{selected.levelName}</KV>
                <KV label="Position in result set">
                  {cursor + 1} of {rows.length}
                </KV>
                <KV label="Bookmarked">{bookmarks[selected.id] ? "Yes" : "No"}</KV>
              </div>
            </div>

            <div className="mt-4">
              <div
                className="text-[12.5px] mb-1.5"
                style={{ color: "var(--color-ink-4)" }}
              >
                Rendered body
              </div>
              <CodeBlock
                code={selected.body ?? selected.summary}
                language="event"
                maxHeight={Math.max(80, detailH - 190)}
              />
            </div>

            {selected.eventId === 1102 && (
              <Callout tone="bad" title="Anti-forensic indicator" className="mt-3">
                A cleared audit log is one of the highest-signal events in this
                dataset. It means whoever did it knew what the logs would show.
              </Callout>
            )}
          </div>

          <div
            className="flex items-center justify-between gap-3 px-4 py-2.5 border-t"
            style={{ borderColor: "var(--color-line)" }}
          >
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="xs"
                disabled={cursor <= 0}
                onClick={() => setCursor(Math.max(0, cursor - 1))}
              >
                <Icon name="chevron-right" size={12} style={{ transform: "rotate(180deg)" }} />
                Previous
              </Button>
              <Button
                variant="ghost"
                size="xs"
                disabled={cursor >= rows.length - 1}
                onClick={() => setCursor(Math.min(rows.length - 1, cursor + 1))}
              >
                Next
                <Icon name="chevron-right" size={12} />
              </Button>
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="xs"
                icon="bookmark"
                onClick={() =>
                  setBookmarks((b) => ({ ...b, [selected.id]: !b[selected.id] }))
                }
              >
                {bookmarks[selected.id] ? "Unbookmark" : "Bookmark"}
              </Button>
              <Button variant="secondary" size="xs" onClick={() => setCursor(-1)}>
                Close
              </Button>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}

/* =============================================================
   IOCs — type filter chips, expandable context, copy-on-click
   ============================================================= */

function IocsPanel({ cache }: { cache: React.RefObject<Record<string, { page: number; filter: string }>> }) {
  const [type, setType] = useState(() => cache.current.iocs?.filter ?? "");
  const [q, setQ] = useState("");
  useEffect(() => {
    return () => {
      cache.current.iocs = { page: 0, filter: type };
    };
  }, [cache, type]);
  const [expanded, setExpanded] = useState<string | null>(null);

  const byType = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const i of EVTX_IOCS) counts[i.type] = (counts[i.type] ?? 0) + 1;
    return counts;
  }, []);

  const rows = EVTX_IOCS.filter(
    (i) =>
      (!type || i.type === type) &&
      (!q || i.value.toLowerCase().includes(q.toLowerCase()) || i.context.toLowerCase().includes(q.toLowerCase())),
  );

  return (
    <Card>
      <CardHead
        title={`Extracted IOCs (${EVTX_IOCS.length})`}
        icon="target"
        action={
          <>
            <Button variant="ghost" size="xs" icon="download" onClick={() => toast(`Exported ${EVTX_IOCS.length} IOCs as CSV`)}>
              CSV
            </Button>
            <Button variant="ghost" size="xs" icon="download" onClick={() => toast(`Exported ${EVTX_IOCS.length} IOCs as JSON`)}>
              JSON
            </Button>
          </>
        }
      />

      {/* index.html:460 — type filter bar */}
      <div
        className="flex items-center gap-2 px-4 py-2.5 border-b flex-wrap"
        style={{ borderColor: "var(--color-line)" }}
      >
        <FilterChip active={!type} onClick={() => setType("")}>
          All ({EVTX_IOCS.length})
        </FilterChip>
        {Object.entries(byType).map(([t, n]) => (
          <FilterChip key={t} active={type === t} onClick={() => setType(t)}>
            {t} ({n})
          </FilterChip>
        ))}
        <div className="ml-auto w-[240px]">
          <Input
            dense
            icon="search"
            placeholder="Search IOC values…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
      </div>

      <Table>
        <thead>
          <tr>
            <Th>Type</Th>
            <Th>Value</Th>
            <Th>Source</Th>
            <Th align="right">Cnt</Th>
            <Th>Context</Th>
            <Th align="right"></Th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <Td colSpan={6} align="center" className="py-8">
                <span style={{ color: "var(--color-ink-4)" }}>
                  No IOCs match your search.
                </span>
              </Td>
            </tr>
          )}
          {rows.map((i) => {
            const open = expanded === i.value;
            return (
              <tr key={i.value} className="hover:bg-[var(--color-surface-2)]">
                <Td>
                  <span
                    className="mono text-[10.5px] font-bold px-1.5 py-0.5 rounded-[4px]"
                    style={{
                      background: "var(--tool-tint)",
                      color: "var(--tool-accent)",
                    }}
                  >
                    {i.type}
                  </span>
                </Td>
                {/* index.html:475 — click to copy */}
                <td
                  className="px-3 py-2.5 cursor-pointer mono text-[12px]"
                  title={`Click to copy: ${i.value}`}
                  onClick={async () => {
                    if (await copyText(i.value)) toast(`Copied ${i.value}`);
                  }}
                >
                  {i.value}
                </td>
                <Td className="text-[12px]" style={{ color: "var(--color-ink-4)" }}>
                  {i.source ?? "—"}
                </Td>
                <Td align="right">
                  <span
                    className="mono text-[12px] font-bold cursor-pointer"
                    style={{
                      color:
                        i.hits > 1 ? "var(--color-warn)" : "var(--color-ink-3)",
                    }}
                    title={`Show ${i.hits} events`}
                  >
                    {i.hits}
                  </span>
                </Td>
                {/* index.html:481 — expands in place */}
                <Td>
                  <button
                    onClick={() => setExpanded(open ? null : i.value)}
                    className="text-left text-[12px] w-full"
                    style={{ color: "var(--color-ink-3)" }}
                  >
                    <span className={cn(open ? "whitespace-pre-wrap" : "truncate", "block")}>
                      {i.context}
                    </span>
                    {i.context.length > 60 && (
                      <span
                        className="text-[10.5px] font-bold ml-1"
                        style={{ color: "var(--tool-accent)" }}
                      >
                        {open ? "▲ less" : "▼ more"}
                      </span>
                    )}
                  </button>
                </Td>
                <Td align="right">
                  <Button variant="ghost" size="xs" onClick={() => toast(`${i.hits} events carry ${i.value}`)}>
                    Events
                  </Button>
                </Td>
              </tr>
            );
          })}
        </tbody>
      </Table>
    </Card>
  );
}

/* =============================================================
   SIGMA — level chips, row opens a detail
   ============================================================= */

function SigmaPanel({ cache }: { cache: React.RefObject<Record<string, { page: number; filter: string }>> }) {
  const [level, setLevel] = useState(() => cache.current.sigma?.filter ?? "");
  useEffect(() => {
    return () => {
      cache.current.sigma = { page: 0, filter: level };
    };
  }, [cache, level]);
  const [q, setQ] = useState("");
  const [detail, setDetail] = useState<(typeof EVTX_SIGMA)[number] | null>(null);

  const byLevel = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const s of EVTX_SIGMA) counts[s.level] = (counts[s.level] ?? 0) + 1;
    return counts;
  }, []);

  const rows = EVTX_SIGMA.filter(
    (s) =>
      (!level || s.level === level) &&
      (!q || s.rule.toLowerCase().includes(q.toLowerCase()) || s.category.toLowerCase().includes(q.toLowerCase())),
  );

  const toneFor = (l: string) =>
    l === "critical" || l === "high" ? "bad" : l === "medium" ? "warn" : "info";

  return (
    <>
      <Card>
        <CardHead
          title={`Sigma Rule Matches (${EVTX_SIGMA.length})`}
          icon="check"
          action={
            <>
              <Button variant="ghost" size="xs" icon="download" onClick={() => toast("Exported Sigma matches as CSV")}>
                CSV
              </Button>
              <Button variant="ghost" size="xs" icon="download" onClick={() => toast("Exported Sigma matches as JSON")}>
                JSON
              </Button>
            </>
          }
        />

        {/* index.html:514 — level filter bar */}
        <div
          className="flex items-center gap-2 px-4 py-2.5 border-b flex-wrap"
          style={{ borderColor: "var(--color-line)" }}
        >
          <FilterChip active={!level} onClick={() => setLevel("")}>
            All ({EVTX_SIGMA.length})
          </FilterChip>
          {Object.entries(byLevel).map(([l, n]) => (
            <FilterChip key={l} active={level === l} onClick={() => setLevel(l)}>
              {l} ({n})
            </FilterChip>
          ))}
          <div className="ml-auto w-[280px]">
            <Input
              dense
              icon="search"
              placeholder="Search rules, MITRE, description…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
        </div>

        <Table>
          <thead>
            <tr>
              <Th align="left">Level</Th>
              <Th align="left">Rule</Th>
              <Th align="right">Cnt</Th>
              <Th align="left">Description</Th>
              <Th align="left">MITRE</Th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <Td colSpan={5} align="center" className="py-8">
                  <span style={{ color: "var(--color-ink-4)" }}>
                    No rules match your search.
                  </span>
                </Td>
              </tr>
            )}
            {rows.map((s) => (
              <tr
                key={s.rule}
                onClick={() => setDetail(s)}
                className="hover:bg-[var(--color-surface-2)] cursor-pointer"
              >
                <Td>
                  <Badge tone={toneFor(s.level)}>{s.level}</Badge>
                </Td>
                <Td>
                  <span className="block text-[12.5px] font-semibold">{s.rule}</span>
                  <span
                    className="block mono text-[10.5px]"
                    style={{ color: "var(--color-ink-4)" }}
                  >
                    sigma.rules.{s.level}
                  </span>
                </Td>
                <Td align="right" mono className="font-bold">
                  {s.hits}
                </Td>
                <Td>
                  <span className="block max-w-[380px] truncate text-[12px]">
                    {s.category}
                  </span>
                </Td>
<Td>
                  <span className="flex gap-1 flex-wrap">
                    {(s.mitre ?? []).map((m) => (
                      <span
                        key={m}
                        className="mono text-[10px] px-1 rounded-[3px]"
                        style={{
                          background: "rgb(168 85 247 / 0.12)",
                          color: "var(--color-magic)",
                        }}
                      >
                        {m}
                      </span>
                    ))}
                    {(s.mitre ?? []).length === 0 && (
                      <span className="text-[11px]" style={{ color: "var(--color-ink-4)" }}>
                        —
                      </span>
                    )}
                  </span>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>

      {/* index.html:336 / app.js:521 pushNav('Rule: …', 'sigma', …) —
          a Sigma rule detail is a breadcrumb entry, not a modal. Same reason
          as the event detail: the list stays visible and navigable behind it. */}
      {detail && (
        <nav
          className="flex items-center gap-2 text-[12.5px] flex-wrap"
          aria-label="Breadcrumb"
        >
          <button
            onClick={() => setDetail(null)}
            className="font-semibold hover:underline"
            style={{ color: "var(--color-ink-3)" }}
          >
            Investigation
          </button>
          <span style={{ color: "var(--color-line-3)" }}>/</span>
          <span className="font-semibold" style={{ color: "var(--tool-accent)" }}>
            {`Rule: ${detail.rule}`}
          </span>
        </nav>
      )}

      {detail && (
        <Card>
          <CardHead
            title={`Rule: ${detail.rule}`}
            icon="check"
            subtitle="Sigma rule match"
            action={
              <Badge tone={toneFor(detail.level)}>{detail.level}</Badge>
            }
          />
          <CardBody className="flex flex-col gap-3">
            <KV label="Matches">{detail.hits} events</KV>
            <KV label="Technique category">{detail.category}</KV>
            {(detail.mitre ?? []).length > 0 && (
              <KV label="MITRE techniques">
                <span className="flex gap-1">
                  {(detail.mitre ?? []).map((m) => (
                    <span
                      key={m}
                      className="mono text-[10px] px-1 rounded-[3px]"
                      style={{
                        background: "rgb(168 85 247 / 0.12)",
                        color: "var(--color-magic)",
                      }}
                    >
                      {m}
                    </span>
                  ))}
                </span>
              </KV>
            )}
            <Callout tone="warn" title="What a hit means">
              The rule matched {detail.hits} events in this investigation. The
              events themselves are on the Events tab — filter by the rule's
              technique to see them.
            </Callout>
            <div className="flex justify-end">
              <Button variant="secondary" size="xs" onClick={() => setDetail(null)}>
                Close
              </Button>
            </div>
          </CardBody>
        </Card>
      )}
    </>
  );
}

function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className="h-[24px] px-2.5 rounded-[6px] text-[11.5px] font-semibold border transition-colors"
      style={{
        background: active ? "var(--tool-tint)" : "transparent",
        borderColor: active ? "var(--tool-tint-2)" : "var(--color-line-2)",
        color: active ? "var(--tool-accent)" : "var(--color-ink-4)",
      }}
    >
      {children}
    </button>
  );
}

/* =============================================================
   NOTES
   ============================================================= */

interface Note {
  id: string;
  at: string;
  text: string;
}

function NotesPanel() {
  const KEY = "secconflux.notes";
  const [notes, setNotes] = useState<Note[]>(() => {
    try {
      return JSON.parse(localStorage.getItem(KEY) ?? "null") ?? [];
    } catch {
      return [];
    }
  });
  const [draft, setDraft] = useState("");
  const [editing, setEditing] = useState<string | null>(null);

  function persist(next: Note[]) {
    setNotes(next);
    try {
      localStorage.setItem(KEY, JSON.stringify(next));
    } catch {
      /* non-fatal: the note stays on screen */
    }
  }

  function save() {
    const text = draft.trim();
    if (!text) return;
    if (editing) {
      persist(notes.map((n) => (n.id === editing ? { ...n, text } : n)));
    } else {
      persist([{ id: `n${Date.now()}`, at: new Date().toISOString(), text }, ...notes]);
    }
    setDraft("");
    setEditing(null);
  }

  return (
    <Card>
      <CardHead
        title="Investigation Notes"
        icon="bookmark"
        count={notes.length}
        subtitle="Attached to this investigation, so the reasoning outlives the session"
      />
      <CardBody className="flex flex-col gap-4">
        <div className="flex flex-col sm:flex-row gap-2">
          <Input
            dense
            autoFocus
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && save()}
            placeholder="What did you conclude, and from which event?"
            className="flex-1"
          />
          <div className="flex gap-2">
            {editing && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setEditing(null);
                  setDraft("");
                }}
              >
                Cancel
              </Button>
            )}
            <Button variant="primary" size="sm" icon="plus" disabled={!draft.trim()} onClick={save}>
              {editing ? "Save" : "Add note"}
            </Button>
          </div>
        </div>

        {notes.length === 0 ? (
          <EmptyState
            compact
            icon="bookmark"
            title="No notes yet"
            body="An investigation that concludes nothing in writing did not conclude. The next analyst will have to start from the raw events again."
          />
        ) : (
          <div className="flex flex-col gap-2">
            {notes.map((n) => (
              <div
                key={n.id}
                className="flex items-start gap-3 p-3 rounded-[var(--radius-md)]"
                style={{
                  background: "var(--color-surface-2)",
                  border: "1px solid var(--color-line)",
                }}
              >
                <div className="min-w-0 flex-1">
                  <p className="text-[13px] leading-relaxed">{n.text}</p>
                  <p className="text-[11px] mt-1" style={{ color: "var(--color-ink-4)" }}>
                    {relativeTime(n.at)}
                  </p>
                </div>
                <div className="flex gap-1 shrink-0">
                  <Button
                    variant="ghost"
                    size="xs"
                    icon="file-code"
                    onClick={() => {
                      setEditing(n.id);
                      setDraft(n.text);
                    }}
                  >
                    Edit
                  </Button>
                  <Button
                    variant="ghost"
                    size="xs"
                    icon="trash"
                    onClick={() => persist(notes.filter((x) => x.id !== n.id))}
                  >
                    Delete
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}

export { EventsPanel, IocsPanel, SigmaPanel, NotesPanel };
