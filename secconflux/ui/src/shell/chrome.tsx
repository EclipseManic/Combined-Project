import { Component, forwardRef, useEffect, useId, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Icon } from "../lib/icons";
import type { IconName } from "../lib/icons";
import { TOOLS, TOOL_BY_ID, LANDING_ORDER, MAIN_TABS, SUB_TABS } from "../lib/tools";
import type { ToolId, NavTab } from "../lib/tools";
import { useShell, hotkeyIndex } from "../lib/shell-context";
import { cn } from "../lib/utils";
import { Kbd } from "../ui";
import { useEdgeFade } from "../lib/useEdgeFade";
import { useTabKeyNav } from "../lib/useTabKeyNav";
import { useScrollLock } from "../lib/useScrollLock";

export const TOOL_ICON: Record<ToolId, IconName> = {
  home: "home",
  malware: "bug",
  ioc: "target",
  events: "activity",
  phishing: "mail",
  ruleforge: "terminal",
};

/* =============================================================
   BRAND MARK
   ============================================================= */

/**
 * The brand mark. The gradient id is generated per instance, and the colours
 * are the BRAND tokens rather than the tool's.
 *
 * This component renders in the header, in the tour and in the tour's header
 * miniature, all in the same document. A hard-coded `id="sc-mark"` put three
 * elements with the same id on the page, and `url(#sc-mark)` always resolves
 * to the FIRST match in document order — so every copy painted with whichever
 * tool's accent happened to be in the header.
 *
 * `--brand`, not `--tool-accent`: the mark must look the same on every tool,
 * or it stops reading as the platform.
 */
export function SecConfluxMark({ size = 30 }: { size?: number }) {
  const gid = useId().replace(/:/g, "");
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      aria-hidden="true"
      style={{ display: "block", flexShrink: 0 }}
    >
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="var(--brand)" />
          <stop offset="100%" stopColor="var(--brand-2)" />
        </linearGradient>
      </defs>
      <path
        d="M16 2.5l3.3 6.7 7.4 1.1-5.3 5.2 1.2 7.3L16 19.5 9.4 22.8l1.2-7.3-5.3-5.2 7.4-1.1L16 2.5z"
        fill={`url(#${gid})`}
      />
      <circle cx="16" cy="15.4" r="2.6" fill="var(--color-canvas)" />
    </svg>
  );
}

/* =============================================================
   HEADER
   ============================================================= */

export const AppHeader = forwardRef<HTMLElement, { navigate: (to: string) => void }>(
  function AppHeader({ navigate }, ref) {
  const {
    tool,
    setTool,
    mainTab,
    setMainTab,
    subTab,
    setSubTab,
    setActionsSlot,
    theme,
    toggleTheme,
    setPaletteOpen,
    setTourOpen,
  } = useShell();
  const main = MAIN_TABS[tool];
  const subs = SUB_TABS[tool];
  const { ref: chipRef, fade: chipFade } = useEdgeFade<HTMLDivElement>();

  /* Arrow keys across the centre strip, wrapping, with DOM focus following.
     Copied from the IOC original's useTabsKeyNav
     (ioc-platform/ui/src/App.tsx:69). Without this the strip is reachable only
     by Tab or mouse, and at six entries that is the difference between
     "the keyboard works" and "the keyboard skips it".

     The strip holds two different kinds of id: on Home they are tool ids, on
     a tool page they are main-tab ids. The selection callback has to handle
     both — treating them as one kind silently does nothing on three of the
     six pages. */
  const centreIds =
    tool === "home" ? ["home", ...TOOLS.map((t) => t.id)] : main.map((t) => t.id);
  const mainTabNav = useTabKeyNav(
    centreIds,
    tool === "home" ? "home" : mainTab,
    (id) => {
      if (id === "home") {
        setTool("home");
        navigate("/");
        return;
      }
      const t = TOOLS.find((x) => x.id === id);
      if (t) {
        setTool(t.id);
        navigate(t.path);
        return;
      }
      if (main.some((m) => m.id === id)) setMainTab(id);
    },
  );

  /* The tool's action belongs to its working surface, which is the second
     main tab by definition. On the overview — a page describing the tool —
     there is nothing for "New Scan" to act on, so it is not shown. The slot
     still renders (empty) so the portal target never disappears mid-session. */
  const workingId = main[1]?.id;
  const onWorkingSurface = tool === "home" ? false : mainTab === workingId;

  return (
    <header
      ref={ref}
      className="sc-glass sticky top-0 z-[100]"
      style={{ borderBottom: "1px solid var(--color-line)" }}
    >
      {/* ── the single header row ──────────────────────────────────
          Three tracks, NOT flex. With flex the middle track is `flex-1` and
          absorbs whatever the outer two do not, so centring inside it
          centres in the leftover space rather than in the header: the brand
          is ~190px and the right rail is wider still, which pushed every tab
          visibly right of centre. Equal `1fr` side tracks make that
          arithmetic impossible to get wrong.

          The scroll container is the OUTER element and the strip inside is
          `w-max mx-auto`. `justify-center` and `overflow-x-auto` on the same
          element is the centred-overflow trap: content wider than the box
          spills equally both sides and the left spill cannot be scrolled to. */}
      <div
        className="h-14 grid items-center gap-3 px-4"
        /* `minmax(0, auto)` on the middle track, not plain `auto`. An `auto`
           track is sized by its content and cannot shrink, so a centre nav
           that is one label too wide pushes the whole page wider than the
           viewport instead of giving up room. `minmax(0, auto)` lets it
           shrink, which turns a layout-breaking overflow into a scrollable
           strip. The content is also kept under the width where it has to
           fit, so this is a guarantee rather than a mitigation. */
        style={{ gridTemplateColumns: "minmax(0,1fr) minmax(0,auto) minmax(0,1fr)" }}
      >
        <div className="min-w-0 flex items-center">
          <BrandSwitcher navigate={navigate} />
        </div>

        {/* CENTRE.

            On a tool page this is the tool's two main tabs. On Home it is the
            launcher: Home plus the five tools. A lone "Home" pill in the
            middle of the header is worse than nothing — it occupies the
            position users look in to navigate, and points at the page they
            are already on. */}
        <div
          ref={mainTabNav.listRef}
          onKeyDown={mainTabNav.onKeyDown}
          className="min-w-0 justify-self-center"
        >
          {main.length > 0 && (
            <div
              className="flex items-center gap-0.5 p-1 rounded-[var(--radius-md)]"
              style={{
                background: "var(--color-surface-2)",
                border: "1px solid var(--color-line)",
              }}
            >
              {tool === "home" ? (
                <>
                  <MainTab
                    tab={main[0]}
                    active
                    onClick={() => {
                      setTool("home");
                      navigate("/");
                    }}
                  />
                  {/* `display: contents` above xl so the buttons below stay
                      flex children of this row, and `hidden` below it. Six
                      pills are 781px; at 1280 that clears the brand and the
                      theme toggle, and below xl it does not. */}
                  <span className="hidden xl:contents">
                    <span
                      className="w-px h-5 mx-1 shrink-0"
                      style={{ background: "var(--color-line-2)" }}
                    />
                    {TOOLS.map((t) => (
                      <MainTab
                        key={t.id}
                        tab={{ id: t.id, label: t.name, icon: TOOL_ICON[t.id] }}
                        active={false}
                        accent={t.accent}
                        onClick={() => {
                          setTool(t.id);
                          navigate(t.path);
                        }}
                      />
                    ))}
                  </span>
                </>
              ) : (
                main.map((t) => (
                  <MainTab
                    key={t.id}
                    tab={t}
                    active={t.id === mainTab}
                    onClick={() => {
                      setMainTab(t.id);
                      // Entering the working surface with no section chosen
                      // would render nothing, so pick the tool's first one.
                      if (t.id !== main[0]?.id && !subs.some((s) => s.id === subTab)) {
                        setSubTab(subs[0]?.id ?? "");
                      }
                    }}
                  />
                ))
              )}
            </div>
          )}
        </div>

        {/* RIGHT of row 1: the platform's own controls. These are global —
            the palette, the tour and the theme apply to SecConflux rather than
            to whichever tool is open — so they sit on the main row and never
            move. */}
        <div
          data-rail=""
          className="flex items-center justify-end gap-2 min-w-0 h-8"
        >
          <PaletteButton onClick={() => setPaletteOpen(true)} />
          <IconBtn
            icon="help"
            onClick={() => setTourOpen(true)}
            title="How SecConflux works  (?)"
          />
          <IconBtn
            icon={theme === "dark" ? "sun" : "moon"}
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
          />
        </div>
      </div>

      {/* ── row 2: the working surface's chips and actions ──────────

          Both belong to the WORKING surface, so the row does not exist on the
          Overview. A chip row sitting under a page that describes the tool
          offers six sections of a screen that is not on display, and it was
          the answer to "why are these always visible" — they were, because
          the strip was rendered unconditionally and only the action inside it
          was gated.

          The Overview has its own call to action inside its own page, so
          nothing is lost by the row being absent. */}
      {subs.length > 0 && onWorkingSurface && (
        <div
          className="relative px-4 border-t"
          style={{ borderColor: "var(--color-line)" }}
        >
          <div
            ref={chipRef}
            className="overflow-x-auto scrollbar-none"
            style={{
              // Fade only the edge that is actually clipped. A permanent mask
              // dims the last chip on a wide screen for no reason, and a chip
              // row that clips a label mid-word with no hint looks like a bug.
              maskImage:
                chipFade.left && chipFade.right
                  ? "linear-gradient(90deg, transparent 0, #000 28px, #000 calc(100% - 28px), transparent 100%)"
                  : chipFade.left
                    ? "linear-gradient(90deg, transparent 0, #000 28px)"
                    : chipFade.right
                      ? "linear-gradient(90deg, #000 calc(100% - 28px), transparent 100%)"
                      : undefined,
            }}
          >
            <div
              className="w-max mx-auto flex items-center h-11"
              role="tablist"
              aria-label={`${TOOL_BY_ID[tool].name} sections`}
            >
              {subs.map((s) => (
                <SubChip
                  key={s.id}
                  tab={s}
                  active={s.id === subTab}
                  onClick={() => {
                    setSubTab(s.id);
                    // A chip names the surface it lives on, so selecting one
                    // also reveals that surface. Without this, choosing a
                    // section while sitting on the overview would change the
                    // highlight and nothing else.
                    if (s.surface) setMainTab(s.surface);
                  }}
                />
              ))}
              <SectionsMenu
                tool={tool}
                subs={subs}
                subTab={subTab}
                setSubTab={setSubTab}
                setMainTab={setMainTab}
              />
            </div>
          </div>

          {/* The tool's own action, floated over the chip strip so the chips
              stay optically centred against the full header width. */}
          <div className="absolute inset-y-0 right-4 flex items-center gap-1.5 pl-3">
            <div
              ref={setActionsSlot}
              className="flex items-center gap-1.5 shrink-0 empty:hidden"
            />
          </div>
        </div>
      )}
    </header>
  );
  },
);

function PaletteButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      title="Command palette  (Ctrl+M)"
      className="hidden lg:inline-flex items-center gap-2 h-8 px-2.5 rounded-[var(--radius-sm)] border border-[var(--color-line-2)] bg-[var(--color-surface-2)] text-[12.5px] text-[var(--color-ink-4)] hover:border-[var(--tool-tint-2)] hover:text-[var(--color-ink-2)] transition-colors"
    >
      <Icon name="search" size={13} />
      Search tools
      <Kbd>⌃M</Kbd>
    </button>
  );
}

/** The narrow-window stand-in for the chip row. Same state, same
 *  consequence, fewer words. It is 32px like everything else in the rail so
 *  the header does not change height between breakpoints. */
function SectionsMenu({
  tool,
  subs,
  subTab,
  setSubTab,
  setMainTab,
}: {
  tool: ToolId;
  subs: NavTab[];
  subTab: string;
  setSubTab: (id: string) => void;
  setMainTab: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const current = subs.find((s) => s.id === subTab) ?? subs[0];

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
    <div ref={ref} className="relative xl:hidden">
      <button
        data-sections-menu=""
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`${TOOL_BY_ID[tool].name} sections`}
        className={cn(
          "inline-flex items-center gap-1.5 h-8 px-2.5 rounded-[var(--radius-sm)]",
          "text-[12.5px] font-semibold leading-none border transition-colors",
        )}
        style={{
          background: "var(--tool-tint)",
          borderColor: "var(--tool-tint-2)",
          color: "var(--tool-accent)",
        }}
      >
        {current?.icon && <Icon name={current.icon as IconName} size={13} />}
        {current?.label}
        <Icon
          name="chevron-down"
          size={12}
          className={cn("transition-transform duration-200", open && "rotate-180")}
        />
      </button>

      {open && (
        <div
          role="menu"
          className="sc-anim-pop sc-overscroll absolute right-0 top-[calc(100%+8px)] z-[150] w-[220px] max-h-[70vh] overflow-y-auto p-1.5"
          style={{
            background: "var(--color-surface)",
            border: "1px solid var(--color-line-2)",
            borderRadius: "var(--radius-lg)",
            boxShadow: "var(--shadow-lg)",
          }}
        >
          {subs.map((s) => {
            const on = s.id === subTab;
            return (
              <button
                key={s.id}
                role="menuitemradio"
                aria-checked={on}
                onClick={() => {
                  setSubTab(s.id);
                  if (s.surface) setMainTab(s.surface);
                  setOpen(false);
                }}
                className={cn(
                  "w-full flex items-center gap-2.5 h-8 px-2.5 rounded-[var(--radius-sm)]",
                  "text-[13px] font-semibold text-left transition-colors",
                  on ? "bg-[var(--tool-tint)]" : "hover:bg-[var(--color-surface-3)]",
                )}
                style={{ color: on ? "var(--tool-accent)" : "var(--color-ink-2)" }}
              >
                {s.icon && <Icon name={s.icon as IconName} size={14} />}
                <span className="flex-1 truncate">{s.label}</span>
                {on && <Icon name="check" size={13} style={{ color: "var(--tool-accent)" }} />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function MainTab({
  tab,
  accent,
  active,
  onClick,
}: {
  tab: NavTab;
  accent?: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      role="tab"
      aria-selected={active}
      className={cn(
        "inline-flex items-center gap-1.5 h-8 px-3.5 rounded-[var(--radius-sm)]",
        "text-[13px] font-semibold leading-none whitespace-nowrap shrink-0",
        "transition-colors",
        active ? "" : "hover:bg-[var(--color-surface-4)]",
      )}
      style={
        active
          ? {
              background: "var(--tool-tint)",
              color: "var(--color-ink)",
              boxShadow: "inset 0 0 0 1px var(--tool-tint-2)",
            }
          : { color: "var(--color-ink-3)" }
      }
    >
      {tab.icon && (
        <span style={{ color: active ? accent ?? "var(--tool-accent)" : "var(--color-ink-4)" }}>
          <Icon name={tab.icon as IconName} size={14} />
        </span>
      )}
      {tab.label}
    </button>
  );
}

/** A section chip.

 *  Deliberately NOT a pill. The centre tabs are pills — filled, boxed,
 *  generous — and when the chips were pills too the whole header read as one
 *  undifferentiated strip of ten tabs, which is exactly the problem the
 *  two-level model exists to solve. So the chips drop to text: no box, no
 *  fill, smaller type, and an underline for the active one. Same 32px height
 *  as everything else in the rail so the header does not change height. */
function SubChip({
  tab,
  active,
  onClick,
}: {
  tab: NavTab;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      role="tab"
      data-chip=""
      aria-selected={active}
      title={tab.label}
      className={cn(
        "relative hidden xl:inline-flex items-center gap-1.5 h-8 px-3",
        "rounded-[var(--radius-sm)] text-[12.5px] font-semibold leading-none",
        "whitespace-nowrap transition-colors shrink-0 hover:bg-[var(--color-surface-3)]",
      )}
      style={{ color: active ? "var(--tool-accent)" : "var(--color-ink-3)" }}
    >
      {tab.icon && (
        <span style={{ color: active ? "var(--tool-accent)" : "var(--color-ink-3)" }}>
          <Icon name={tab.icon as IconName} size={13} />
        </span>
      )}
      {tab.label}
      {active && (
        <span
          className="absolute inset-x-1.5 bottom-0.5 h-[2px] rounded-full"
          style={{ background: "var(--tool-accent)" }}
        />
      )}
    </button>
  );
}

/** The brand block IS the switcher. There is no separate control next to it,
 *  because two controls that both open the same list is one control too many
 *  and the second one is the one people reach for first. */
function BrandSwitcher({ navigate }: { navigate: (to: string) => void }) {
  const { tool, setTool } = useShell();
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

  function pick(id: ToolId, path: string) {
    setTool(id);
    navigate(path);
    setOpen(false);
  }

return (
    <div ref={ref} className="relative shrink-0">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label="SecConflux — switch tool"
        title="Switch tool  (Ctrl+M)"
        className={cn(
          "group flex items-center gap-2.5 h-10 pl-2 pr-3 rounded-[var(--radius-md)] -ml-2",
          "border transition-all duration-150",
          open
            ? "bg-[var(--brand-tint)] border-[var(--brand-tint-2)]"
            : "border-transparent hover:border-[var(--color-line)] hover:bg-[var(--color-surface-2)]",
        )}
      >
        <SecConfluxMark size={24} />
        <span className="text-left leading-none">
          {/* The wordmark is plain ink, not a hue. Every coloured thing in
              this header belongs to the tool; the brand is the one element
              that does not, which is what makes it read as the platform. */}
          <span
            className={cn(
              "block text-[15px] font-extrabold tracking-[-0.02em] transition-colors",
              open ? "text-[var(--brand)]" : "text-[var(--color-ink)]",
            )}
          >
            SecConflux
          </span>
          <span
            className="block text-[10px] font-semibold tracking-[0.12em] uppercase"
            style={{ color: "var(--color-ink-4)" }}
          >
            SecOps Utility
          </span>
        </span>

        {/* An explicit affordance. The brand block reads as a wordmark, and a
            wordmark does not look like a control — so the chevron is joined by
            a label that only appears when the brand is NOT already open, which
            is the moment a first-time user needs telling. */}
        {!open && (
          <span
            className="hidden xl:inline-flex items-center gap-1 ml-1.5 pl-2 h-5 px-1.5 rounded-[4px] text-[10.5px] font-bold tracking-[0.06em] uppercase transition-colors"
            style={{
              background: "var(--brand-tint)",
              border: "1px solid var(--brand-tint-2)",
              color: "var(--brand)",
            }}
          >
            Click me
          </span>
        )}

        <Icon
          name="chevron-down"
          size={13}
          className={cn(
            "ml-0.5 text-[var(--color-ink-4)] transition-transform duration-200",
            open && "rotate-180",
          )}
        />
      </button>

      {open && (
        <div
          role="listbox"
          className="sc-anim-pop sc-overscroll absolute left-0 top-[calc(100%+8px)] z-[150] w-[340px] max-h-[70vh] overflow-y-auto p-1.5"
          style={{
            background: "var(--color-surface)",
            border: "1px solid var(--color-line-2)",
            borderRadius: "var(--radius-lg)",
            boxShadow: "var(--shadow-lg)",
          }}
        >
          <div
            className="px-3 pt-1 pb-2 text-[10.5px] font-bold tracking-[0.08em] uppercase"
            style={{ color: "var(--color-ink-4)" }}
          >
            Go to
          </div>
<SwitcherRow
            label="SecConflux Home"
            hint="Platform overview and all five tools"
            icon={<SecConfluxMark size={15} />}
            active={tool === "home"}
            hotkey="0"
            onClick={() => pick("home", "/")}
          />
          <div className="my-1.5 h-px" style={{ background: "var(--color-line)" }} />
          <div
            className="px-3 pt-1 pb-2 text-[10.5px] font-bold tracking-[0.08em] uppercase"
            style={{ color: "var(--color-ink-4)" }}
          >
            Tools
          </div>
          {TOOLS.map((t) => (
            <SwitcherRow
              key={t.id}
              label={t.name}
              hint={t.tagline}
              icon={<Icon name={TOOL_ICON[t.id]} size={14} />}
              accent={t.accent}
              active={tool === t.id}
              hotkey={t.hotkey}
              onClick={() => pick(t.id, t.path)}
            />
          ))}
          <div className="my-1.5 h-px" style={{ background: "var(--color-line)" }} />
          <div
            className="flex items-center gap-2 px-3 py-2 text-[11.5px]"
            style={{ background: "var(--color-surface-2)", borderRadius: "var(--radius-sm)" }}
          >
            <Icon name="command" size={12} style={{ color: "var(--tool-accent)" }} />
            <span style={{ color: "var(--color-ink-4)" }}>
              Ctrl+M from anywhere, or press{" "}
              <span className="mono" style={{ color: "var(--color-ink-2)" }}>
                1
              </span>
              –
              <span className="mono" style={{ color: "var(--color-ink-2)" }}>
                5
              </span>
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

function SwitcherRow({
  label,
  hint,
  icon,
  accent,
  active,
  hotkey,
  onClick,
}: {
  label: string;
  hint: string;
  icon: ReactNode;
  accent?: string;
  active: boolean;
  hotkey?: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "w-full flex items-center gap-3 px-3 py-2.5 rounded-[var(--radius-md)] text-left",
        "transition-colors duration-100",
        active ? "bg-[var(--tool-tint)]" : "hover:bg-[var(--color-surface-3)]",
      )}
    >
      <span
        className="grid place-items-center w-7 h-7 rounded-[var(--radius-sm)] shrink-0"
        style={{
          background: active ? "var(--tool-tint-2)" : "var(--color-surface-3)",
          border: "1px solid var(--color-line-2)",
          color: accent ?? "var(--color-ink-3)",
        }}
      >
        {icon}
      </span>
      <span
        className="min-w-0 flex-1"
      >
        <span className="flex items-center gap-2">
          <span
            className={cn(
              "text-[13.5px] font-semibold truncate",
              active ? "text-[var(--color-ink)]" : "text-[var(--color-ink-2)]",
            )}
          >
            {label}
          </span>
          {active && (
            <Icon name="check" size={12} style={{ color: "var(--tool-accent)", flexShrink: 0 }} />
          )}
        </span>
        <span className="block text-[11.5px] truncate mt-px" style={{ color: "var(--color-ink-4)" }}>
          {hint}
        </span>
      </span>
      {hotkey && (
        <Kbd>{hotkey}</Kbd>
      )}
    </button>
  );
}

/** One key-cap, one size, everywhere. Four different kbd heights had crept
 *  in across the switcher, the palette and the landing page, and they were
 *  not baseline-aligned with the text beside them. */
function IconBtn({
  icon,
  onClick,
  title,
}: {
  icon: IconName;
  onClick: () => void;
  title: string;
}) {
  return (
    <button
      onClick={onClick}
      title={title}
      aria-label={title}
      className="grid place-items-center w-8 h-8 rounded-[var(--radius-sm)] text-[var(--color-ink-4)] hover:text-[var(--tool-accent)] hover:bg-[var(--tool-tint)] transition-colors shrink-0"
    >
      <Icon name={icon} size={15} />
    </button>
  );
}

/* =============================================================
   COMMAND PALETTE
   ============================================================= */

interface Command {
  id: string;
  label: string;
  hint?: string;
  group: "Navigate" | "Actions";
  icon: IconName;
  run: () => void;
  accent?: string;
}

export function CommandPalette({ navigate }: { navigate: (to: string) => void }) {
  const { paletteOpen, setPaletteOpen, setTool, setTourOpen, toggleTheme, theme } = useShell();
  const [q, setQ] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const commands: Command[] = [
    {
      id: "home",
      label: "Go to SecConflux Home",
      hint: "Platform overview, all tools, how switching works",
      group: "Navigate",
      icon: "home",
      run: () => navigate("/"),
    },
    ...TOOLS.map((t) => ({
      id: t.id,
      label: `Open ${t.name}`,
      hint: t.tagline,
      group: "Navigate" as const,
      icon: TOOL_ICON[t.id],
      accent: t.accent,
      run: () => navigate(t.path),
    })),
    {
      id: "tour",
      label: "How SecConflux works",
      hint: "Reopen the guided tour",
      group: "Actions",
      icon: "help",
      run: () => setTourOpen(true),
    },
    {
      id: "theme",
      label: `Switch to ${theme === "dark" ? "light" : "dark"} theme`,
      group: "Actions",
      icon: theme === "dark" ? "sun" : "moon",
      run: toggleTheme,
    },
  ];

  const filtered = q.trim()
    ? commands.filter((c) =>
        (c.label + " " + (c.hint ?? "")).toLowerCase().includes(q.trim().toLowerCase()),
      )
    : commands;

  useEffect(() => {
    if (paletteOpen) {
      setQ("");
      setCursor(0);
      setTimeout(() => inputRef.current?.focus(), 20);
    }
  }, [paletteOpen]);

  useEffect(() => {
    if (!paletteOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setPaletteOpen(false);
      else if (e.key === "ArrowDown") {
        e.preventDefault();
        // Wrap. A palette that stops at the last entry makes the arrow keys
        // feel broken at exactly the point you are navigating.
        if (filtered.length) setCursor((c) => (c + 1) % filtered.length);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        // Wrap the other way: Up from the first entry goes to the LAST, which
        // is the behaviour every command palette on the platform uses.
        if (filtered.length) setCursor((c) => (c - 1 + filtered.length) % filtered.length);
      } else if (e.key === "Home") {
        e.preventDefault();
        setCursor(0);
      } else if (e.key === "End") {
        e.preventDefault();
        setCursor(Math.max(0, filtered.length - 1));
      } else if (e.key === "Enter") {
        e.preventDefault();
        const cmd = filtered[cursor];
        if (cmd) {
          setPaletteOpen(false);
          // Set the tool before navigating so the accent is correct on the
          // first paint of the destination, not one frame late.
          if (cmd.id !== "tour" && cmd.id !== "theme") setTool(cmd.id as ToolId);
          cmd.run();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [paletteOpen, filtered, cursor, setPaletteOpen, setTool]);

  /* Keep the highlighted row inside the viewport. Moving the cursor with the
     arrow keys changed which row was active but never scrolled the list, so
     once the selection passed the bottom edge it disappeared and the keys
     looked like they had stopped working. */
  useEffect(() => {
    if (!paletteOpen) return;
    const row = listRef.current?.querySelector<HTMLElement>(
      `[data-cursor="${cursor}"]`,
    );
    row?.scrollIntoView({ block: "nearest" });
  }, [cursor, paletteOpen]);

  useScrollLock(paletteOpen);

  if (!paletteOpen) return null;

  let lastGroup = "";

  return (
    <div
      className="fixed inset-0 z-[300] flex items-start justify-center p-4 pt-[14vh] sc-anim-in sc-overscroll-page"
      style={{ background: "rgb(0 0 0 / 0.6)", backdropFilter: "blur(6px)" }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) setPaletteOpen(false);
      }}
    >
      <div
        className="sc-anim-pop w-full overflow-hidden"
        style={{
          maxWidth: 580,
          background: "var(--color-surface)",
          border: "1px solid var(--color-line-2)",
          borderRadius: "var(--radius-xl)",
          boxShadow: "var(--shadow-lg)",
        }}
      >
        <div
          className="flex items-center gap-3 px-4 h-14 border-b"
          style={{ borderColor: "var(--color-line)" }}
        >
          <Icon name="search" size={17} className="text-[var(--tool-accent)]" />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setCursor(0);
            }}
            placeholder="Jump to a tool, or run a command…"
            className="flex-1 bg-transparent text-[15px] placeholder:text-[var(--color-ink-4)] focus:outline-none"
          />
          <Kbd>ESC</Kbd>
        </div>

        <div ref={listRef} className="max-h-[52vh] overflow-y-auto p-1.5 sc-overscroll">
          {filtered.length === 0 && (
            <div className="px-4 py-10 text-center text-[13.5px] text-[var(--color-ink-4)]">
              No match for “{q}”.
            </div>
          )}
          {filtered.map((c, i) => {
            const showGroup = c.group !== lastGroup;
            lastGroup = c.group;
            const on = i === cursor;
            return (
              <div key={c.id}>
                {showGroup && (
                  <div className="px-3 pt-3 pb-1.5 text-[10.5px] font-bold tracking-[0.08em] uppercase text-[var(--color-ink-4)]">
                    {c.group}
                  </div>
                )}
                <button
                  data-cursor={i}
                  onMouseEnter={() => setCursor(i)}
                  onClick={() => {
                    setPaletteOpen(false);
                    if (c.id !== "tour" && c.id !== "theme") setTool(c.id as ToolId);
                    c.run();
                  }}
                  className={cn(
                    "w-full flex items-center gap-3 px-3 py-2.5 rounded-[var(--radius-md)] text-left transition-colors",
                    on ? "bg-[var(--tool-tint)]" : "hover:bg-[var(--color-surface-3)]",
                  )}
                >
                  <span
                    className="grid place-items-center w-7 h-7 rounded-[var(--radius-sm)] shrink-0"
                    style={{
                      background: on ? "var(--tool-tint-2)" : "var(--color-surface-3)",
                      color: c.accent ?? "var(--color-ink-3)",
                    }}
                  >
                    <Icon name={c.icon} size={14} />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-[13.5px] font-semibold truncate">{c.label}</span>
                    {c.hint && (
                      <span className="block text-[12px] text-[var(--color-ink-4)] truncate">
                        {c.hint}
                      </span>
                    )}
                  </span>
                  {hotkeyIndex(c.id as ToolId) !== -1 && (
                    <Kbd>{hotkeyIndex(c.id as ToolId) + 1}</Kbd>
                  )}
                </button>
              </div>
            );
          })}
        </div>

        <div
          className="flex items-center gap-4 px-4 py-2.5 text-[11.5px] text-[var(--color-ink-4)]"
          style={{ background: "var(--color-surface-2)", borderTop: "1px solid var(--color-line)" }}
        >
          <span className="flex items-center gap-1.5">
            <Kbd>↑↓</Kbd>
            navigate
          </span>
          <span className="flex items-center gap-1.5">
            <Kbd>⏎</Kbd>
            open
          </span>
          <span className="flex-1" />
          <span>SecConflux · {LANDING_ORDER.length} tools</span>
        </div>
      </div>
    </div>
  );
}

/* =============================================================
   TOASTS
   ============================================================= */

interface Toast {
  id: number;
  text: string;
  tone: "ok" | "bad" | "info" | "warn";
}

let toastSeq = 0;
const listeners = new Set<(t: Toast[]) => void>();
let toasts: Toast[] = [];

export function toast(text: string, tone: Toast["tone"] = "info") {
  const t = { id: ++toastSeq, text, tone };
  toasts = [...toasts, t];
  listeners.forEach((l) => l(toasts));
  setTimeout(() => {
    toasts = toasts.filter((x) => x.id !== t.id);
    listeners.forEach((l) => l(toasts));
  }, 3400);
}

export function ToastHost() {
  const [items, setItems] = useState<Toast[]>(toasts);
  useEffect(() => {
    listeners.add(setItems);
    return () => {
      listeners.delete(setItems);
    };
  }, []);

  const tones: Record<Toast["tone"], string> = {
    ok: "var(--color-ok)",
    bad: "var(--color-bad)",
    info: "var(--color-info)",
    warn: "var(--color-warn)",
  };

  return (
    <div className="fixed bottom-5 right-5 z-[400] flex flex-col gap-2 pointer-events-none">
      {items.map((t) => (
        <div
          key={t.id}
          className="sc-anim-pop flex items-center gap-2.5 px-3.5 py-2.5 rounded-[var(--radius-md)] text-[13px] font-medium max-w-sm"
          style={{
            background: "var(--color-surface)",
            border: "1px solid var(--color-line-2)",
            boxShadow: "var(--shadow-lg)",
          }}
        >
          <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: tones[t.tone] }} />
          <span>{t.text}</span>
        </div>
      ))}
    </div>
  );
}

/* =============================================================
   ERROR BOUNDARY

   A tool that throws must not take the shell with it. The boundary
   shows the failure and offers the one action that always works:
   go home.
   ============================================================= */

interface BoundaryProps {
  children: ReactNode;
  onError: (e: Error) => void;
}

class BoundaryInner extends Component<BoundaryProps> {
  componentDidCatch(error: Error) {
    this.props.onError(error);
  }
  render() {
    return this.props.children;
  }
}

export function ToolErrorBoundary({
  children,
  toolName,
  onHome,
}: {
  children: ReactNode;
  toolName: string;
  onHome: () => void;
}) {
  const [error, setError] = useState<Error | null>(null);

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-24 px-6 text-center">
        <div
          className="grid place-items-center w-14 h-14 rounded-[var(--radius-lg)] mb-4"
          style={{
            background: "rgb(248 113 113 / 0.12)",
            border: "1px solid rgb(248 113 113 / 0.3)",
            color: "var(--color-bad)",
          }}
        >
          <Icon name="alert-octagon" size={24} strokeWidth={1.5} />
        </div>
        <h2 className="text-[17px] font-bold">{toolName} could not render</h2>
        <p className="mt-2 text-[13.5px] text-[var(--color-ink-4)] max-w-md leading-relaxed">
          The rest of SecConflux is unaffected. The message below is the actual error, not a
          summary of it.
        </p>
        <pre
          className="mono text-[12px] mt-4 p-3 rounded-[var(--radius-md)] text-left max-w-lg w-full overflow-auto"
          style={{
            background: "var(--color-canvas-2)",
            border: "1px solid var(--color-line)",
            color: "var(--color-bad)",
          }}
        >
          {error.message}
        </pre>
        <button
          onClick={() => {
            setError(null);
            onHome();
          }}
          className="mt-5 inline-flex items-center gap-2 h-10 px-4 rounded-[var(--radius-md)] text-[14px] font-bold text-white"
          style={{
            background: "linear-gradient(135deg, var(--tool-accent), var(--tool-accent-2))",
          }}
        >
          Back to SecConflux Home
        </button>
      </div>
    );
  }

  return <BoundaryInner onError={setError}>{children}</BoundaryInner>;
}
