import { useRef } from "react";

// "Sources" merges what used to be two tabs. "Evidence" answered *what the
// sources said*; "Raw Data" answered *what each one actually returned* — but an
// analyst asking "which APIs ran, and which of my keys went unused" had to
// cross-reference both. They are one question, so they are one tab.
const TABS = ["Investigation", "Enrichment", "Relationships", "Sources", "Export"] as const;
export type TabName = (typeof TABS)[number];

export default function TabBar({
  active,
  onChange,
  badges,
}: {
  active: TabName;
  onChange: (tab: TabName) => void;
  badges?: Partial<Record<TabName, number | string>>;
}) {
  const listRef = useRef<HTMLDivElement>(null);

  function handleKeyDown(e: React.KeyboardEvent) {
    const idx = TABS.indexOf(active);
    let nextIdx: number | null = null;
    if (e.key === "ArrowRight") nextIdx = (idx + 1) % TABS.length;
    else if (e.key === "ArrowLeft") nextIdx = (idx - 1 + TABS.length) % TABS.length;
    if (nextIdx === null) return;
    e.preventDefault();
    onChange(TABS[nextIdx]);
    const buttons = listRef.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]');
    buttons?.[nextIdx]?.focus();
  }

  return (
    <div
      ref={listRef}
      className="flex gap-1 border-b border-border overflow-x-auto scrollbar-thin"
      role="tablist"
      aria-label="Result sections"
      onKeyDown={handleKeyDown}
    >
      {TABS.map((tab) => {
        const badge = badges?.[tab];
        return (
          <button
            key={tab}
            onClick={() => onChange(tab)}
            role="tab"
            aria-selected={active === tab}
            aria-controls="result-panel"
            tabIndex={active === tab ? 0 : -1}
            className={`px-4 py-2.5 text-xs font-semibold uppercase tracking-wider transition-colors relative flex items-center gap-1.5 shrink-0 ${
              active === tab
                ? "text-accent"
                : "text-text-secondary hover:text-text-primary"
            }`}
          >
            <span>{tab}</span>
            {badge !== undefined && badge !== null && badge !== 0 && (
              <span className={`rounded-full px-1.5 py-0.2 text-xs font-mono ${
                active === tab ? "bg-accent/20 text-accent font-bold" : "bg-bg-elevated text-text-secondary"
              }`}>
                {badge}
              </span>
            )}
            {active === tab && (
              <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-accent rounded-full shadow-[0_0_8px_rgba(56,189,248,0.6)]" />
            )}
          </button>
        );
      })}
    </div>
  );
}
