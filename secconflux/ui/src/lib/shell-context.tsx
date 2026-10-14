import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { ToolId } from "./tools";
import { TOOL_BY_ID, LANDING_ORDER, MAIN_TABS, SUB_TABS } from "./tools";

export type ThemeMode = "dark" | "light";

interface ShellState {
  tool: ToolId;
  setTool: (t: ToolId) => void;
  /** Which of the tool's two main tabs is active. Centred in the header. */
  mainTab: string;
  setMainTab: (id: string) => void;
  /** Which section of the working surface is active. Chips on the header's
   *  right. Independent of mainTab because for some tools a chip is a peer
   *  of the second main tab, not a child of it. */
  subTab: string;
  setSubTab: (id: string) => void;
  /** DOM node in the header's right rail that tool pages portal their
   *  primary action into. A portal rather than state holding a node, so the
   *  button is rendered by the page that owns the state it closes over. */
  actionsSlot: HTMLElement | null;
  setActionsSlot: (el: HTMLElement | null) => void;
  theme: ThemeMode;
  toggleTheme: () => void;
  paletteOpen: boolean;
  setPaletteOpen: (v: boolean) => void;
  tourOpen: boolean;
  setTourOpen: (v: boolean) => void;
  /** How many times a given tool has been opened this browser profile. */
  visits: Record<string, number>;
  markVisit: (t: string) => void;
}

const Ctx = createContext<ShellState | null>(null);

const VISITS_KEY = "secconflux.visits";
const THEME_KEY = "secconflux.theme";

function readVisits(): Record<string, number> {
  try {
    return JSON.parse(localStorage.getItem(VISITS_KEY) ?? "{}");
  } catch {
    return {};
  }
}

export function ShellProvider({ children }: { children: ReactNode }) {
  const [tool, setToolState] = useState<ToolId>("home");
  const [mainTab, setMainTabState] = useState<string>("");
  const [subTab, setSubTabState] = useState<string>("");
  const [actionsSlot, setActionsSlot] = useState<HTMLElement | null>(null);
  const [theme, setTheme] = useState<ThemeMode>(() => {
    try {
      const stored = localStorage.getItem(THEME_KEY);
      if (stored === "light" || stored === "dark") return stored;
    } catch {
      /* private mode, or a locked-down profile. Default is dark below. */
    }
    return "dark";
  });
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [tourOpen, setTourOpen] = useState(false);
  const [visits, setVisits] = useState<Record<string, number>>(readVisits);

  // The accent hue lives on <html data-tool>, so the entire product
  // re-tints from one attribute and no component knows which tool it
  // is rendered inside.
  useEffect(() => {
    document.documentElement.setAttribute("data-tool", tool);
  }, [tool]);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    document.documentElement.classList.toggle("light", theme === "light");
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch {
      /* not persistable. The session still works. */
    }
  }, [theme]);

  const setTool = useCallback((t: ToolId) => {
    setToolState(t);
    // Reset both levels of navigation. Without this, a tool whose ids
    // overlap (RuleForge and IOC Lookup both have "history", both have
    // "overview") would open on a section it does not have and render an
    // empty page with no visible way back.
    setMainTabState(MAIN_TABS[t][0]?.id ?? "");
    setSubTabState(SUB_TABS[t][0]?.id ?? "");
  }, []);

  const setMainTab = useCallback((id: string) => {
    setMainTabState(id);
  }, []);

  const setSubTab = useCallback((id: string) => {
    setSubTabState(id);
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme((t) => (t === "dark" ? "light" : "dark"));
  }, []);

  const markVisit = useCallback((t: string) => {
    setVisits((prev) => {
      const next = { ...prev, [t]: (prev[t] ?? 0) + 1 };
      try {
        localStorage.setItem(VISITS_KEY, JSON.stringify(next));
      } catch {
        /* non-fatal */
      }
      return next;
    });
  }, []);

  const value = useMemo<ShellState>(
    () => ({
      tool,
      setTool,
      mainTab,
      setMainTab,
      subTab,
      setSubTab,
      actionsSlot,
      setActionsSlot,
      theme,
      toggleTheme,
      paletteOpen,
      setPaletteOpen,
      tourOpen,
      setTourOpen,
      visits,
      markVisit,
    }),
    [tool, setTool, mainTab, setMainTab, subTab, setSubTab, actionsSlot, theme, toggleTheme, paletteOpen, tourOpen, visits, markVisit],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useShell(): ShellState {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useShell must be used inside <ShellProvider>");
  return ctx;
}

/** Resolves a tool id from a route fragment, falling back to the landing page. */
export function toolFromRoute(fragment: string): ToolId {
  const t = fragment.replace(/^\/+|\/+$/g, "") as ToolId;
  if (t in TOOL_BY_ID) return t;
  return "home";
}

/** Index of a tool in landing order, or -1. Drives the 1-5 hotkeys. */
export function hotkeyIndex(t: ToolId): number {
  return LANDING_ORDER.indexOf(t);
}