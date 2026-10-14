import { useCallback, useEffect, useRef, useState } from "react";
import ErrorBoundary from "./components/ErrorBoundary";
import ToastContainer from "./components/Toast";
import Landing from "./pages/Landing";
import HomePage from "./pages/HomePage";
import { AUTH_REQUIRED_EVENT, setRuntimeApiKey, type BatchResult, type LookupResponse } from "./services/api";

export type Page = "home" | "lookup";
export type Tool = "investigations" | "batch" | "history";

export interface NavigateEvent {
  page: Page;
  tool?: Tool | null;
  ioc?: string;
  iocType?: string;
  batchId?: string;
  batchResult?: BatchResult;
  historyId?: number;
  isHistorical?: boolean;
  batchResultItem?: LookupResponse;
  fromBatch?: boolean;
  autoRescan?: boolean;
  createdAt?: string;
}

const NAV_TABS: { id: string; label: string }[] = [
  { id: "home", label: "Home" },
  { id: "lookup", label: "Lookup" },
  { id: "investigations", label: "Investigations" },
  { id: "batch", label: "Batch" },
  { id: "history", label: "History" },
];

const VALID_PAGES = new Set<string>(["home", "lookup"]);
const TOOL_IDS = new Set<string>(["investigations", "batch", "history"]);
const NAV_TAB_IDS = NAV_TABS.map((t) => t.id);

export interface RouteState {
  page: Page;
  tool: Tool | null;
  ioc: string;
  iocType: string;
  batchId: string;
  batchResult?: BatchResult;
  historyId?: number;
  isHistorical?: boolean;
  batchResultItem?: LookupResponse;
  fromBatch?: boolean;
  autoRescan?: boolean;
  createdAt?: string;
}

function parseLocation(): RouteState {
  const params = new URLSearchParams(window.location.search);
  const raw = params.get("page") ?? "";
  const toolRaw = params.get("tool") ?? "";
  const ioc = params.get("ioc") ?? "";
  const iocType = params.get("ioc_type") ?? "";
  const batchId = params.get("batch") ?? "";
  // Back-compat: legacy `?page=batch`-style deep links map to a Lookup sub-tab.
  if (TOOL_IDS.has(raw)) {
    return { page: "lookup", tool: raw as Tool, ioc, iocType, batchId };
  }
  const page: Page = VALID_PAGES.has(raw) ? (raw as Page) : "home";
  const tool: Tool | null = page === "lookup" && TOOL_IDS.has(toolRaw) ? (toolRaw as Tool) : null;
  return { page, tool, ioc, iocType, batchId };
}

function useTabsKeyNav(list: readonly string[], active: string, onSelect: (id: string) => void) {
  const listRef = useRef<HTMLDivElement>(null);
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    const idx = list.indexOf(active);
    let nextIdx: number | null = null;
    if (e.key === "ArrowRight") nextIdx = (idx + 1) % list.length;
    else if (e.key === "ArrowLeft") nextIdx = (idx - 1 + list.length) % list.length;
    if (nextIdx === null) return;
    e.preventDefault();
    onSelect(list[nextIdx]);
    const buttons = listRef.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]');
    buttons?.[nextIdx]?.focus();
  }, [list, active, onSelect]);
  return { listRef, handleKeyDown };
}

function AuthPrompt({ onSubmit }: { onSubmit: (value: string) => void }) {
  const [value, setValue] = useState("");

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 p-4">
      <form
        role="dialog"
        aria-modal="true"
        aria-labelledby="auth-prompt-title"
        onSubmit={(event) => {
          event.preventDefault();
          if (value.trim()) onSubmit(value);
        }}
        className="w-full max-w-md rounded-xl border border-border bg-bg-card p-6 shadow-2xl"
      >
        <h2 id="auth-prompt-title" className="text-lg font-bold">Local API key required</h2>
        <p className="mt-2 text-sm text-text-secondary">Enter the API_KEYS value configured for this local instance. It is kept only for this browser session.</p>
        <input
          type="password"
          autoFocus
          value={value}
          onChange={(event) => setValue(event.target.value)}
          aria-label="Local API key"
          className="mt-4 w-full rounded-lg border border-border bg-bg-secondary px-3 py-2 text-sm outline-none focus:border-accent"
        />
        <div className="mt-4 flex justify-end">
          <button type="submit" disabled={!value.trim()} className="rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-[#06070d] disabled:opacity-50">Continue</button>
        </div>
      </form>
    </div>
  );
}

export default function App() {
  const [route, setRoute] = useState<RouteState>(parseLocation);
  const [authRequired, setAuthRequired] = useState(false);
  const { page, tool, ioc, iocType, batchId, batchResult, historyId, isHistorical, batchResultItem, fromBatch, autoRescan, createdAt } = route;

  useEffect(() => {
    const handleAuthRequired = () => setAuthRequired(true);
    window.addEventListener(AUTH_REQUIRED_EVENT, handleAuthRequired);
    return () => window.removeEventListener(AUTH_REQUIRED_EVENT, handleAuthRequired);
  }, []);

  useEffect(() => {
    if (document.activeElement?.closest('[role="tablist"]')) return;
    const id =
      page === "home" ? "page-home" : tool ? `panel-${tool}` : "page-lookup";
    document.getElementById(id)?.focus({ preventScroll: true });
  }, [page, tool]);

  useEffect(() => {
    function onPopState() {
      setRoute(parseLocation());
    }
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const navigate = useCallback((
    next: Page,
    nextTool: Tool | null = null,
    iocValue = "",
    nextIocType = "",
    nextBatchId = "",
    extra?: {
      historyId?: number;
      isHistorical?: boolean;
      batchResultItem?: LookupResponse;
      batchResult?: BatchResult;
      fromBatch?: boolean;
      autoRescan?: boolean;
      createdAt?: string;
    }
  ) => {
    if (
      next === page &&
      nextTool === tool &&
       iocValue === ioc &&
       nextIocType === iocType &&
       nextBatchId === batchId &&
      !extra?.batchResultItem &&
      !extra?.historyId &&
      !extra?.autoRescan
    ) return;
    const url = new URL(window.location.href);
    const params = url.searchParams;
    if (next === "home") {
      params.delete("page");
      params.delete("tool");
      params.delete("ioc");
      params.delete("ioc_type");
      params.delete("batch");
    } else {
      params.set("page", "lookup");
      if (nextTool) {
        params.set("tool", nextTool);
      } else {
        params.delete("tool");
      }
       if (iocValue) {
         params.set("ioc", iocValue);
       } else {
         params.delete("ioc");
       }
       if (nextIocType) {
         params.set("ioc_type", nextIocType);
       } else {
         params.delete("ioc_type");
       }
       if (nextBatchId) params.set("batch", nextBatchId); else params.delete("batch");
    }
    window.history.pushState({}, "", url.toString());
    setRoute({
      page: next,
       tool: nextTool,
       ioc: iocValue,
       iocType: nextIocType,
       batchId: nextBatchId,
      historyId: extra?.historyId,
      isHistorical: extra?.isHistorical,
      batchResultItem: extra?.batchResultItem,
      batchResult: extra?.batchResult,
      fromBatch: extra?.fromBatch,
      autoRescan: extra?.autoRescan,
      createdAt: extra?.createdAt,
    });
  }, [batchId, ioc, iocType, page, tool]);

  useEffect(() => {
     function onIocSync(e: Event) {
       const detail = (e as CustomEvent<{ value: string; iocType?: string }>).detail;
       const value = detail?.value;
       const nextIocType = detail?.iocType ?? "";
      if (!value || page !== "lookup" || tool !== null) return;
      setRoute((prev) => (
        prev.ioc === value && prev.iocType === nextIocType
          ? prev
          : {
              ...prev,
              ioc: value,
              iocType: nextIocType,
              historyId: undefined,
              isHistorical: undefined,
              batchResultItem: undefined,
              fromBatch: undefined,
              autoRescan: undefined,
              createdAt: undefined,
            }
      ));
      const url = new URL(window.location.href);
      const params = url.searchParams;
      params.set("page", "lookup");
       params.delete("tool");
       params.set("ioc", value);
       if (nextIocType) params.set("ioc_type", nextIocType); else params.delete("ioc_type");
       window.history.replaceState({}, "", url.toString());
    }
    window.addEventListener("ioc-sync", onIocSync);
    return () => window.removeEventListener("ioc-sync", onIocSync);
  }, [page, tool]);

  useEffect(() => {
    function handler(e: Event) {
      const d = (e as CustomEvent<NavigateEvent>).detail;
       navigate(d.page, d.tool ?? null, d.ioc ?? "", d.iocType ?? "", d.batchId ?? "", {
        historyId: d.historyId,
        isHistorical: d.isHistorical,
        batchResultItem: d.batchResultItem,
        batchResult: d.batchResult,
        fromBatch: d.fromBatch,
        autoRescan: d.autoRescan,
        createdAt: d.createdAt,
      });
    }
    window.addEventListener("navigate", handler);
    return () => window.removeEventListener("navigate", handler);
  }, [navigate]);

  const activeTool: Tool | "lookup" | null = page === "lookup" ? (tool ?? "lookup") : null;
  const activeNavId = page === "home" ? "home" : (activeTool ?? "lookup");

  const navOnSelect = useCallback((id: string) => {
    if (id === "home") {
      navigate("home");
    } else if (id === "lookup") {
       navigate("lookup", null, ioc, iocType);
    } else {
       navigate("lookup", id as Tool, ioc, iocType);
    }
  }, [navigate, ioc, iocType]);
  const navKeys = useTabsKeyNav(NAV_TAB_IDS, activeNavId, navOnSelect);

  return (
    <div className="min-h-screen bg-bg-primary text-text-primary">
      <div className="scanline-overlay" aria-hidden="true" />
      <nav
        className="sticky top-0 z-50 border-b border-border bg-bg-secondary/85 backdrop-blur px-6 py-3 flex flex-wrap items-center gap-x-6 gap-y-2 relative"
        aria-label="Main navigation"
      >
        <a
          href={`${window.location.pathname}${window.location.search}`}
          onClick={(e) => { e.preventDefault(); navigate("home"); }}
          className="text-lg font-bold bg-gradient-to-r from-accent to-accent-secondary bg-clip-text text-transparent"
          aria-label="Home"
        >
          IOC Lookup Platform
        </a>

        <div className="flex-1 flex justify-center">
          <div
            ref={navKeys.listRef}
            onKeyDown={navKeys.handleKeyDown}
            className="inline-flex flex-wrap gap-1 p-1 bg-bg-card border border-border rounded-lg"
            role="tablist"
            aria-label="Navigation"
          >
            {NAV_TABS.map((tab) => {
              const isActive = activeNavId === tab.id;
              return (
                <button
                  key={tab.id}
                  id={`tab-${tab.id}`}
                  onClick={() => navOnSelect(tab.id)}
                  role="tab"
                  aria-selected={isActive}
                  tabIndex={isActive ? 0 : -1}
                  className={`px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${
                    isActive
                      ? "text-accent bg-bg-elevated shadow-[0_0_12px_rgba(250,204,21,0.25)]"
                      : "text-text-secondary hover:text-text-primary"
                  }`}
                >
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>
      </nav>

      <main className="px-4 sm:px-6 py-6 max-w-[1500px] mx-auto">
        {page === "home" && (
          <div id="page-home" role="tabpanel" aria-labelledby="tab-home" tabIndex={-1} className="page-enter outline-none">
            <ErrorBoundary>
              <Landing />
            </ErrorBoundary>
          </div>
        )}
        {page === "lookup" && (
          <div id="page-lookup" role="tabpanel" aria-labelledby="tab-lookup" tabIndex={-1} className="outline-none">
            <ErrorBoundary>
              <HomePage
                 initialValue={ioc}
                 initialType={iocType}
                 tool={tool}
                initialBatchId={batchId}
                batchResult={batchResult}
                historyId={historyId}
                isHistorical={isHistorical}
                batchResultItem={batchResultItem}
                fromBatch={fromBatch}
                autoRescan={autoRescan}
                createdAt={createdAt}
              />
            </ErrorBoundary>
          </div>
        )}
      </main>

      {authRequired && (
        <AuthPrompt
          onSubmit={(value) => {
            setRuntimeApiKey(value);
            window.location.reload();
          }}
        />
      )}

      <ToastContainer />
    </div>
  );
}
