import { useEffect, useRef } from "react";
import { useHashRoute, parseRoute } from "./lib/router";
import { ShellProvider, useShell, toolFromRoute } from "./lib/shell-context";
import { TOOL_BY_ID, LANDING_ORDER } from "./lib/tools";
import { AppHeader, CommandPalette, ToastHost, ToolErrorBoundary } from "./shell/chrome";
import { Tour } from "./shell/tour";
import { Landing } from "./pages/Landing";
import { MalwarePage } from "./pages/tools/Malware";
import { IocPage } from "./pages/tools/Ioc";
import { EventsPage } from "./pages/tools/Events";
import { PhishingPage } from "./pages/tools/Phishing";
import { RuleForgePage } from "./pages/tools/RuleForge";

/* =============================================================
   ROUTER

   Hash routes, deliberately. The five backends get mounted under
   path prefixes on this same origin (/tool/malware/, /tool/ioc/, ...)
   when they are wired in. A history router would own the whole path
   namespace and turn every one of those mounts into a negotiation.
   Hash routing keeps the shell's routes in a namespace that cannot
   collide with a proxied backend.
   ============================================================= */

function Routes() {
  const [route, navigate] = useHashRoute();
  const { tool, setTool, setPaletteOpen, setTourOpen, markVisit, visits } = useShell();
  const { tool: toolFragment } = parseRoute(route);
  const headerRef = useRef<HTMLElement>(null);

  // Resolve the route fragment into a tool id, and push that into shell
  // state so the accent follows navigation. Doing it here, in one place,
  // is what keeps the palette, the switcher and the URL from disagreeing
  // about which tool is open.
  const resolved = toolFromRoute(toolFragment);

  useEffect(() => {
    if (resolved !== tool) setTool(resolved);
  }, [resolved, tool, setTool]);

  /* Always land at the top of the new page. A hash change does not scroll by
     itself, so switching tools kept the previous page's scroll offset — which
     is how Home could open halfway down its own hero on a second visit, and
     how a tool opened mid-report instead of at the top of its first section. */
  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: "auto" });
  }, [resolved]);

  // Publish the header's REAL height as a CSS variable.
  //
  // The hard-coded value was wrong by a pixel: row 1 is 56px, the border is
  // 1px, row 2 is 44px, so the header is 101px and the constant said 100.
  // Every sticky row sat one pixel under the header as a result. Rather than
  // re-derive the number whenever the header changes, measure it.
  useEffect(() => {
    const el = headerRef.current;
    if (!el) return;
    const publish = () =>
      document.documentElement.style.setProperty(
        "--shell-header-h",
        `${el.offsetHeight}px`,
      );
    publish();
    const ro = new ResizeObserver(publish);
    ro.observe(el);
    return () => ro.disconnect();
  }, [resolved]);

  // First visit to a tool opens the tour once, so a new user is walked
  // through the switcher instead of discovering it by accident. Tracked
  // per browser profile, and only after they have actually landed there.
  useEffect(() => {
    if (resolved === "home") return;
    if ((visits[resolved] ?? 0) === 0) setTourOpen(true);
    markVisit(resolved);
  }, [resolved, visits, setTourOpen, markVisit]);

  // Global keyboard: Ctrl/Cmd+K opens the palette, 1-5 jump to a tool,
  // Escape closes whatever is open.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const inField =
        e.target instanceof HTMLElement &&
        (e.target.tagName === "INPUT" ||
          e.target.tagName === "TEXTAREA" ||
          e.target.isContentEditable);

      // Ctrl/Cmd+M opens the palette. M rather than K: K is taken by the
      // browser's own omnibox search on some setups and loses the race, so the
      // shortcut appeared to do nothing.
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "m") {
        e.preventDefault();
        setPaletteOpen(true);
        return;
      }
      if (e.key === "?" && !inField) {
        e.preventDefault();
        setTourOpen(true);
        return;
      }
      if (inField || e.ctrlKey || e.metaKey || e.altKey) return;

      /* 0 goes Home; 1-5 go to the five tools in landing order. Home has a
         hotkey like every other destination, so it is numbered 0 rather than
         left unlabelled — an unnumbered entry in a numbered list reads as an
         oversight rather than as a deliberate choice. */
      const n = Number(e.key);
      if (Number.isInteger(n) && n === 0) {
        setTool("home");
        navigate("/");
        return;
      }
      if (Number.isInteger(n) && n >= 1 && n <= LANDING_ORDER.length) {
        const t = LANDING_ORDER[n - 1];
        navigate(TOOL_BY_ID[t].path);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [navigate, setPaletteOpen, setTourOpen]);

  const which =
    resolved === "home" ? (
      <Landing navigate={navigate} />
    ) : (
      <ToolErrorBoundary
        toolName={TOOL_BY_ID[resolved].name}
        onHome={() => navigate("/")}
      >
        {resolved === "malware" && <MalwarePage navigate={navigate} />}
        {resolved === "ioc" && <IocPage navigate={navigate} />}
        {resolved === "events" && <EventsPage navigate={navigate} />}
        {resolved === "phishing" && <PhishingPage navigate={navigate} />}
        {resolved === "ruleforge" && <RuleForgePage navigate={navigate} />}
      </ToolErrorBoundary>
    );

  return (
    <div className="min-h-full flex flex-col">
      <AppHeader ref={headerRef} navigate={navigate} />
      <main className="flex-1 min-w-0">{which}</main>
      <CommandPalette navigate={navigate} />
      <Tour navigate={navigate} />
      <ToastHost />
    </div>
  );
}

export default function App() {
  return (
    <ShellProvider>
      <Routes />
    </ShellProvider>
  );
}
