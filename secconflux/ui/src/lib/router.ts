import { useCallback, useEffect, useState } from "react";

/**
 * Hash routing, deliberately.
 *
 * The five backends are mounted under path prefixes on the same origin
 * (/tool/ioc/, /tool/events/, ...). A history-based router would own
 * the whole path namespace and make every one of those mounts a
 * negotiation. Hash routing keeps the shell's routes inside a
 * namespace that cannot collide with a proxied backend, so the shell
 * and the backends never have to agree about who owns which path.
 */
export function useHashRoute(): [string, (to: string, opts?: { replace?: boolean }) => void] {
  const read = () => window.location.hash.replace(/^#/, "") || "/";
  const [route, setRoute] = useState<string>(read);

  useEffect(() => {
    const onChange = () => setRoute(read());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  const navigate = useCallback((to: string, opts?: { replace?: boolean }) => {
    const target = `#${to}`;
    if (opts?.replace) {
      window.history.replaceState(null, "", target);
      setRoute(to);
    } else if (window.location.hash !== target) {
      window.location.hash = to;
    } else {
      setRoute(to);
    }
  }, []);

  return [route, navigate];
}

export interface RouteMatch {
  /** First segment, e.g. "t" or "". Empty for the landing page. */
  root: string;
  /** Second segment, e.g. "malware". */
  tool: string;
  /** Everything after that, unparsed. */
  rest: string;
}

export function parseRoute(route: string): RouteMatch {
  const clean = route.split("?")[0].replace(/^\/+|\/+$/g, "");
  const parts = clean.split("/").filter(Boolean);
  return {
    root: parts[0] ?? "",
    tool: parts[1] ?? "",
    rest: parts.slice(2).join("/"),
  };
}
