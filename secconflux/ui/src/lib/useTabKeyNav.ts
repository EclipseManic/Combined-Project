import { useCallback, useRef } from "react";

/**
 * Left/Right arrow navigation across a tab strip, wrapping at both ends and
 * moving DOM focus to the newly selected tab.
 *
 * Copied from ioc-platform/ui/src/App.tsx:69 `useTabsKeyNav`. That is the
 * behaviour the original has and SecConflux did not: arrow keys stepped
 * through the results list, but the header's own tab strips were reachable
 * only by Tab or by mouse. For a strip of five or six chips that is the
 * difference between "keyboard works" and "the keyboard skips it".
 *
 * Wrapping rather than clamping is deliberate. Clamping makes the keys appear
 * to stop working at the ends, which is the same complaint as the palette
 * had before it wrapped.
 */
export function useTabKeyNav(
  list: readonly string[],
  active: string,
  onSelect: (id: string) => void,
) {
  const listRef = useRef<HTMLDivElement>(null);

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (!list.length) return;
      const idx = Math.max(0, list.indexOf(active));
      let next: number | null = null;
      if (e.key === "ArrowRight") next = (idx + 1) % list.length;
      else if (e.key === "ArrowLeft") next = (idx - 1 + list.length) % list.length;
      else if (e.key === "Home") next = 0;
      else if (e.key === "End") next = list.length - 1;
      if (next === null) return;
      e.preventDefault();
      onSelect(list[next]);
      // Move real focus too, so the next arrow press continues from the new
      // position instead of jumping back.
      listRef.current
        ?.querySelectorAll<HTMLElement>('[role="tab"]')
        ?.[next]?.focus();
    },
    [list, active, onSelect],
  );

  return { listRef, onKeyDown };
}