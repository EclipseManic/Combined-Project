import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Reports which edges of a horizontally scrollable strip are currently
 * clipped, so a fade can be applied only where there is something to fade.
 *
 * A permanently applied edge mask looks like a rendering fault when nothing
 * is actually cut off — "Dialects" fading out on a 1920px screen reads as
 * clipped text, not as a hint. And a mask that is missing when the strip IS
 * clipped is worse: the last chip appears sliced in half with no indication
 * that the row scrolls. So the two are derived from measurement, not guessed.
 */
export interface EdgeFade {
  left: boolean;
  right: boolean;
}

export function useEdgeFade<T extends HTMLElement>() {
  const ref = useRef<T | null>(null);
  const [fade, setFade] = useState<EdgeFade>({ left: false, right: false });

  const measure = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    const max = el.scrollWidth - el.clientWidth;
    // A 2px tolerance: sub-pixel layout rounding otherwise flickers the
    // fade on and off as a scrollbar appears and disappears.
    const atStart = el.scrollLeft <= 2;
    const atEnd = el.scrollLeft >= max - 2;
    setFade((prev) => {
      const next = { left: max > 2 && !atStart, right: max > 2 && !atEnd };
      return prev.left === next.left && prev.right === next.right ? prev : next;
    });
  }, []);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    for (const child of Array.from(el.children)) ro.observe(child);
    el.addEventListener("scroll", measure, { passive: true });
    return () => {
      ro.disconnect();
      el.removeEventListener("scroll", measure);
    };
  }, [measure]);

  return { ref, fade };
}
