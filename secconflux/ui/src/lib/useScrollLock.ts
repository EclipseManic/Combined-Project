import { useEffect } from "react";

/**
 * Locks page scrolling while a full-screen overlay is open.
 *
 * WHY THE EARLIER FIX DID NOT WORK
 *
 * `overscroll-behavior: contain` only has an effect on an element that is a
 * SCROLL CONTAINER — one with `overflow` other than `visible`. A dropdown whose
 * content fits has no overflow, so it is not a scroll container, the property
 * is inert on it, and a wheel gesture over it falls through to the nearest
 * scrollable ancestor. That ancestor is the document. So the page behind the
 * menu scrolled, and `contain` had changed nothing.
 *
 * Two things have to be true, and only doing one of them is why this kept
 * coming back:
 *
 *   1. the surface that eats the gesture must BE a scroll container, so a
 *      dropdown now carries `overflow-y: auto` and is genuinely scrollable;
 *   2. a full-screen overlay must remove the document from the scroll chain
 *      entirely, which is what this hook does.
 *
 * Both, or the background scrolls again.
 */

let locks = 0;
let savedHtmlOverflow: string | null = null;
let savedBodyPaddingRight: string | null = null;

/** Lock on documentElement, not body.
 *
 *  In standards mode the document's scrolling element is <html>, and `overflow`
 *  propagates DOWNWARD from <html> to the viewport — never upward from
 *  <body>. So `body { overflow: hidden }` leaves the page perfectly
 *  scrollable: the wheel skips straight past the body to the viewport.
 *  That is why every overlay leaked scroll no matter what the body said.
 *
 *  The padding compensation stays on <body> so the content does not shift
 *  sideways when the scrollbar disappears. */
function sync() {
  const shouldLock = locks > 0;
  const html = document.documentElement;
  if (shouldLock && savedHtmlOverflow === null) {
    const gap = window.innerWidth - html.clientWidth;
    savedHtmlOverflow = html.style.overflow;
    savedBodyPaddingRight = document.body.style.paddingRight;
    html.style.overflow = "hidden";
    if (gap > 0) document.body.style.paddingRight = `${gap}px`;
  } else if (!shouldLock && savedHtmlOverflow !== null) {
    html.style.overflow = savedHtmlOverflow;
    document.body.style.paddingRight = savedBodyPaddingRight ?? "";
    savedHtmlOverflow = null;
    savedBodyPaddingRight = null;
  }
}

export function useScrollLock(active: boolean) {
  useEffect(() => {
    if (!active) return;
    locks += 1;
    sync();
    return () => {
      locks -= 1;
      if (locks < 0) locks = 0;
      sync();
    };
  }, [active]);
}