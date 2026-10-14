import { useEffect, useRef } from "react";

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

export default function Modal({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: string; children: React.ReactNode }) {
  const overlayRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const previouslyFocusedRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (open) {
      previouslyFocusedRef.current = document.activeElement as HTMLElement | null;
      document.body.style.overflow = "hidden";
      closeRef.current?.focus();

      const keyHandler = (e: KeyboardEvent) => {
        if (e.key === "Escape") onClose();
        if (e.key === "Tab" && panelRef.current) {
          const focusables = Array.from(panelRef.current.querySelectorAll<HTMLElement>(FOCUSABLE));
          if (focusables.length === 0) return;
          const first = focusables[0];
          const last = focusables[focusables.length - 1];
          const active = document.activeElement as HTMLElement | null;
          if (e.shiftKey && (active === first || !panelRef.current.contains(active))) {
            e.preventDefault();
            last.focus();
          } else if (!e.shiftKey && active === last) {
            e.preventDefault();
            first.focus();
          }
        }
      };
      window.addEventListener("keydown", keyHandler);
      return () => {
        document.body.style.overflow = "";
        window.removeEventListener("keydown", keyHandler);
        previouslyFocusedRef.current?.focus();
      };
    }
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={(e) => { if (e.target === overlayRef.current) onClose(); }}
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      <div ref={panelRef} className="bg-bg-card border border-border rounded-xl shadow-2xl w-full max-w-lg mx-4 max-h-[80vh] overflow-auto">
        <div className="flex items-center justify-between px-5 py-3 border-b border-border">
          <h2 className="text-sm font-semibold">{title}</h2>
          <button ref={closeRef} onClick={onClose} className="text-text-secondary hover:text-text-primary transition-colors" aria-label="Close">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}
