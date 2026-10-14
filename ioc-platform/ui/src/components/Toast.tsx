import { useEffect, useRef, useState } from "react";

interface ToastData {
  id: string;
  message: string;
  type: "success" | "error" | "info";
}

type ToastListener = (t: ToastData) => void;
const toastListeners = new Set<ToastListener>();

export function showToast(message: string, type: "success" | "error" | "info" = "info") {
  const id = Math.random().toString(36).slice(2);
  toastListeners.forEach((fn) => fn({ id, message, type }));
}

const TYPE_STYLES = {
  success: "border-green-500/30 bg-green-500/10 text-green-400",
  error: "border-red-500/30 bg-red-500/10 text-red-400",
  info: "border-accent/30 bg-accent/10 text-accent",
};

const TOAST_DURATION = 3500;

export default function ToastContainer() {
  const [toasts, setToasts] = useState<ToastData[]>([]);
  const timersRef = useRef<Map<string, number>>(new Map());

  useEffect(() => {
    const timers = timersRef.current;
    const handler: ToastListener = (t) => {
      setToasts((prev) => [...prev, t]);
      const timer = window.setTimeout(() => {
        setToasts((prev) => prev.filter((x) => x.id !== t.id));
        timers.delete(t.id);
      }, TOAST_DURATION);
      timers.set(t.id, timer);
    };
    toastListeners.add(handler);
    return () => {
      toastListeners.delete(handler);
      timers.forEach((timer) => window.clearTimeout(timer));
      timers.clear();
    };
  }, []);

  function dismiss(id: string) {
    const timer = timersRef.current.get(id);
    if (timer !== undefined) window.clearTimeout(timer);
    timersRef.current.delete(id);
    setToasts((prev) => prev.filter((x) => x.id !== id));
  }

  return (
    <div
      className="fixed bottom-4 right-4 z-50 space-y-2"
      role="region"
      aria-live="polite"
      aria-label="Notifications"
    >
      {toasts.map((t) => (
        <div
          key={t.id}
          role={t.type === "error" ? "alert" : "status"}
          className={`px-4 py-2 rounded-lg border text-sm shadow-lg toast-in flex items-center gap-3 ${TYPE_STYLES[t.type]}`}
        >
          <span className="flex-1">{t.message}</span>
          <button
            onClick={() => dismiss(t.id)}
            className="shrink-0 opacity-60 hover:opacity-100 transition-opacity"
            aria-label="Dismiss notification"
          >
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      ))}
    </div>
  );
}
