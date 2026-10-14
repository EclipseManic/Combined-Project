import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";
import { useEffect, useRef, useState } from "react";
import { useScrollLock } from "../lib/useScrollLock";
import type { CSSProperties } from "react";
import { Icon } from "../lib/icons";
import type { IconName } from "../lib/icons";
import { cn, copyText } from "../lib/utils";
import { VERDICT_STYLE } from "../lib/tools";
import type { Verdict } from "../lib/tools";

/* =============================================================
   BUTTON
   ============================================================= */

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "subtle";
type ButtonSize = "xs" | "sm" | "md" | "lg";

const VARIANTS: Record<ButtonVariant, string> = {
  primary:
    "text-white shadow-[0_2px_12px_-2px_var(--tool-glow)] hover:brightness-110 active:brightness-95",
  secondary:
    "bg-[var(--color-surface-3)] text-[var(--color-ink)] border border-[var(--color-line-2)] hover:bg-[var(--color-surface-4)] hover:border-[var(--color-line-3)]",
  ghost:
    "text-[var(--color-ink-3)] hover:text-[var(--color-ink)] hover:bg-[var(--color-surface-3)]",
  danger:
    "bg-[rgb(248_113_113/0.12)] text-[var(--color-bad)] border border-[rgb(248_113_113/0.32)] hover:bg-[rgb(248_113_113/0.2)]",
  subtle:
    "bg-[var(--tool-tint)] text-[var(--tool-accent)] border border-[var(--tool-tint-2)] hover:bg-[var(--tool-tint-2)]",
};

/* One control scale, in one place.

   `sm` is 32px, which is also the size of the header's icon button and of a
   main tab. That is deliberate: the header's right rail puts section chips,
   the tool's action buttons and the theme toggle side by side, and if those
   three are 28/34/32 the row is visibly ragged no matter how each item is
   styled internally. Everything in a rail shares the rail's height. */
const SIZES: Record<ButtonSize, string> = {
  xs: "h-6 px-2.5 text-[12px] gap-1.5 rounded-[var(--radius-sm)]",
  sm: "h-8 px-3 text-[13px] gap-1.5 rounded-[var(--radius-sm)]",
  md: "h-9 px-4 text-[14px] gap-2 rounded-[var(--radius-md)]",
  lg: "h-11 px-6 text-[15px] gap-2.5 rounded-[var(--radius-lg)]",
};

/* Icon size follows the label size. A fixed 15px icon next to a 12px label
   makes small buttons look like they are mostly icon. */
const ICON_SIZE: Record<ButtonSize, number> = { xs: 12, sm: 13, md: 14, lg: 15 };

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: IconName;
  iconRight?: IconName;
  loading?: boolean;
  full?: boolean;
}

export function Button({
  variant = "secondary",
  size = "sm",
  icon,
  iconRight,
  loading,
  full,
  className,
  children,
  disabled,
  ...rest
}: ButtonProps) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center font-semibold whitespace-nowrap",
        "transition-[background-color,border-color,color,filter,transform] duration-150",
        "disabled:opacity-45 disabled:pointer-events-none select-none",
        SIZES[size],
        VARIANTS[variant],
        full && "w-full",
        className,
      )}
      style={
        variant === "primary"
          ? {
              background:
                "linear-gradient(135deg, var(--tool-accent) 0%, var(--tool-accent-2) 100%)",
            }
          : undefined
      }
      disabled={disabled || loading}
      {...rest}
    >
      {loading ? (
        <span
          className="rounded-full border-2 border-current border-t-transparent"
          style={{
            width: ICON_SIZE[size],
            height: ICON_SIZE[size],
            animation: "sc-spin 0.6s linear infinite",
          }}
        />
      ) : (
        icon && <Icon name={icon} size={ICON_SIZE[size]} />
      )}
      {children}
      {iconRight && !loading && <Icon name={iconRight} size={ICON_SIZE[size]} />}
    </button>
  );
}

/* =============================================================
   CARD
   ============================================================= */

/* =============================================================
   PANEL GRID

   Reproduced from the original tool's own CSS (styles.css:1086-1101):
   a two-column grid with 16px gaps, where `panel-wide` spans both
   columns. Panels carry their own header band with a raised background
   and a border, which is what makes a wall of them read as separate
   instruments rather than one long page.
   ============================================================= */

export function PanelGrid({ children }: { children: ReactNode }) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">{children}</div>
  );
}

export function Panel({
  title,
  icon,
  wide,
  action,
  children,
  className,
}: {
  title: string;
  /** Emoji in the originals (⚙️, 🧬, 🧮, 🎯, 📄, 🧵). Typed as a node so a
   *  panel can carry either an emoji or one of the set icons. */
  icon?: ReactNode;
  wide?: boolean;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={cn(
        "overflow-hidden rounded-[var(--radius-lg)] bg-[var(--color-surface)]",
        "border border-[var(--color-line)] shadow-[var(--shadow-sm)]",
        "transition-shadow duration-200 hover:shadow-[var(--shadow-md)]",
        wide && "lg:col-span-2",
        className,
      )}
    >
      <div
        className="flex items-center gap-2.5 px-4 py-3 border-b"
        style={{
          background: "var(--color-surface-2)",
          borderColor: "var(--color-line)",
        }}
      >
        {icon && (
          <span className="text-[15px] leading-none shrink-0" aria-hidden>
            {icon}
          </span>
        )}
        <h3 className="text-[14px] font-bold tracking-[-0.01em] flex-1 min-w-0 truncate">
          {title}
        </h3>
        {action && <div className="shrink-0 flex items-center gap-1.5">{action}</div>}
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Card({
  children,
  className,
  interactive,
  glow,
  ...rest
}: {
  children: ReactNode;
  className?: string;
  interactive?: boolean;
  glow?: boolean;
} & React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "bg-[var(--color-surface)] border border-[var(--color-line)] rounded-[var(--radius-lg)]",
        "relative",
        interactive &&
          "transition-[border-color,transform,box-shadow] duration-200 cursor-pointer hover:border-[var(--tool-tint-2)] hover:-translate-y-0.5",
        glow && "sc-accent-edge shadow-[var(--shadow-md)]",
        className,
      )}
      {...rest}
    >
      {children}
    </div>
  );
}

export function CardHead({
  title,
  icon,
  count,
  action,
  subtitle,
  className,
}: {
  title: ReactNode;
  icon?: IconName;
  count?: number | string;
  action?: ReactNode;
  subtitle?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex items-center justify-between gap-3 px-4 py-3 border-b border-[var(--color-line)]",
        /* Wraps rather than crushing the title. Several card heads carry a
           search box and a select in the action slot, which is ~450px of
           controls; without wrapping, a narrow window squeezes the heading
           into a sliver next to them. */
        "flex-wrap",
        className,
      )}
    >
      <div className="flex items-center gap-2.5 min-w-0">
        {icon && (
          <span
            className="grid place-items-center w-6 h-6 rounded-[var(--radius-sm)] shrink-0"
            style={{ background: "var(--tool-tint)", color: "var(--tool-accent)" }}
          >
            <Icon name={icon} size={13} />
          </span>
        )}
        <div className="min-w-0">
          <h3 className="text-[13px] font-bold tracking-[0.01em] truncate">{title}</h3>
          {subtitle && (
            <p className="text-[12px] text-[var(--color-ink-4)] truncate mt-px">{subtitle}</p>
          )}
        </div>
        {count !== undefined && (
          <span
            className="ml-1 px-1.5 py-0.5 rounded-[var(--radius-xs)] text-[11px] font-bold mono"
            style={{ background: "var(--tool-tint)", color: "var(--tool-accent)" }}
          >
            {count}
          </span>
        )}
      </div>
      {action && <div className="flex items-center gap-1.5 shrink-0 ml-auto">{action}</div>}
    </div>
  );
}

export function CardBody({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("p-4", className)}>{children}</div>;
}

/* =============================================================
   BADGE
   ============================================================= */

export function Badge({
  children,
  tone = "neutral",
  className,
  dot,
  mono,
}: {
  children: ReactNode;
  tone?: "neutral" | "accent" | "ok" | "warn" | "bad" | "info" | "magic";
  className?: string;
  dot?: boolean;
  mono?: boolean;
}) {
  const tones: Record<string, { bg: string; fg: string; bd: string }> = {
    neutral: {
      bg: "var(--color-surface-3)",
      fg: "var(--color-ink-3)",
      bd: "var(--color-line-2)",
    },
    accent: {
      bg: "var(--tool-tint)",
      fg: "var(--tool-accent)",
      bd: "var(--tool-tint-2)",
    },
    ok: { bg: "rgb(52 211 153 / 0.12)", fg: "var(--color-ok)", bd: "rgb(52 211 153 / 0.28)" },
    warn: { bg: "rgb(251 191 36 / 0.12)", fg: "var(--color-warn)", bd: "rgb(251 191 36 / 0.28)" },
    bad: { bg: "rgb(248 113 113 / 0.12)", fg: "var(--color-bad)", bd: "rgb(248 113 113 / 0.3)" },
    info: { bg: "rgb(56 189 248 / 0.12)", fg: "var(--color-info)", bd: "rgb(56 189 248 / 0.28)" },
    magic: { bg: "rgb(168 85 247 / 0.12)", fg: "var(--color-magic)", bd: "rgb(168 85 247 / 0.28)" },
  };
  const t = tones[tone];
  return (
    <span
      className={cn(
        // A FIXED height, not padding around a line box. The body carries
        // line-height 1.6, so a 11px badge inherited ~17.6px of leading and
        // ended up taller than a 12px badge in the same row. Rows of chips
        // with variable content are where a toolbar starts to look ragged.
        //
        // `max-w-full` + truncate is a safety net: a chip in a wrapping row
        // can still be wider than its container if its label is long, and an
        // overflowing chip pushes a card's edge out rather than shrinking.
        "inline-flex items-center gap-1.5 h-[22px] max-w-full px-2",
        "rounded-[var(--radius-xs)] truncate",
        "text-[11px] font-semibold leading-none border",
        mono && "mono",
        className,
      )}
      style={{ background: t.bg, color: t.fg, borderColor: t.bd }}
    >
      {dot && (
        <span
          className="w-1.5 h-1.5 rounded-full"
          style={{ background: t.fg, flexShrink: 0 }}
        />
      )}
      {children}
    </span>
  );
}

export function VerdictBadge({ verdict, className }: { verdict: Verdict; className?: string }) {
  const s = VERDICT_STYLE[verdict];
  return (
    <span
      className={cn(
        // Same 22px as Badge, on purpose: these two sit side by side in the
        // same row and were 4px apart in height.
        "inline-flex items-center gap-1.5 h-[22px] px-2.5 rounded-[var(--radius-sm)]",
        "text-[11.5px] font-extrabold tracking-[0.04em] leading-none border",
        className,
      )}
      style={{ background: s.bg, color: s.color, borderColor: s.border }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: s.color }} />
      {s.label}
    </span>
  );
}

/* =============================================================
   TABS
   ============================================================= */

export function TabBar({
  tabs,
  active,
  onChange,
  className,
}: {
  tabs: { id: string; label: string; icon?: IconName; count?: number }[];
  active: string;
  onChange: (id: string) => void;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex items-center gap-1 p-1 rounded-[var(--radius-md)] overflow-x-auto",
        "bg-[var(--color-surface-2)] border border-[var(--color-line)]",
        className,
      )}
      role="tablist"
    >
      {tabs.map((t) => {
        const on = t.id === active;
        return (
          <button
            key={t.id}
            role="tab"
            aria-selected={on}
            onClick={() => onChange(t.id)}
            className={cn(
              "inline-flex items-center gap-1.5 px-3 h-8 rounded-[var(--radius-sm)]",
              "text-[13px] font-semibold whitespace-nowrap",
              "transition-colors duration-150",
              on
                ? "text-[var(--tool-accent)]"
                : "text-[var(--color-ink-3)] hover:text-[var(--color-ink)]",
            )}
            style={
              on
                ? {
                    background: "var(--tool-tint)",
                    boxShadow: "inset 0 0 0 1px var(--tool-tint-2)",
                  }
                : undefined
            }
          >
            {t.icon && <Icon name={t.icon} size={14} />}
            {t.label}
            {t.count !== undefined && (
              <span
                className="px-1.5 text-[10.5px] rounded-[3px] mono"
                style={{
                  background: on ? "var(--tool-tint-2)" : "var(--color-surface-3)",
                  color: on ? "var(--tool-accent)" : "var(--color-ink-4)",
                }}
              >
                {t.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

export function SubNav({
  tabs,
  active,
  onChange,
}: {
  tabs: { id: string; label: string; icon?: IconName }[];
  active: string;
  onChange: (id: string) => void;
}) {
  return (
    <div className="flex items-center gap-0.5 overflow-x-auto border-b border-[var(--color-line)]">
      {tabs.map((t) => {
        const on = t.id === active;
        return (
          <button
            key={t.id}
            onClick={() => onChange(t.id)}
            className={cn(
              "relative inline-flex items-center gap-1.5 px-3.5 h-11",
              "text-[13.5px] font-semibold whitespace-nowrap transition-colors",
              on
                ? "text-[var(--tool-accent)]"
                : "text-[var(--color-ink-3)] hover:text-[var(--color-ink-2)]",
            )}
          >
            {t.icon && <Icon name={t.icon} size={15} />}
            {t.label}
            {on && (
              <span
                className="absolute inset-x-2 bottom-0 h-[2px] rounded-full"
                style={{ background: "var(--tool-accent)" }}
              />
            )}
          </button>
        );
      })}
    </div>
  );
}

/* =============================================================
   SCORE RING
   ============================================================= */

export function ScoreRing({
  score,
  size = 132,
  label,
  sublabel,
  thickness = 9,
}: {
  score: number;
  size?: number;
  label?: string;
  sublabel?: string;
  thickness?: number;
}) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score));
  const color =
    pct >= 70
      ? "var(--color-bad)"
      : pct >= 45
        ? "var(--color-warn)"
        : pct >= 20
          ? "var(--color-warn-2)"
          : "var(--color-ok)";

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg viewBox="0 0 120 120" width={size} height={size} style={{ display: "block" }}>
        <circle
          cx="60"
          cy="60"
          r={r}
          fill="none"
          stroke="var(--color-surface-3)"
          strokeWidth={thickness}
        />
        <circle
          cx="60"
          cy="60"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={thickness}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c - (pct / 100) * c}
          transform="rotate(-90 60 60)"
          style={{
            transition: "stroke-dashoffset 900ms var(--ease-out), stroke 400ms",
            filter: `drop-shadow(0 0 8px ${color}66)`,
          }}
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <div
            className="font-black leading-none tracking-tight"
            style={{ fontSize: size * 0.3, color }}
          >
            {Math.round(pct)}
          </div>
          {label && (
            <div
              className="font-bold tracking-[0.1em] mt-1"
              style={{ fontSize: size * 0.085, color }}
            >
              {label}
            </div>
          )}
          {sublabel && (
            <div
              className="text-[var(--color-ink-4)] mt-0.5"
              style={{ fontSize: size * 0.075 }}
            >
              {sublabel}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* =============================================================
   PROGRESS
   ============================================================= */

export function ProgressBar({
  value,
  height = 6,
  color,
  striped,
}: {
  value: number;
  height?: number;
  color?: string;
  striped?: boolean;
}) {
  const c = color ?? "var(--tool-accent)";
  return (
    <div
      className="w-full overflow-hidden rounded-full bg-[var(--color-surface-3)]"
      style={{ height }}
      role="progressbar"
      aria-valuenow={Math.round(value)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className="h-full rounded-full relative overflow-hidden"
        style={{
          width: `${Math.max(0, Math.min(100, value))}%`,
          background: c,
          transition: "width 400ms var(--ease-out)",
        }}
      >
        {striped && (
          <span
            className="absolute inset-0"
            style={{
              backgroundImage:
                "repeating-linear-gradient(115deg, rgba(255,255,255,0.22) 0 8px, transparent 8px 16px)",
              backgroundSize: "200% 100%",
              animation: "sc-stripes 0.8s linear infinite",
            }}
          />
        )}
      </div>
    </div>
  );
}

/* =============================================================
   TABLE
   ============================================================= */

export function Table({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn("overflow-x-auto sc-overscroll", className)}>
      <table className="w-full border-collapse text-[13px]">{children}</table>
    </div>
  );
}

export function Th({
  children,
  className,
  align = "left",
  onClick,
  sorted,
}: {
  children?: ReactNode;
  className?: string;
  align?: "left" | "right" | "center";
  onClick?: () => void;
  sorted?: "asc" | "desc" | null;
}) {
  return (
    <th
      onClick={onClick}
      className={cn(
        "px-3 py-2.5 text-[11px] font-bold tracking-[0.06em] uppercase",
        "text-[var(--color-ink-4)] border-b border-[var(--color-line)] whitespace-nowrap",
        onClick && "cursor-pointer hover:text-[var(--color-ink-2)] select-none",
        className,
      )}
      style={{ textAlign: align }}
    >
      <span className="inline-flex items-center gap-1">
        {children}
        {sorted && (
          <Icon name={sorted === "asc" ? "arrow-up" : "arrow-down"} size={11} />
        )}
      </span>
    </th>
  );
}

export function Td({
  children,
  className,
  align = "left",
  mono,
  colSpan,
  style,
}: {
  children?: ReactNode;
  className?: string;
  align?: "left" | "right" | "center";
  mono?: boolean;
  colSpan?: number;
  style?: CSSProperties;
}) {
  return (
    <td
      colSpan={colSpan}
      className={cn(
        "px-3 py-2.5 border-b border-[var(--color-line)] align-middle",
        mono && "mono text-[12px]",
        className,
      )}
      style={{ textAlign: align, ...style }}
    >
      {children}
    </td>
  );
}

/* =============================================================
   KEY / VALUE
   ============================================================= */

export function KV({
  label,
  children,
  mono,
  copyable,
  className,
}: {
  label: string;
  children: ReactNode;
  mono?: boolean;
  copyable?: boolean;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  const text = typeof children === "string" ? children : undefined;

  return (
    <div
      className={cn(
        "flex items-start justify-between gap-3 py-1.5 border-b border-[var(--color-line)] last:border-0",
        className,
      )}
    >
      <span className="text-[12.5px] text-[var(--color-ink-4)] shrink-0">{label}</span>
      <div className="flex items-center gap-1.5 min-w-0 text-right">
        <span
          className={cn(
            "text-[12.5px] text-[var(--color-ink-2)] min-w-0 break-all",
            mono && "mono text-[12px]",
          )}
        >
          {children}
        </span>
        {copyable && text && (
          <button
            onClick={async () => {
              if (await copyText(text)) {
                setCopied(true);
                setTimeout(() => setCopied(false), 1400);
              }
            }}
            className="shrink-0 p-1 rounded-[4px] text-[var(--color-ink-4)] hover:text-[var(--tool-accent)] hover:bg-[var(--tool-tint)] transition-colors"
            title="Copy"
            aria-label={`Copy ${label}`}
          >
            <Icon name={copied ? "check" : "copy"} size={12} />
          </button>
        )}
      </div>
    </div>
  );
}

/* =============================================================
   STAT TILE
   ============================================================= */

export function StatTile({
  label,
  value,
  sub,
  icon,
  tone = "neutral",
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  icon?: IconName;
  tone?: "neutral" | "ok" | "warn" | "bad" | "info" | "accent";
}) {
  const colors: Record<string, string> = {
    neutral: "var(--color-ink)",
    ok: "var(--color-ok)",
    warn: "var(--color-warn)",
    bad: "var(--color-bad)",
    info: "var(--color-info)",
    accent: "var(--tool-accent)",
  };
  return (
    <div
      data-tile=""
      className="bg-[var(--color-surface-2)] border border-[var(--color-line)] rounded-[var(--radius-md)] p-3.5 flex flex-col"
    >
      {/* The label reserves two lines whether it uses one or two. Without the
          reservation, "SOURCES" sits on one line and "INDICATOR TYPES" on
          two, and the values below land on different baselines — which in a
          row of four tiles reads as four unrelated numbers rather than four
          comparable ones.

          35px, not 2.4em: 2.4em of an 11px label is 26px, but two lines at
          the inherited 1.6 leading is 35px, so an em-based reservation is
          undersized and the drift survives. The number has to be the
          rendered line box, not a multiple of the font size. */}
      <div className="flex items-start gap-1.5 min-h-[35px] text-[11px] font-bold tracking-[0.06em] uppercase text-[var(--color-ink-4)]">
        {icon && (
          <span className="shrink-0 mt-px">
            <Icon name={icon} size={12} />
          </span>
        )}
        <span className="min-w-0">{label}</span>
      </div>
      <div
        data-tile-value=""
        className="mt-1 text-[26px] font-black leading-none tracking-tight"
        style={{ color: colors[tone] }}
      >
        {value}
      </div>
      {sub && <div className="mt-1 text-[12px] text-[var(--color-ink-4)]">{sub}</div>}
    </div>
  );
}

/* =============================================================
   INPUTS
   ============================================================= */

/* `dense` rather than `size`, because `size` is a real attribute on <input>
   (its character width) and shadowing it with a styling token is the kind of
   collision that produces a mystery later. */
export function Input({
  icon,
  className,
  dense,
  inputRef,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & {
  icon?: IconName;
  dense?: boolean;
  /** A ref to the underlying <input>.
   *
   *  Event Analyzer's Ctrl+/ shortcut has to focus and select the search box
   *  (app.js:1538-1550). Without this prop there is nowhere to put that ref,
   *  because the component wraps the input in a div for the icon — so the
   *  shortcut silently did nothing. */
  inputRef?: React.Ref<HTMLInputElement>;
}) {
  return (
    <div className={cn("relative flex items-center", className)}>
      {icon && (
        <span className="absolute left-3 text-[var(--color-ink-4)] pointer-events-none flex">
          <Icon name={icon} size={dense ? 13 : 15} />
        </span>
      )}
      <input
        ref={inputRef}
        className={cn(
          "w-full rounded-[var(--radius-md)] bg-[var(--color-surface-2)]",
          "border border-[var(--color-line-2)] text-[var(--color-ink)]",
          "placeholder:text-[var(--color-ink-4)] transition-colors",
          "focus:outline-none focus:border-[var(--tool-accent)]",
          dense ? "h-8 px-2.5 pl-8 text-[13px]" : "h-9 px-3 pl-9 text-[14px]",
        )}
        {...rest}
      />
    </div>
  );
}

export function Select({
  className,
  dense,
  children,
  ...rest
}: SelectHTMLAttributes<HTMLSelectElement> & { dense?: boolean }) {
  return (
    <select
      className={cn(
        "rounded-[var(--radius-md)] bg-[var(--color-surface-2)]",
        "border border-[var(--color-line-2)] text-[var(--color-ink)]",
        "focus:outline-none focus:border-[var(--tool-accent)] cursor-pointer",
        dense ? "h-8 px-2.5 text-[13px]" : "h-9 px-3 text-[14px]",
        className,
      )}
      {...rest}
    >
      {children}
    </select>
  );
}

export function Textarea({
  className,
  mono,
  dense,
  ...rest
}: React.TextareaHTMLAttributes<HTMLTextAreaElement> & { mono?: boolean; dense?: boolean }) {
  return (
    <textarea
      className={cn(
        "w-full px-3 py-2.5 rounded-[var(--radius-md)] bg-[var(--color-surface-2)]",
        "border border-[var(--color-line-2)] text-[13.5px] text-[var(--color-ink)]",
        "placeholder:text-[var(--color-ink-4)] focus:outline-none",
        "focus:border-[var(--tool-accent)] resize-y leading-relaxed",
        dense && "text-[13px] py-2",
        mono && "mono text-[12.5px]",
        className,
      )}
      {...rest}
    />
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  hint,
  id,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  hint?: string;
  id?: string;
}) {
  return (
    <label
      htmlFor={id}
      className="flex items-center justify-between gap-4 cursor-pointer group py-1"
    >
      <span className="min-w-0">
        <span className="block text-[13.5px] font-semibold text-[var(--color-ink-2)] group-hover:text-[var(--color-ink)] transition-colors">
          {label}
        </span>
        {hint && <span className="block text-[12px] text-[var(--color-ink-4)]">{hint}</span>}
      </span>
      <button
        id={id}
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className="relative shrink-0 w-11 h-6 rounded-full transition-colors duration-200"
        style={{
          background: checked ? "var(--tool-accent)" : "var(--color-surface-4)",
          boxShadow: checked ? "0 0 0 1px var(--tool-tint-2)" : "inset 0 0 0 1px var(--color-line-2)",
        }}
      >
        <span
          className="absolute top-0.5 w-5 h-5 rounded-full bg-white shadow-sm transition-[left] duration-200"
          style={{ left: checked ? 22 : 2 }}
        />
      </button>
    </label>
  );
}

/* =============================================================
   CODE
   ============================================================= */

export function CodeBlock({
  code,
  language,
  maxHeight,
  filename,
  onCopy,
}: {
  code: string;
  language?: string;
  maxHeight?: number;
  filename?: string;
  onCopy?: (code: string) => void;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-[var(--radius-md)] border border-[var(--color-line)] overflow-hidden bg-[var(--color-canvas-2)]">
      <div className="flex items-center justify-between px-3 py-1.5 bg-[var(--color-surface-2)] border-b border-[var(--color-line)]">
        <div className="flex items-center gap-2 min-w-0">
          <span className="flex gap-1 shrink-0">
            {["#f87171", "#fbbf24", "#34d399"].map((c) => (
              <span
                key={c}
                className="w-2 h-2 rounded-full"
                style={{ background: c, opacity: 0.65 }}
              />
            ))}
          </span>
          {filename && (
            <span className="text-[11.5px] mono text-[var(--color-ink-3)] truncate">
              {filename}
            </span>
          )}
          {language && (
            <span className="text-[10.5px] font-bold tracking-[0.06em] uppercase text-[var(--color-ink-4)] px-1.5 py-px rounded bg-[var(--color-surface-3)]">
              {language}
            </span>
          )}
        </div>
        <button
          onClick={async () => {
            const ok = await copyText(code);
            onCopy?.(code);
            if (ok) {
              setCopied(true);
              setTimeout(() => setCopied(false), 1400);
            }
          }}
          className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11.5px] font-semibold text-[var(--color-ink-4)] hover:text-[var(--tool-accent)] hover:bg-[var(--tool-tint)] transition-colors"
        >
          <Icon name={copied ? "check" : "copy"} size={12} />
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre
        className="mono text-[12px] leading-relaxed p-3 overflow-auto whitespace-pre text-[var(--color-ink-2)]"
        style={{ maxHeight }}
      >
        {code}
      </pre>
    </div>
  );
}

/* =============================================================
   EMPTY STATE
   ============================================================= */

export function EmptyState({
  icon = "file",
  title,
  body,
  action,
  compact,
}: {
  icon?: IconName;
  title: string;
  body?: ReactNode;
  action?: ReactNode;
  /** Drops the generous vertical padding. Use when the empty state is a hero
   *  band above other content rather than the whole page. */
  compact?: boolean;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center text-center px-6",
        compact ? "py-6" : "py-16",
      )}
    >
      <div
        className="grid place-items-center w-14 h-14 rounded-[var(--radius-lg)] mb-4"
        style={{
          background: "var(--tool-tint)",
          border: "1px solid var(--tool-tint-2)",
          color: "var(--tool-accent)",
        }}
      >
        <Icon name={icon} size={24} strokeWidth={1.4} />
      </div>
      <h3 className="text-[16px] font-bold">{title}</h3>
      {body && (
        <p className="mt-1.5 text-[13.5px] text-[var(--color-ink-4)] max-w-sm leading-relaxed">
          {body}
        </p>
      )}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

/* =============================================================
   MODAL
   ============================================================= */

export function Modal({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
  width = 560,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: ReactNode;
  footer?: ReactNode;
  width?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  useScrollLock(open);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[200] flex items-start justify-center p-4 pt-[8vh] overflow-y-auto sc-anim-in sc-overscroll"
      style={{ background: "rgb(0 0 0 / 0.62)", backdropFilter: "blur(6px)" }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="sc-anim-pop w-full rounded-[var(--radius-xl)] overflow-hidden"
        style={{
          maxWidth: width,
          background: "var(--color-surface)",
          border: "1px solid var(--color-line-2)",
          boxShadow: "var(--shadow-lg)",
        }}
      >
        <div className="flex items-start justify-between gap-4 px-5 py-4 border-b border-[var(--color-line)]">
          <div className="min-w-0">
            <h2 className="text-[16px] font-bold tracking-tight">{title}</h2>
            {subtitle && (
              <p className="text-[13px] text-[var(--color-ink-4)] mt-0.5">{subtitle}</p>
            )}
          </div>
          <button
            onClick={onClose}
            className="p-1.5 -m-1 rounded-[var(--radius-sm)] text-[var(--color-ink-4)] hover:text-[var(--color-ink)] hover:bg-[var(--color-surface-3)] transition-colors"
            aria-label="Close"
          >
            <Icon name="x" size={17} />
          </button>
        </div>
        <div className="p-5">{children}</div>
        {footer && (
          <div className="flex items-center justify-end gap-2 px-5 py-3.5 bg-[var(--color-surface-2)] border-t border-[var(--color-line)]">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}

/* =============================================================
   DROP ZONE
   ============================================================= */

export function DropZone({
  onFile,
  accept,
  title,
  hint,
  icon = "upload",
  compact,
  disabled,
}: {
  onFile: (f: File) => void;
  accept?: string;
  title: string;
  hint?: string;
  icon?: IconName;
  compact?: boolean;
  disabled?: boolean;
}) {
  const [over, setOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        if (disabled) return;
        const f = e.dataTransfer.files?.[0];
        if (f) onFile(f);
      }}
      onClick={() => !disabled && inputRef.current?.click()}
      className={cn(
        "relative rounded-[var(--radius-lg)] border-2 border-dashed cursor-pointer",
        "transition-all duration-200 group",
        compact ? "p-5" : "p-10",
        over
          ? "border-[var(--tool-accent)] scale-[1.01]"
          : "border-[var(--color-line-2)] hover:border-[var(--tool-tint-2)]",
        disabled && "opacity-50 pointer-events-none",
      )}
      style={{
        background: over ? "var(--tool-tint)" : "var(--color-surface-2)",
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) onFile(f);
          e.target.value = "";
        }}
      />
      <div className="flex flex-col items-center text-center">
        <div
          className="grid place-items-center rounded-[var(--radius-lg)] mb-3 transition-transform duration-200"
          style={{
            width: compact ? 40 : 56,
            height: compact ? 40 : 56,
            background: "var(--tool-tint)",
            border: "1px solid var(--tool-tint-2)",
            color: "var(--tool-accent)",
          }}
        >
          <Icon name={icon} size={compact ? 19 : 26} strokeWidth={1.5} />
        </div>
        <p className="text-[14px] font-bold">{title}</p>
        {hint && (
          <p className="mt-1 text-[12.5px] text-[var(--color-ink-4)] max-w-sm">{hint}</p>
        )}
      </div>
    </div>
  );
}

/* =============================================================
   MISC
   ============================================================= */

/* =============================================================
   KEY CAP

   Four different key-cap heights had crept in across the switcher, the
   palette and the landing page, and none of them were baseline-aligned with
   the text beside them. One primitive, one size.
   ============================================================= */

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd
      className="shrink-0 h-5 min-w-5 px-1 inline-flex items-center justify-center rounded-[4px] mono text-[10.5px] font-medium leading-none"
      style={{
        background: "var(--color-surface-2)",
        border: "1px solid var(--color-line-2)",
        color: "var(--color-ink-4)",
      }}
    >
      {children}
    </kbd>
  );
}

/* =============================================================
   DIVIDER
   ============================================================= */

export function Divider({ label }: { label?: string }) {
  if (!label) return <div className="h-px bg-[var(--color-line)] my-4" />;
  return (
    <div className="flex items-center gap-3 my-4">
      <div className="flex-1 h-px bg-[var(--color-line)]" />
      <span className="text-[11px] font-bold tracking-[0.08em] uppercase text-[var(--color-ink-4)]">
        {label}
      </span>
      <div className="flex-1 h-px bg-[var(--color-line)]" />
    </div>
  );
}

export function SectionTitle({
  children,
  sub,
  right,
  className,
}: {
  children: ReactNode;
  sub?: ReactNode;
  right?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-end justify-between gap-4 mb-4", className)}>
      <div className="min-w-0">
        <h2 className="text-[19px] font-extrabold tracking-[-0.01em]">{children}</h2>
        {sub && <p className="text-[13.5px] text-[var(--color-ink-4)] mt-1">{sub}</p>}
      </div>
      {right && <div className="shrink-0">{right}</div>}
    </div>
  );
}

export function Callout({
  tone = "info",
  title,
  children,
  icon,
  className,
}: {
  tone?: "info" | "ok" | "warn" | "bad" | "accent";
  title?: string;
  children: ReactNode;
  icon?: IconName;
  className?: string;
}) {
  const tones: Record<string, { fg: string; bg: string; bd: string; dflt: IconName }> = {
    info: {
      fg: "var(--color-info)",
      bg: "rgb(56 189 248 / 0.08)",
      bd: "rgb(56 189 248 / 0.25)",
      dflt: "info",
    },
    ok: {
      fg: "var(--color-ok)",
      bg: "rgb(52 211 153 / 0.08)",
      bd: "rgb(52 211 153 / 0.25)",
      dflt: "check",
    },
    warn: {
      fg: "var(--color-warn)",
      bg: "rgb(251 191 36 / 0.08)",
      bd: "rgb(251 191 36 / 0.28)",
      dflt: "alert-triangle",
    },
    bad: {
      fg: "var(--color-bad)",
      bg: "rgb(248 113 113 / 0.08)",
      bd: "rgb(248 113 113 / 0.28)",
      dflt: "alert-octagon",
    },
    accent: {
      fg: "var(--tool-accent)",
      bg: "var(--tool-tint)",
      bd: "var(--tool-tint-2)",
      dflt: "sparkles",
    },
  };
  const t = tones[tone];
  return (
    <div
      className={cn("flex gap-3 p-3.5 rounded-[var(--radius-md)] border", className)}
      style={{ background: t.bg, borderColor: t.bd }}
    >
      <span style={{ color: t.fg }} className="mt-px shrink-0">
        <Icon name={icon ?? t.dflt} size={15} />
      </span>
      <div className="min-w-0 text-[13px] leading-relaxed">
        {title && (
          <div className="font-bold mb-0.5" style={{ color: t.fg }}>
            {title}
          </div>
        )}
        <div className="text-[var(--color-ink-2)]">{children}</div>
      </div>
    </div>
  );
}

export function Skeleton({ h = 14, w = "100%", className }: { h?: number; w?: string | number; className?: string }) {
  return (
    <div
      className={cn("rounded-[var(--radius-sm)]", className)}
      style={{
        height: h,
        width: w,
        background:
          "linear-gradient(90deg, var(--color-surface-2) 25%, var(--color-surface-3) 50%, var(--color-surface-2) 75%)",
        backgroundSize: "200% 100%",
        animation: "sc-shimmer 1.4s linear infinite",
      }}
    />
  );
}
