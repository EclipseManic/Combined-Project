import type { ReactNode, CSSProperties } from "react";

export type IconName =
  | "shield"
  | "bug"
  | "target"
  | "search"
  | "mail"
  | "terminal"
  | "home"
  | "chevron-down"
  | "chevron-right"
  | "arrow-right"
  | "arrow-up"
  | "arrow-down"
  | "check"
  | "x"
  | "alert-triangle"
  | "alert-octagon"
  | "info"
  | "copy"
  | "download"
  | "upload"
  | "trash"
  | "refresh"
  | "sun"
  | "moon"
  | "command"
  | "help"
  | "file"
  | "file-code"
  | "hash"
  | "link"
  | "globe"
  | "clock"
  | "play"
  | "zap"
  | "database"
  | "filter"
  | "bookmark"
  | "external"
  | "lock"
  | "cpu"
  | "layers"
  | "sparkles"
  | "user"
  | "server"
  | "git-branch"
  | "eye"
  | "plus"
  | "settings"
  | "grid"
  | "activity"
  | "list"
  | "save";

const PATHS: Record<IconName, ReactNode> = {
  shield: <path d="M12 2l8 3.5v6c0 5-3.4 9.3-8 10.5-4.6-1.2-8-5.5-8-10.5v-6L12 2z" />,
  bug: (
    <>
      <path d="M8 6a4 4 0 018 0M6 10h12M6 14h12" />
      <path d="M9 6V4M15 6V4M9 18v2M15 18v2" />
      <circle cx="12" cy="12" r="5" />
    </>
  ),
  target: (
    <>
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="4.5" />
      <circle cx="12" cy="12" r="1" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="M16.5 16.5L21 21" />
    </>
  ),
  mail: (
    <>
      <rect x="2.5" y="5" width="19" height="14" rx="2.5" />
      <path d="M3 7l9 6 9-6" />
    </>
  ),
  terminal: (
    <>
      <rect x="2.5" y="4" width="19" height="16" rx="2.5" />
      <path d="M7 9l3 3-3 3M13 15h4" />
    </>
  ),
  home: <path d="M4 11l8-7 8 7M6 10v9h12v-9" />,
  "chevron-down": <path d="M6 9l6 6 6-6" />,
  "chevron-right": <path d="M9 6l6 6-6 6" />,
  "arrow-right": <path d="M5 12h14M13 6l6 6-6 6" />,
  "arrow-up": <path d="M12 19V5M6 11l6-6 6 6" />,
  "arrow-down": <path d="M12 5v14M6 13l6 6 6-6" />,
  check: <path d="M4 12.5l5 5L20 6.5" />,
  x: <path d="M6 6l12 12M18 6L6 18" />,
  "alert-triangle": (
    <>
      <path d="M12 3.5L22 20H2L12 3.5z" />
      <path d="M12 10v4M12 17.5v.5" />
    </>
  ),
  "alert-octagon": (
    <>
      <path d="M8 2.5h8L21.5 8v8L16 21.5H8L2.5 16V8L8 2.5z" />
      <path d="M12 8v4M12 16v.5" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5M12 8v.5" />
    </>
  ),
  copy: (
    <>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15H4.5A1.5 1.5 0 013 13.5v-9A1.5 1.5 0 014.5 3h9A1.5 1.5 0 0115 4.5V5" />
    </>
  ),
  download: <path d="M12 3v12M7 11l5 5 5-5M4 20h16" />,
  upload: <path d="M12 20V8M7 12l5-5 5 5M4 3.5h16" />,
  trash: <path d="M4 7h16M9 7V4.5h6V7M6 7l1 13h10l1-13M10 11v6M14 11v6" />,
  refresh: <path d="M20 11a8 8 0 10-2.3 6.3M20 5v6h-6" />,
  sun: (
    <>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M5 5l1.8 1.8M17.2 17.2L19 19M19 5l-1.8 1.8M6.8 17.2L5 19" />
    </>
  ),
  moon: <path d="M20 14.5A8.5 8.5 0 019.5 4a8.5 8.5 0 1010.5 10.5z" />,
  command: <path d="M6 3.5a2.5 2.5 0 110 5h12a2.5 2.5 0 110-5 2.5 2.5 0 100 5v10a2.5 2.5 0 100 5H6a2.5 2.5 0 110-5h12a2.5 2.5 0 110 5 2.5 2.5 0 100-5V8.5a2.5 2.5 0 100-5z" />,
  help: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M9.5 9.5a2.5 2.5 0 115 0c0 1.5-2.5 2-2.5 3.5M12 16.5v.5" />
    </>
  ),
  file: <path d="M6 2.5h8l5 5v14H6v-19zM14 2.5v5h5" />,
  "file-code": <path d="M6 2.5h8l5 5v14H6v-19zM14 2.5v5h5M10 12l-2 2 2 2M14 12l2 2-2 2" />,
  hash: <path d="M9 3L7 21M17 3l-2 18M4 8.5h16M3 15.5h16" />,
  link: <path d="M10 13.5a4 4 0 005.7 0l3-3a4 4 0 10-5.7-5.7L11.5 6.3M14 10.5a4 4 0 00-5.7 0l-3 3a4 4 0 105.7 5.7l1.5-1.5" />,
  globe: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3c2.5 2.6 3.8 5.7 3.8 9S14.5 18.4 12 21c-2.5-2.6-3.8-5.7-3.8-9S9.5 5.6 12 3z" />
    </>
  ),
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5.5l3.5 2" />
    </>
  ),
  play: <path d="M7 4.5l12 7.5-12 7.5v-15z" />,
  zap: <path d="M13 2L4 14h6l-1 8 9-12h-6l1-8z" />,
  database: (
    <>
      <ellipse cx="12" cy="5.5" rx="8" ry="3" />
      <path d="M4 5.5v13c0 1.7 3.6 3 8 3s8-1.3 8-3v-13M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" />
    </>
  ),
  filter: <path d="M3 5h18l-7 8v6l-4 2v-8L3 5z" />,
  bookmark: <path d="M6 3.5h12v18l-6-4.5-6 4.5v-18z" />,
  external: <path d="M14 4h6v6M20 4l-9 9M18 13v7H4V6h7" />,
  lock: (
    <>
      <rect x="4.5" y="10" width="15" height="11" rx="2.5" />
      <path d="M8 10V7a4 4 0 018 0v3" />
    </>
  ),
  cpu: (
    <>
      <rect x="6" y="6" width="12" height="12" rx="2" />
      <rect x="9.5" y="9.5" width="5" height="5" rx="1" />
      <path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4" />
    </>
  ),
  layers: <path d="M12 3l9 5-9 5-9-5 9-5zM3 13l9 5 9-5M3 17l9 5 9-5" />,
  sparkles: <path d="M12 3l1.8 4.7L18.5 9.5 13.8 11.3 12 16l-1.8-4.7L5.5 9.5l4.7-1.8L12 3zM18 15l.9 2.3 2.3.9-2.3.9-.9 2.3-.9-2.3-2.3-.9 2.3-.9L18 15z" />,
  user: (
    <>
      <circle cx="12" cy="8" r="4" />
      <path d="M4.5 21a7.5 7.5 0 0115 0" />
    </>
  ),
  server: (
    <>
      <rect x="3" y="4" width="18" height="7" rx="2" />
      <rect x="3" y="13" width="18" height="7" rx="2" />
      <path d="M7 7.5v.5M7 16.5v.5" />
    </>
  ),
  "git-branch": (
    <>
      <circle cx="6" cy="5" r="2.5" />
      <circle cx="6" cy="19" r="2.5" />
      <circle cx="18" cy="12" r="2.5" />
      <path d="M6 7.5v9M8.5 5h4A3.5 3.5 0 0116 8.5v1" />
    </>
  ),
  eye: (
    <>
      <path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  plus: <path d="M12 5v14M5 12h14" />,
  settings: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.2 5.2l2.1 2.1M16.7 16.7l2.1 2.1M18.8 5.2l-2.1 2.1M7.3 16.7l-2.1 2.1" />
    </>
  ),
  grid: (
    <>
      <rect x="3" y="3" width="8" height="8" rx="2" />
      <rect x="13" y="3" width="8" height="8" rx="2" />
      <rect x="3" y="13" width="8" height="8" rx="2" />
      <rect x="13" y="13" width="8" height="8" rx="2" />
    </>
  ),
  list: (
    <>
      <path d="M8 6h13M8 12h13M8 18h13" />
      <circle cx="4" cy="6" r="1" />
      <circle cx="4" cy="12" r="1" />
      <circle cx="4" cy="18" r="1" />
    </>
  ),
  save: <path d="M5 3.5h11l3 3v14H5v-17zM8.5 3.5v6h7v-6M8 20.5v-6h8v6" />,
  activity: <path d="M2 12h4l3 8 5-16 3 8h5" />,
};

export function Icon({
  name,
  size = 16,
  className,
  strokeWidth = 1.7,
  style,
}: {
  name: IconName;
  size?: number;
  className?: string;
  strokeWidth?: number;
  style?: CSSProperties;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
      style={{ flexShrink: 0, display: "block", ...style }}
    >
      {PATHS[name]}
    </svg>
  );
}
