export type ToolId = "home" | "malware" | "ioc" | "events" | "phishing" | "ruleforge";

export interface ToolMeta {
  id: ToolId;
  /** Product name shown in the switcher. Short, so the toggle stays narrow. */
  name: string;
  /** One line, shown under the tool card on the landing page. */
  tagline: string;
  /** Longer prose, for the switcher and the tour. */
  blurb: string;
  /** Route within the shell. `home` is the marketing page. */
  path: string;
  /** Accent hue, mirrored from tokens.css. Kept here so cards can tint
   *  before the html attribute has been applied. */
  accent: string;
  /** Real numbers, read from each tool's backend. Not marketing filler. */
  stats: { label: string; value: string }[];
  /** The concrete jobs this tool does. Full sentences, for prose. */
  capabilities: string[];
  /** Two-to-four-word labels for chips. `capabilities` are sentences and a
   *  sentence inside a chip overflows the card that holds it. */
  tags: string[];
  /** Keyboard shortcut digit, 1-5 in landing order. */
  hotkey: string;
}

export const TOOLS: ToolMeta[] = [
  {
    id: "malware",
    name: "Malware Analyzer",
    tagline: "Binary threat intelligence",
    blurb:
      "Drop an executable, DLL, PDF or archive. Static PE dissection, 800+ YARA rules, IOC extraction and cloud threat feeds in a single pass.",
    path: "/t/malware",
    accent: "#818cf8",
    stats: [
      { label: "Analysis layers", value: "6" },
      { label: "YARA rules", value: "812+" },
      { label: "Intel feeds", value: "4" },
    ],
    capabilities: [
      "PE section entropy and overlay detection",
      "YARA matching across community rulesets",
      "VirusTotal, Hybrid Analysis, Triage, FileScan",
      "URL, IP, domain, registry and base64 IOC extraction",
      "MITRE ATT&CK technique auto-mapping",
      "imphash and simhash variant correlation",
    ],
    tags: ["YARA 812+", "PE", "VT", "HA", "MITRE"],
    hotkey: "1",
  },
  {
    id: "ioc",
    name: "IOC Lookup",
    tagline: "40+ source enrichment",
    blurb:
      "Resolve any indicator against fourty sources at once and watch consensus form as each one answers.",
    path: "/t/ioc",
    accent: "#facc15",
    stats: [
      { label: "Providers", value: "40+" },
      { label: "Indicator types", value: "12" },
      { label: "Exports", value: "STIX/MISP" },
    ],
    capabilities: [
      "IPv4, IPv6, domain, URL and CIDR resolution",
      "File hashes across MD5, SHA-1, SHA-256, SSDeep",
      "Email, username and phone intelligence",
      "Bitcoin and Ethereum wallet tracing",
      "CVE lookup with NVD and cve.org corroboration",
      "STIX 2.1, MISP, SIEM and CSV export",
    ],
    tags: ["40+ sources", "STIX", "MISP", "CVE", "Wallet"],
    hotkey: "2",
  },
  {
    id: "events",
    name: "Event Analyzer",
    tagline: "Windows event log forensics",
    blurb:
      "Ingest EVTX exports, index every event with full-text search, then pivot into the IOCs and Sigma rules hiding in them.",
    path: "/t/events",
    accent: "#38bdf8",
    stats: [
      { label: "Search", value: "FTS5" },
      { label: "Sigma rules", value: "Bundled" },
      { label: "MITRE map", value: "Yes" },
    ],
    capabilities: [
      "Bulk EVTX ingestion with a progress pipeline",
      "Full-text search across every rendered field",
      "Channel, provider, host and user faceting",
      "Timeline histogram and burst detection",
      "Automatic IOC extraction from event text",
      "Sigma rule matching with per-rule hit counts",
    ],
    tags: ["FTS5", "EVTX", "Sigma", "MITRE", "IOC"],
    hotkey: "3",
  },
  {
    id: "phishing",
    name: "Phishing Detector",
    tagline: "Email threat triage",
    blurb:
      "Upload a raw .eml and get header authentication, HTML rendering, attachment artefacts and a scored verdict with the reasoning shown.",
    path: "/t/phishing",
    accent: "#fb7185",
    stats: [
      { label: "Auth checks", value: "SPF/DKIM/DMARC" },
      { label: "Renderers", value: "HTML + QR" },
      { label: "Verdict tiers", value: "4" },
    ],
    capabilities: [
      "SPF, DKIM and DMARC alignment checking",
      "Reply-To and Return-Path spoof detection",
      "Header chain and authentication results table",
      "Safe HTML rendering and QR code decoding",
      "Link extraction with redirect resolution",
      "Attachment and artefact inventory",
    ],
    tags: ["SPF", "DKIM", "DMARC", "QR", "VT"],
    hotkey: "4",
  },
  {
    id: "ruleforge",
    name: "RuleForge",
    tagline: "SIEM detection engineering",
    blurb:
      "Author, explain and debug detection rules across eight SIEM dialects. It tells you what a rule actually means, not just what it parses as.",
    path: "/t/ruleforge",
    accent: "#2dd4bf",
    stats: [
      { label: "Dialects", value: "8" },
      { label: "Jobs", value: "5" },
      { label: "Tests", value: "468" },
    ],
    capabilities: [
      "SPL, KQL, AQL, EQL, CQL, FQL, Wazuh, YARA-L",
      "Author a rule in one dialect, render it to another",
      "Plain-language explanation of every node",
      "Tuning suggestions from real sample events",
      "Generate logs from a rule, then rebuild it",
      "Append-only history, no rewrite path",
    ],
    tags: ["SPL", "KQL", "AQL", "EQL", "Wazuh"],
    hotkey: "5",
  },
];

export const TOOL_BY_ID: Record<ToolId, ToolMeta> = Object.fromEntries(
  TOOLS.map((t) => [t.id, t]),
) as Record<ToolId, ToolMeta>;

/** Navigation model.

 *  Each tool has exactly TWO main tabs, which sit in the centre of the
 *  header: the overview surface, and the working surface. Everything else a
 *  tool has is a SECTION of that working surface, and those render as chips
 *  on the right of the header.

 *  This is a real distinction, not a styling preference. The main tabs answer
 *  "which surface am I on"; the chips answer "which part of it". A tool with
 *  six peers competing for the centre reads as six unrelated pages. A tool
 *  with two peers and four refinements reads as one tool with depth.
 *
 *  `SUB_TABS` is deliberately not derived from the main tabs: for some tools a
 *  chip IS a peer of the second main tab rather than a section of it, and
 *  pretending otherwise would make the two rows lie about the structure. */


/** Landing order. The switcher renders in exactly this sequence, and the
 *  number keys 1-5 map to these positions. */
export const LANDING_ORDER: ToolId[] = [
  "malware",
  "ioc",
  "events",
  "phishing",
  "ruleforge",
];

export type Verdict = "clean" | "low" | "suspicious" | "malicious" | "unknown";

export const VERDICT_STYLE: Record<
  Verdict,
  { label: string; color: string; bg: string; border: string }
> = {
  clean: { label: "CLEAN", color: "var(--color-ok)", bg: "rgb(52 211 153 / 0.12)", border: "rgb(52 211 153 / 0.3)" },
  low: { label: "LOW", color: "var(--color-ok)", bg: "rgb(52 211 153 / 0.12)", border: "rgb(52 211 153 / 0.3)" },
  suspicious: {
    label: "SUSPICIOUS",
    color: "var(--color-warn)",
    bg: "rgb(251 191 36 / 0.12)",
    border: "rgb(251 191 36 / 0.3)",
  },
  malicious: {
    label: "MALICIOUS",
    color: "var(--color-bad)",
    bg: "rgb(248 113 113 / 0.12)",
    border: "rgb(248 113 113 / 0.32)",
  },
  unknown: {
    label: "UNKNOWN",
    color: "var(--color-ink-3)",
    bg: "rgb(139 149 184 / 0.12)",
    border: "rgb(139 149 184 / 0.25)",
  },
};

/** Maps a 0-100 risk score onto the four tiers every tool shares. */
export function verdictForScore(score: number): Verdict {
  if (score >= 70) return "malicious";
  if (score >= 45) return "suspicious";
  if (score >= 20) return "low";
  return "clean";
}

/* =============================================================
   NAVIGATION MODEL — FAITHFUL COPIES

   These labels and this order are the ORIGINAL tools' own navigation, read
   out of their source rather than invented:

     Malware Analyzer   ui/index.html:281-300      Dashboard, Static Analysis,
                                                    Threat Intel, Behavioral, IOCs
     IOC Lookup         ui/src/App.tsx:26-32      Home, Lookup, Investigations,
                                                    Batch, History
     Event Analyzer     templates/index.html:25-51 primary: overview,
                                                    investigation
                                                    sub: Events, IOCs, Sigma, Notes
     Phishing Detector  templates/index.html:458 primary: Overview, Analysis
                          templates/index.html:602 sub: Dashboard, Sender & Auth,
                                                    Headers, Artifacts
     RuleForge          templates/workshop.html:6 Author, Tune, Debug, Understand

   Nothing here is invented and nothing is renamed. An earlier pass shortened
   "Static Analysis" to "Static", renamed "Threat Intel" to "Intel", and gave
   Event Analyzer a Timeline, a Channels tab and a Bookmarks tab that the tool
   never had, while dropping the Notes tab it did have. That is the change that
   made five tools stop feeling like the tools they came from.

   MAIN_TABS is the two-level split the shell header needs. SUB_TABS is each
   tool's own tab list, verbatim, as sections of the working surface.
   ============================================================= */

export interface NavTab {
  id: string;
  label: string;
  icon?: string;
  /** Which main tab this chip belongs to. Required, so a chip click always
   *  knows which surface to reveal. */
  surface?: string;
}

export const MAIN_TABS: Record<ToolId, NavTab[]> = {
  home: [{ id: "overview", label: "Home", icon: "home" }],

  malware: [
    { id: "overview", label: "Overview", icon: "grid" },
    { id: "investigation", label: "Investigation", icon: "search" },
  ],

  ioc: [
    { id: "overview", label: "Overview", icon: "grid" },
    { id: "lookup", label: "Lookup", icon: "search" },
  ],

  events: [
    { id: "overview", label: "Overview", icon: "grid" },
    { id: "investigation", label: "Investigation", icon: "search" },
  ],

  phishing: [
    { id: "overview", label: "Overview", icon: "grid" },
    { id: "analysis", label: "Analysis", icon: "search" },
  ],

  ruleforge: [
    { id: "overview", label: "Overview", icon: "grid" },
    { id: "workshop", label: "Workshop", icon: "terminal" },
  ],
};

export const SUB_TABS: Record<ToolId, NavTab[]> = {
  home: [],

  malware: [
    { id: "overview", label: "Dashboard", icon: "grid", surface: "investigation" },
    { id: "static", label: "Static Analysis", icon: "file-code", surface: "investigation" },
    { id: "intel", label: "Threat Intel", icon: "globe", surface: "investigation" },
    { id: "behavioral", label: "Behavioral", icon: "activity", surface: "investigation" },
    { id: "iocs", label: "IOCs", icon: "target", surface: "investigation" },
  ],

  ioc: [
    { id: "lookup", label: "Lookup", icon: "search", surface: "lookup" },
    { id: "investigations", label: "Investigations", icon: "layers", surface: "lookup" },
    { id: "batch", label: "Batch", icon: "grid", surface: "lookup" },
    { id: "history", label: "History", icon: "clock", surface: "lookup" },
  ],

  events: [
    { id: "events", label: "Events", icon: "list", surface: "investigation" },
    { id: "iocs", label: "IOCs", icon: "target", surface: "investigation" },
    { id: "sigma", label: "Sigma", icon: "check", surface: "investigation" },
    { id: "notes", label: "Notes", icon: "bookmark", surface: "investigation" },
  ],

/* From templates/index.html:602 onward. The fourth tab is "Preview Mail",
     not "Headers" — Headers is a panel inside the analysis, not a tab of its
     own, and reading the DOM at runtime settled it: the buttons are
     Dashboard, Sender & Auth, Artifacts, Preview Mail. */
  phishing: [
    { id: "dashboard", label: "Dashboard", icon: "grid", surface: "analysis" },
    { id: "sender-auth", label: "Sender & Auth", icon: "lock", surface: "analysis" },
    { id: "artifacts", label: "Artifacts", icon: "file", surface: "analysis" },
    { id: "preview", label: "Preview Mail", icon: "eye", surface: "analysis" },
  ],

  ruleforge: [
    { id: "author", label: "Author", icon: "sparkles", surface: "workshop" },
    { id: "tune", label: "Tune", icon: "activity", surface: "workshop" },
    { id: "debug", label: "Debug", icon: "git-branch", surface: "workshop" },
    { id: "understand", label: "Understand", icon: "eye", surface: "workshop" },
    { id: "history", label: "History", icon: "clock", surface: "workshop" },
    { id: "docs", label: "Dialects", icon: "file-code", surface: "workshop" },
  ],
};

/** Every navigable id a tool owns, main tabs first. Used to seed and reset
 *  the shell's nav state so a tool can never be left pointing at a section it
 *  does not have. */
export function allTabIds(tool: ToolId): string[] {
  return [...MAIN_TABS[tool], ...SUB_TABS[tool]].map((t) => t.id);
}
