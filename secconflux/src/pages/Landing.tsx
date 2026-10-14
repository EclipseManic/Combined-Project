
// ============================================================================
// 7. LANDING PAGE (Section 6) & FIRST-RUN 7-SLIDE TOUR MODAL
// ============================================================================
const TOUR_SLIDES = [
  {
    step: 1,
    title: 'Welcome to SecConflux 2.0',
    badge: 'UNIFIED SECOPS PLATFORM',
    body: 'SecConflux converges five standalone security engines—Malware Analyzer, IOC Lookup, Event Analyzer, Phishing Detector, and RuleForge—into a single, dark-first analyst workspace with zero tab switching.'
  },
  {
    step: 2,
    title: 'The Unified Command Center Dashboard',
    badge: 'MORNING BRIEFING (#/dashboard)',
    body: 'Start your shift in the Command Center: inspect 7-day threat posture sparklines across all 5 engines, triage prioritized Critical Findings, correlate overlapping IOCs across tools, and export unified activity logs.'
  },
  {
    step: 3,
    title: 'Two-Tier Navigation Architecture',
    badge: 'ROW 1 MAIN TABS · ROW 2 SUB-TABS',
    body: 'Every tool shares a predictable 2-tab primary bar: Tab 1 (Overview) and Tab 2 (Working Surface: Investigation / Lookup / Analysis / Workshop). When on Tab 2, contextual sub-tab chips appear in Row 2.'
  },
  {
    step: 4,
    title: 'Cross-Tool Pivoting & Return Breadcrumbs',
    badge: 'CONVERGE & CORRELATE',
    body: 'Click any indicator (IP, domain, SHA-256 hash, email, or Sigma rule) to pivot directly into another tool with pre-populated queries—complete with a one-click breadcrumb banner to return to your prior investigation.'
  },
  {
    step: 5,
    title: 'Shared Cross-Tool IOC Clipboard',
    badge: 'FLOATING CLIPBOARD (BOTTOM RIGHT)',
    body: 'Pin indicators from any engine into your session-persistent IOC Clipboard (up to 50 items, FIFO). Send all pinned indicators to IOC Batch Lookup or hunt across Windows EVTX logs in one click.'
  },
  {
    step: 6,
    title: 'Global Command Palette & Power Hotkeys',
    badge: 'CTRL+K / CMD+K',
    body: 'Press Ctrl+K (or Cmd+K) from anywhere to launch the Command Palette. Use keys 0–5 when no input is focused to jump directly between Home and the 5 engines, or press ? to reopen this guide.'
  },
  {
    step: 7,
    title: 'Ready to Investigate',
    badge: 'GET STARTED',
    body: 'All five engines are pre-loaded with correlated intrusion telemetry (Cobalt Strike C2 198.51.100.45 & invoice_q3.exe) and can be switched between Fixture Demo Mode and Live Backend Proxy Mode in Settings.'
  }
];

export const FirstRunTourModal: React.FC<{
  open: boolean;
  onClose: () => void;
  onNavigate: (page: PageRouteId, mainTab?: string, subTab?: string) => void;
}> = ({ open, onClose, onNavigate }) => {
  const [slideIdx, setSlideIdx] = useState(0);
  if (!open) return null;
  const slide = TOUR_SLIDES[slideIdx];

  return (
    <Modal
      open={open}
      title={`Platform Tour (${slide.step} of ${TOUR_SLIDES.length})`}
      subtitle="SecConflux 2.0 Interactive Analyst Walkthrough"
      onClose={onClose}
      maxWidth="max-w-lg"
    >
      <div className="space-y-4">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-[11px] font-semibold sc-accent-bg text-white">
          <span>Slide {slide.step}/7</span>
          <span>·</span>
          <span>{slide.badge}</span>
        </div>
        <h4 className="text-lg font-bold">{slide.title}</h4>
        <p className="text-sm leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
          {slide.body}
        </p>

        <div className="flex items-center gap-1.5 pt-2">
          {TOUR_SLIDES.map((_, i) => (
            <button
              key={i}
              type="button"
              onClick={() => setSlideIdx(i)}
              className="h-1.5 rounded-full transition-all cursor-pointer"
              style={{
                width: i === slideIdx ? '28px' : '10px',
                backgroundColor: i === slideIdx ? 'var(--accent-from)' : 'var(--color-border)'
              }}
              aria-label={`Go to slide ${i + 1}`}
            />
          ))}
        </div>

        <div className="flex items-center justify-between pt-4 border-t" style={{ borderColor: 'var(--color-border)' }}>
          <button
            type="button"
            onClick={onClose}
            className="text-xs font-medium hover:underline cursor-pointer"
            style={{ color: 'var(--color-text-secondary)' }}
          >
            Skip Tour
          </button>
          <div className="flex items-center gap-2">
            {slideIdx > 0 && (
              <button
                type="button"
                onClick={() => setSlideIdx(slideIdx - 1)}
                className="px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer"
                style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              >
                ← Back
              </button>
            )}
            {slideIdx < TOUR_SLIDES.length - 1 ? (
              <button
                type="button"
                onClick={() => setSlideIdx(slideIdx + 1)}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer"
              >
                Next →
              </button>
            ) : (
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onNavigate('dashboard');
                }}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer"
              >
                Open Command Center →
              </button>
            )}
          </div>
        </div>
      </div>
    </Modal>
  );
};

export const LandingPage: React.FC<{
  activityFeed: ActivityItem[];
  onNavigate: (page: PageRouteId, mainTab?: string, subTab?: string) => void;
  onOpenTour: () => void;
  onQuickIocLookup: (ioc: string) => void;
  onTriggerUploadModal: (tool: ToolId) => void;
}> = ({ activityFeed, onNavigate, onOpenTour, onQuickIocLookup, onTriggerUploadModal }) => {
  const [selectedDemoStep, setSelectedDemoStep] = useState<number>(0);
  const [quickIocInput, setQuickIocInput] = useState('198.51.100.45');

  const evidenceSteps = [
    {
      step: '1. Malware Analyzer',
      tool: 'malware' as ToolId,
      mainTab: 'investigation',
      subTab: 'iocs',
      headline: 'Flagged in invoice_q3.exe Scan',
      badge: 'CRITICAL 87/100',
      detail: 'Extracted from PE `.rsrc` Cobalt Strike configuration & sandbox `rundll32.exe` HTTPS beacon callback to `https://198.51.100.45:443/api/v2/telemetry/checkin`.'
    },
    {
      step: '2. IOC Lookup',
      tool: 'ioc' as ToolId,
      mainTab: 'lookup',
      subTab: 'lookup',
      headline: 'Enriched Across 28/33 Intel Sources',
      badge: 'MALICIOUS 92/100',
      detail: '19/28 sources voted Malicious. AbuseIPDB 99% confidence (318 reports), Shodan port 50050 + Cobalt Strike JA3S fingerprint, and 14 Hudson Rock LummaC2 logs.'
    },
    {
      step: '3. Event Analyzer',
      tool: 'events' as ToolId,
      mainTab: 'investigation',
      subTab: 'events',
      headline: 'Found in 47 Windows Sysmon Events',
      badge: '47 EVTX HITS',
      detail: 'Matched in `WKS-FINANCE04-Sysmon.evtx` (Event ID 3 NetworkConnect from `rundll32.exe` PID 6104) and correlated with PowerShell Event ID 4104 stage-2 cradle.'
    },
    {
      step: '4. Phishing Detector',
      tool: 'phishing' as ToolId,
      mainTab: 'analysis',
      subTab: 'dashboard',
      headline: 'Originating Hop #1 MTA in Spearphish',
      badge: 'UNSAFE 9.2/10',
      detail: 'Identified in `X-Originating-IP` and Received Hop #1 (`edge-gw45.evil-login-portal.com`) of the weaponized wire transfer email delivering `Invoice_Q3_Remittance.zip`.'
    },
    {
      step: '5. RuleForge',
      tool: 'ruleforge' as ToolId,
      mainTab: 'workshop',
      subTab: 'author',
      headline: 'Compiled Cross-SIEM Detection Rule',
      badge: '8 SIEM DIALECTS',
      detail: 'Auto-synthesized into production Sentinel KQL, Splunk SPL, and Sigma rules (`v-104`) verified against live sample logs with Three-Valued Evaluation (`matched`).'
    }
  ];

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-12">
      {/* 6.1 Hero Section */}
      <section className="rounded-2xl p-8 md:p-10 sc-surface sc-hero-grid sc-glow relative overflow-hidden">
        <div className="max-w-3xl space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold border" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}>
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>5 Engines · 33+ Intel Sources · 8 SIEM Dialects · 812+ YARA Rules</span>
          </div>
          <h1 className="text-3xl sm:text-4xl md:text-5xl font-extrabold tracking-tight">
            <span className="sc-accent-text">Converge. Correlate. Contain.</span>
          </h1>
          <p className="text-base sm:text-lg leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
            Five security engines. One analyst workspace. Zero tab switching. Built for high-velocity SOC investigations across binaries, threat intelligence, Windows EVTX logs, phishing forensics, and multi-SIEM detection engineering.
          </p>
          <div className="flex flex-wrap items-center gap-3 pt-2">
            <button
              type="button"
              onClick={() => onNavigate('dashboard')}
              className="px-5 py-2.5 rounded-lg text-sm font-semibold text-white sc-accent-bg shadow-lg hover:opacity-95 transition cursor-pointer"
            >
              Open Command Center →
            </button>
            <button
              type="button"
              onClick={onOpenTour}
              className="px-4 py-2.5 rounded-lg text-sm font-semibold border hover:opacity-90 transition cursor-pointer"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            >
              Take a Tour (?)
            </button>
          </div>
        </div>
      </section>

      {/* 6.5 Quick Actions Bar */}
      <section className="rounded-xl p-4 sc-surface space-y-3">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Immediate Analyst Workflows
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => onTriggerUploadModal('malware')}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold border hover:opacity-90 flex items-center gap-1.5 cursor-pointer"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
            >
              <ToolIcon tool="malware" size={14} />
              <span>New Malware Scan</span>
            </button>
            <button
              type="button"
              onClick={() => onTriggerUploadModal('events')}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold border hover:opacity-90 flex items-center gap-1.5 cursor-pointer"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
            >
              <ToolIcon tool="events" size={14} />
              <span>Ingest EVTX</span>
            </button>
            <button
              type="button"
              onClick={() => onTriggerUploadModal('phishing')}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold border hover:opacity-90 flex items-center gap-1.5 cursor-pointer"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
            >
              <ToolIcon tool="phishing" size={14} />
              <span>Analyze Email (.eml)</span>
            </button>
            <button
              type="button"
              onClick={() => onNavigate('ruleforge', 'workshop', 'author')}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold border hover:opacity-90 flex items-center gap-1.5 cursor-pointer"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
            >
              <ToolIcon tool="ruleforge" size={14} />
              <span>Create Detection Rule</span>
            </button>
          </div>
        </div>
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 pt-1">
          <div className="relative flex-1">
            <input
              type="text"
              value={quickIocInput}
              onChange={(e) => setQuickIocInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && quickIocInput.trim()) onQuickIocLookup(quickIocInput.trim());
              }}
              placeholder="Quick IOC Lookup (e.g., 198.51.100.45, evil-login-portal.com, bc1qxy2..., +1-415-890-9912, password:Summer2026!)"
              className="w-full px-3.5 py-2 rounded-lg text-xs sc-mono border focus:outline-none"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
          </div>
          <button
            type="button"
            onClick={() => {
              if (quickIocInput.trim()) onQuickIocLookup(quickIocInput.trim());
            }}
            className="px-4 py-2 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer shrink-0"
          >
            🔍 Enrich Indicator →
          </button>
        </div>
      </section>

      {/* 6.2 Tool Cards Grid */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold">Integrated Security Engines</h2>
          <span className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
            Press <Kbd>1</Kbd> – <Kbd>5</Kbd> to jump directly to any engine
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-5 gap-4">
          {(Object.values(TOOLS_REGISTRY) as ToolDefinition[]).map((tool) => (
            <div
              key={tool.id}
              className="rounded-xl p-5 sc-surface sc-page-enter flex flex-col justify-between transition-transform duration-200 hover:scale-[1.02] sc-glow"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div
                    className="w-10 h-10 rounded-lg flex items-center justify-center text-white shadow"
                    style={{ background: `linear-gradient(135deg, ${tool.accentFrom}, ${tool.accentTo})` }}
                  >
                    <ToolIcon tool={tool.id} size={20} />
                  </div>
                  <Kbd>{tool.hotkey}</Kbd>
                </div>
                <div>
                  <h3 className="text-base font-bold">{tool.name}</h3>
                  <p className="text-xs mt-1 leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
                    {tool.description}
                  </p>
                </div>
                <ul className="space-y-1.5 pt-1 text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                  {tool.capabilities.map((cap, idx) => (
                    <li key={idx} className="flex items-start gap-1.5">
                      <span style={{ color: tool.accentFrom }}>▸</span>
                      <span>{cap}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="pt-4 mt-4 border-t flex items-center justify-between" style={{ borderColor: 'var(--color-border-subtle)' }}>
                <button
                  type="button"
                  onClick={() => onNavigate(tool.id, 'overview')}
                  className="text-xs font-medium hover:underline cursor-pointer"
                  style={{ color: 'var(--color-text-secondary)' }}
                >
                  Overview
                </button>
                <button
                  type="button"
                  onClick={() => onNavigate(tool.id, tool.mainTabs[1].id, tool.subTabs[0].id)}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white cursor-pointer"
                  style={{ background: `linear-gradient(135deg, ${tool.accentFrom}, ${tool.accentTo})` }}
                >
                  Launch {tool.mainTabs[1].label} →
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 6.3 Cross-Tool Evidence Demo */}
      <section className="rounded-xl p-6 sc-surface space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-base font-bold">Cross-Tool Evidence Convergence Demo</h2>
            <p className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
              Click any stage below to trace how a single adversary C2 IP (<code className="sc-mono font-semibold" style={{ color: 'var(--color-malicious)' }}>198.51.100.45</code>) correlates across all 5 SecConflux engines.
            </p>
          </div>
          <VerdictBadge verdict="malicious" label="ACTIVE INTRUSION CHAIN: 198.51.100.45" />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {evidenceSteps.map((st, idx) => {
            const active = selectedDemoStep === idx;
            return (
              <button
                key={idx}
                type="button"
                onClick={() => setSelectedDemoStep(idx)}
                className="text-left p-3.5 rounded-xl border transition cursor-pointer"
                style={{
                  backgroundColor: active ? 'var(--color-surface-raised)' : 'var(--color-canvas)',
                  borderColor: active ? 'var(--color-border-focus)' : 'var(--color-border)'
                }}
              >
                <div className="flex items-center justify-between text-[11px] font-semibold mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>
                  <span className="flex items-center gap-1.5">
                    <ToolIcon tool={st.tool} size={13} />
                    <span>{st.step}</span>
                  </span>
                </div>
                <div className="text-xs font-bold mb-1.5">{st.headline}</div>
                <span className="sc-mono text-[10px] px-2 py-0.5 rounded bg-red-500/15 text-red-400 font-semibold">
                  {st.badge}
                </span>
              </button>
            );
          })}
        </div>

        <div
          className="p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4"
          style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
        >
          <div className="space-y-1">
            <div className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--accent-from)' }}>
              {evidenceSteps[selectedDemoStep].step} — {evidenceSteps[selectedDemoStep].headline}
            </div>
            <p className="text-xs leading-relaxed" style={{ color: 'var(--color-text-primary)' }}>
              {evidenceSteps[selectedDemoStep].detail}
            </p>
          </div>
          <button
            type="button"
            onClick={() =>
              onNavigate(
                evidenceSteps[selectedDemoStep].tool,
                evidenceSteps[selectedDemoStep].mainTab,
                evidenceSteps[selectedDemoStep].subTab
              )
            }
            className="px-4 py-2 rounded-lg text-xs font-semibold text-white sc-accent-bg shrink-0 cursor-pointer"
          >
            Inspect in {TOOLS_REGISTRY[evidenceSteps[selectedDemoStep].tool].shortName} →
          </button>
        </div>
      </section>

      {/* 6.4 Recent Activity Feed */}
      <section className="rounded-xl p-6 sc-surface space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold">Recent SOC Activity Stream</h2>
            <p className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
              Consolidated telemetry across all 5 engines
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('dashboard')}
            className="text-xs font-semibold hover:underline cursor-pointer"
            style={{ color: 'var(--accent-from)' }}
          >
            View All Activity in Command Center →
          </button>
        </div>
        <div className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
          {activityFeed.slice(0, 5).map((item) => {
            const toolDef = TOOLS_REGISTRY[item.tool];
            return (
              <div key={item.id} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-start sm:items-center gap-3">
                  <div
                    className="w-7 h-7 rounded-lg flex items-center justify-center text-white shrink-0"
                    style={{ background: `linear-gradient(135deg, ${toolDef.accentFrom}, ${toolDef.accentTo})` }}
                  >
                    <ToolIcon tool={item.tool} size={14} />
                  </div>
                  <div>
                    <div className="text-xs font-semibold flex flex-wrap items-center gap-2">
                      <span>{toolDef.name}</span>
                      <span style={{ color: 'var(--color-text-tertiary)' }}>·</span>
                      <span style={{ color: 'var(--color-text-primary)' }}>{item.description}</span>
                    </div>
                    <div className="sc-mono text-[11px] mt-0.5" style={{ color: 'var(--color-text-tertiary)' }}>
                      {item.timestamp} · {item.actionType}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {item.verdict && <VerdictBadge verdict={item.verdict} label={item.scoreText} />}
                  <button
                    type="button"
                    onClick={() => onNavigate(item.tool, toolDef.mainTabs[1].id, item.targetSubTab || toolDef.subTabs[0].id)}
                    className="px-2.5 py-1 rounded text-xs font-medium border hover:opacity-80 cursor-pointer"
                    style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}
                  >
                    Open →
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
};

// ============================================================================
// 8. UNIFIED COMMAND CENTER DASHBOARD (Section 7 — #/dashboard)
// ============================================================================
export const CommandCenterDashboard: React.FC<{
  activityFeed: ActivityItem[];
  backendStatus: Record<ToolId, 'online' | 'offline' | 'unknown'>;
  onNavigate: (page: PageRouteId, mainTab?: string, subTab?: string) => void;
  onPivot: (req: Omit<PivotRequest, 'id' | 'timestamp'>) => void;
  onBatchEnrichAll: (iocs: string[]) => void;
  onAddToast: (t: Omit<ToastMessage, 'id'>) => void;
}> = ({ activityFeed, backendStatus, onNavigate, onPivot, onBatchEnrichAll, onAddToast }) => {
  const [selectedToolsFilter, setSelectedToolsFilter] = useState<Record<ToolId, boolean>>({
    malware: true,
    ioc: true,
    events: true,
    phishing: true,
    ruleforge: true
  });
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<string>('24h');

  const postureTiles = [
    {
      tool: 'malware' as ToolId,
      metric: '12 Scans',
      critBadge: '3 CRITICAL',
      verdict: 'malicious' as VerdictType,
      sparkline: [2, 3, 1, 5, 4, 8, 12],
      targetMain: 'investigation',
      targetSub: 'dashboard'
    },
    {
      tool: 'ioc' as ToolId,
      metric: '47 IOCs',
      critBadge: '5 MALICIOUS',
      verdict: 'malicious' as VerdictType,
      sparkline: [10, 14, 19, 22, 31, 39, 47],
      targetMain: 'lookup',
      targetSub: 'lookup'
    },
    {
      tool: 'events' as ToolId,
      metric: '3 Invest.',
      critBadge: '891 SIGMA',
      verdict: 'suspicious' as VerdictType,
      sparkline: [120, 240, 310, 490, 620, 740, 891],
      targetMain: 'investigation',
      targetSub: 'sigma'
    },
    {
      tool: 'phishing' as ToolId,
      metric: '8 Emails',
      critBadge: '2 UNSAFE',
      verdict: 'malicious' as VerdictType,
      sparkline: [1, 0, 2, 1, 3, 5, 8],
      targetMain: 'analysis',
      targetSub: 'dashboard'
    },
    {
      tool: 'ruleforge' as ToolId,
      metric: '24 Rules',
      critBadge: '2 REFUSALS',
      verdict: 'info' as VerdictType,
      sparkline: [4, 7, 11, 14, 18, 21, 24],
      targetMain: 'workshop',
      targetSub: 'author'
    }
  ];

  const criticalFindings = [
    {
      id: 'cf-1',
      severity: 'CRITICAL',
      verdict: 'malicious' as VerdictType,
      tool: 'malware' as ToolId,
      title: 'invoice_q3.exe — Cobalt Strike / AsyncRAT Loader (Score 87/100)',
      summary: 'Packed PE32+ executable with VirtualAllocEx/CreateRemoteThread injection into rundll32.exe and HTTPS beacon to 198.51.100.45:443.',
      timestamp: '11:42 UTC',
      mainTab: 'investigation',
      subTab: 'dashboard'
    },
    {
      id: 'cf-2',
      severity: 'CRITICAL',
      verdict: 'malicious' as VerdictType,
      tool: 'phishing' as ToolId,
      title: 'URGENT: Q3 Wire Transfer (#INV-99412) — Score 9.2/10 (UNSAFE)',
      summary: 'DMARC/DKIM failure, Reply-To divergence, Hop #1 originating from 198.51.100.45, and attached Invoice_Q3_Remittance.zip dropper.',
      timestamp: '11:38 UTC',
      mainTab: 'analysis',
      subTab: 'dashboard'
    },
    {
      id: 'cf-3',
      severity: 'CRITICAL',
      verdict: 'malicious' as VerdictType,
      tool: 'events' as ToolId,
      title: 'Sigma SIG-001 & SIG-003 Triggered on WKS-FINANCE04 (51 Matches)',
      summary: 'Sysmon Event ID 3 outbound connection from rundll32.exe to 198.51.100.45:443 + PowerShell Event ID 4104 encoded WebClient download.',
      timestamp: '11:50 UTC',
      mainTab: 'investigation',
      subTab: 'sigma'
    },
    {
      id: 'cf-4',
      severity: 'HIGH',
      verdict: 'malicious' as VerdictType,
      tool: 'ioc' as ToolId,
      title: '198.51.100.45 — Consensus Malicious Across 19/28 Intel Providers (92/100)',
      summary: 'Confirmed active Cobalt Strike C2 & LummaC2 exfiltration endpoint in AS209401 with self-signed TLS cert.',
      timestamp: '11:44 UTC',
      mainTab: 'lookup',
      subTab: 'lookup'
    },
    {
      id: 'cf-5',
      severity: 'MEDIUM',
      verdict: 'suspicious' as VerdictType,
      tool: 'ruleforge' as ToolId,
      title: 'Dialect Conversion Refusal: Multi-Event Sequence Join on Wazuh XML',
      summary: 'RuleForge safely refused approximate translation of temporal sequence stage to stateless Wazuh XML.',
      timestamp: '11:52 UTC',
      mainTab: 'workshop',
      subTab: 'author'
    }
  ];

  const correlatedIocs = [
    {
      ioc: '198.51.100.45',
      type: 'IPv4 C2',
      tools: ['malware', 'ioc', 'events', 'phishing', 'ruleforge'] as ToolId[],
      context: 'Malware C2 callback · IOC score 92/100 · 47 Sysmon EventID 3 hits · Phishing Hop #1 MTA · RuleForge KQL/Sigma filter'
    },
    {
      ioc: 'evil-login-portal.com',
      type: 'Domain',
      tools: ['malware', 'ioc', 'events', 'phishing'] as ToolId[],
      context: 'PE stage-2 string · Newly registered (15d) · PowerShell 4104 cradle · Phishing sender & credential harvester host'
    },
    {
      ioc: 'a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b',
      type: 'SHA-256',
      tools: ['malware', 'ioc', 'events', 'phishing'] as ToolId[],
      context: 'invoice_q3.exe primary hash · 52/71 VT detections · Sysmon EventID 1 ProcessCreate · Phishing ZIP attachment payload'
    },
    {
      ioc: 'C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll',
      type: 'File Path',
      tools: ['malware', 'events', 'ruleforge'] as ToolId[],
      context: 'Sandbox dropped beacon DLL · Sysmon EventID 13 Run key target · RuleForge CommandLine filter predicate'
    }
  ];

  const filteredTimeline = useMemo(() => {
    return activityFeed.filter((item) => {
      if (!selectedToolsFilter[item.tool]) return false;
      if (severityFilter !== 'all' && item.severity !== severityFilter) return false;
      return true;
    });
  }, [activityFeed, selectedToolsFilter, severityFilter]);

  const onlineCount = Object.values(backendStatus).filter((s) => s === 'online').length;

  const handleExportActivityCsv = () => {
    const header = 'ID,Timestamp,Tool,ActionType,Severity,Score,Description\n';
    const rows = filteredTimeline
      .map((r) => `"${r.id}","${r.timestamp}","${r.tool}","${r.actionType}","${r.severity}","${r.scoreText || ''}","${r.description.replace(/"/g, '""')}"`)
      .join('\n');
    downloadFileBlob('secconflux-activity-log.csv', header + rows, 'text/csv');
    onAddToast({
      type: 'success',
      title: 'Activity Log Exported',
      description: `Downloaded ${filteredTimeline.length} activity records as CSV.`
    });
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Unified Command Center Dashboard</h1>
          <p className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
            Real-time cross-engine threat posture, prioritized alert triage, and multi-tool indicator correlation
          </p>
        </div>
        <div
          className="inline-flex items-center gap-2.5 px-3.5 py-1.5 rounded-full text-xs font-semibold border"
          style={{ backgroundColor: 'var(--color-surface)', borderColor: 'var(--color-border)' }}
        >
          <span className={`w-2.5 h-2.5 rounded-full ${onlineCount === 5 ? 'bg-emerald-400' : 'bg-amber-400'}`} />
          <span>Platform Health: {onlineCount}/5 Engines Online</span>
          <span style={{ color: 'var(--color-text-tertiary)' }}>({apiClient.useFixtures ? 'Fixture Mode' : 'Live Proxy'})</span>
        </div>
      </div>

      {/* 7.1 Threat Posture Summary Bar */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
        {postureTiles.map((tile) => {
          const toolDef = TOOLS_REGISTRY[tile.tool];
          return (
            <button
              key={tile.tool}
              type="button"
              onClick={() => onNavigate(tile.tool, tile.targetMain, tile.targetSub)}
              className={`text-left p-4 rounded-xl sc-surface hover:scale-[1.02] transition cursor-pointer flex flex-col justify-between gap-3 sc-stagger-${(postureTiles.indexOf(tile) % 5) + 1}`}
            >
              <div className="flex items-center justify-between">
                <span className="inline-flex items-center gap-2 text-xs font-bold">
                  <span
                    className="w-6 h-6 rounded-md flex items-center justify-center text-white"
                    style={{ background: `linear-gradient(135deg, ${toolDef.accentFrom}, ${toolDef.accentTo})` }}
                  >
                    <ToolIcon tool={tile.tool} size={13} />
                  </span>
                  <span>{toolDef.shortName}</span>
                </span>
                <VerdictBadge verdict={tile.verdict} label={tile.critBadge} />
              </div>

              <div className="flex items-end justify-between gap-2 pt-1">
                <div>
                  <div className="sc-mono text-xl font-extrabold">{tile.metric}</div>
                  <div className="text-[10px]" style={{ color: 'var(--color-text-tertiary)' }}>
                    Last 7 days trend
                  </div>
                </div>
                <Sparkline values={tile.sparkline} color={toolDef.accentFrom} />
              </div>
            </button>
          );
        })}
      </section>

      {/* 7.2 Critical Findings Feed & 7.3 Cross-Tool IOC Correlation Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* 7.2 Critical Findings Feed */}
        <section className="lg:col-span-7 rounded-xl p-5 sc-surface space-y-3.5">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold uppercase tracking-wider">Prioritized Critical Findings</h2>
              <p className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
                High-severity detections aggregated across Malware, IOC, Events, Phishing & RuleForge
              </p>
            </div>
            <span className="sc-mono text-xs px-2 py-0.5 rounded bg-red-500/15 text-red-400 font-semibold">
              {criticalFindings.length} Active Alerts
            </span>
          </div>

          <div className="space-y-2.5">
            {criticalFindings.map((f) => {
              const tDef = TOOLS_REGISTRY[f.tool];
              return (
                <div
                  key={f.id}
                  className="p-3.5 rounded-lg border flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <VerdictBadge verdict={f.verdict} label={f.severity} />
                      <span className="inline-flex items-center gap-1 text-xs font-semibold" style={{ color: tDef.accentFrom }}>
                        <ToolIcon tool={f.tool} size={13} />
                        <span>{tDef.shortName}</span>
                      </span>
                      <span className="sc-mono text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>
                        {f.timestamp}
                      </span>
                    </div>
                    <div className="text-xs font-bold">{f.title}</div>
                    <p className="text-xs leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
                      {f.summary}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => onNavigate(f.tool, f.mainTab, f.subTab)}
                    className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg shrink-0 cursor-pointer"
                  >
                    Investigate →
                  </button>
                </div>
              );
            })}
          </div>
        </section>

        {/* 7.3 Cross-Tool IOC Correlation Panel */}
        <section className="lg:col-span-5 rounded-xl p-5 sc-surface space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-bold uppercase tracking-wider">Cross-Tool IOC Correlation Matrix</h2>
                <p className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
                  Indicators observed simultaneously in ≥ 3 security engines
                </p>
              </div>
              <button
                type="button"
                onClick={() => onBatchEnrichAll(correlatedIocs.map((c) => c.ioc))}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer shrink-0"
              >
                Enrich All ({correlatedIocs.length}) →
              </button>
            </div>

            <div className="space-y-2.5">
              {correlatedIocs.map((item, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg border space-y-2"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="sc-mono text-xs font-bold truncate" title={item.ioc}>
                      {item.ioc}
                    </span>
                    <span className="sc-mono text-[10px] px-2 py-0.5 rounded border shrink-0" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                      {item.type}
                    </span>
                  </div>
                  <p className="text-[11px] leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
                    {item.context}
                  </p>
                  <div className="flex items-center justify-between pt-1">
                    <div className="flex flex-wrap items-center gap-1">
                      {(['malware', 'ioc', 'events', 'phishing', 'ruleforge'] as ToolId[]).map((tid) => {
                        const present = item.tools.includes(tid);
                        const td = TOOLS_REGISTRY[tid];
                        return (
                          <span
                            key={tid}
                            className="px-2 py-0.5 rounded text-[10px] font-semibold flex items-center gap-1"
                            style={{
                              backgroundColor: present ? 'rgba(99, 102, 241, 0.16)' : 'var(--color-canvas)',
                              color: present ? td.accentFrom : 'var(--color-text-tertiary)',
                              border: `1px solid ${present ? td.accentFrom : 'var(--color-border-subtle)'}`
                            }}
                          >
                            <ToolIcon tool={tid} size={10} />
                            <span>{td.shortName}</span>
                          </span>
                        );
                      })}
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        onPivot({
                          fromTool: 'dashboard',
                          fromLabel: 'Command Center Correlation Matrix',
                          toTool: 'ioc',
                          toMainTab: 'lookup',
                          toSubTab: 'lookup',
                          indicatorValue: item.ioc,
                          indicatorType: item.type
                        })
                      }
                      className="text-[11px] font-semibold hover:underline cursor-pointer shrink-0 ml-2"
                      style={{ color: 'var(--accent-from)' }}
                    >
                      Pivot →
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div
            className="p-3 rounded-lg border text-xs flex items-center justify-between"
            style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border-subtle)' }}
          >
            <span style={{ color: 'var(--color-text-secondary)' }}>
              Campaign Cluster: <strong>FIN-Q4-COBALT-99412</strong>
            </span>
            <span className="sc-mono font-semibold text-emerald-400">Confidence: 98.4%</span>
          </div>
        </section>
      </div>

      {/* 7.4 Recent Activity Timeline */}
      <section className="rounded-xl p-5 sc-surface space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider">Unified Activity Timeline</h2>
            <p className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
              Chronological audit trail across all 5 engines ({filteredTimeline.length} events shown)
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Tool filter checkboxes */}
            {(['malware', 'ioc', 'events', 'phishing', 'ruleforge'] as ToolId[]).map((tid) => (
              <label
                key={tid}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs border cursor-pointer select-none"
                style={{
                  backgroundColor: selectedToolsFilter[tid] ? 'var(--color-surface-raised)' : 'var(--color-canvas)',
                  borderColor: selectedToolsFilter[tid] ? 'var(--color-border-focus)' : 'var(--color-border)'
                }}
              >
                <input
                  type="checkbox"
                  checked={selectedToolsFilter[tid]}
                  onChange={(e) => setSelectedToolsFilter({ ...selectedToolsFilter, [tid]: e.target.checked })}
                  className="accent-indigo-500"
                />
                <span>{TOOLS_REGISTRY[tid].shortName}</span>
              </label>
            ))}

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-2.5 py-1 rounded-md text-xs border"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              aria-label="Filter by severity"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical Only</option>
              <option value="high">High Only</option>
              <option value="medium">Medium Only</option>
            </select>

            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="px-2.5 py-1 rounded-md text-xs border"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              aria-label="Filter by time range"
            >
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>

            <button
              type="button"
              onClick={handleExportActivityCsv}
              className="px-3 py-1 rounded-md text-xs font-semibold border hover:opacity-90 cursor-pointer"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
            >
              ⬇ Export Activity Log (CSV)
            </button>
          </div>
        </div>

        <div className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
          {filteredTimeline.map((act) => {
            const tDef = TOOLS_REGISTRY[act.tool];
            return (
              <div key={act.id} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  <div
                    className="w-7 h-7 rounded-lg flex items-center justify-center text-white shrink-0"
                    style={{ background: `linear-gradient(135deg, ${tDef.accentFrom}, ${tDef.accentTo})` }}
                  >
                    <ToolIcon tool={act.tool} size={14} />
                  </div>
                  <div>
                    <div className="text-xs font-semibold flex flex-wrap items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] sc-mono border" style={{ borderColor: 'var(--color-border)' }}>
                        {act.actionType}
                      </span>
                      <span>{act.description}</span>
                    </div>
                    <div className="sc-mono text-[11px] mt-0.5" style={{ color: 'var(--color-text-tertiary)' }}>
                      {act.timestamp} · Source: {tDef.name}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {act.verdict && <VerdictBadge verdict={act.verdict} label={act.scoreText} />}
                  <button
                    type="button"
                    onClick={() => onNavigate(act.tool, tDef.mainTabs[1].id, act.targetSubTab || tDef.subTabs[0].id)}
                    className="px-2.5 py-1 rounded text-xs font-medium border hover:opacity-80 cursor-pointer"
                    style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}
                  >
                    Inspect →
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
};
