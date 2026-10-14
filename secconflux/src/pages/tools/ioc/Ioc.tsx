
// ============================================================================
// 10. TOOL 2: IOC LOOKUP PLATFORM (Section 9 — #/t/ioc & #/t/ioc/lookup)
// ============================================================================
const IOC_PIPELINE_STAGES = ['Classify', 'Query Sources', 'Score', 'Enrich'];

function refangIndicator(raw: string): { cleaned: string; wasDefanged: boolean } {
  const trimmed = raw.trim();
  const cleaned = trimmed
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/^hxxps:\/\//i, 'https://')
    .replace(/^hxxp:\/\//i, 'http://')
    .replace(/\[:\]/g, ':');
  return { cleaned, wasDefanged: cleaned !== trimmed };
}

export const IocTool: React.FC<{
  mainTab: string;
  subTab: string;
  setMainTab: (t: string) => void;
  setSubTab: (s: string) => void;
  activeQuery: string;
  setActiveQuery: (q: string) => void;
  batchPrefill: string[];
  onClearBatchPrefill: () => void;
  onPivot: (req: Omit<PivotRequest, 'id' | 'timestamp'>) => void;
  onPinIoc: (item: Omit<IOCClipboardItem, 'id' | 'addedAt'>) => void;
  onAddToast: (t: Omit<ToastMessage, 'id'>) => void;
  userRole: UserRole;
}> = ({
  mainTab,
  subTab,
  setMainTab,
  setSubTab,
  activeQuery,
  setActiveQuery,
  batchPrefill,
  onClearBatchPrefill,
  onPivot,
  onPinIoc,
  onAddToast,
  userRole
}) => {
  const [searchInput, setSearchInput] = useState(activeQuery || '198.51.100.45');
  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [pipelineStage, setPipelineStage] = useState(0);
  const [resultTab, setResultTab] = useState<'investigation' | 'enrichment' | 'sources' | 'relationships' | 'export'>('investigation');
  const [exportFormat, setExportFormat] = useState<'CSV' | 'STIX 2.1' | 'MISP' | 'SIEM' | 'HTML Report'>('STIX 2.1');
  const [showCoverageInfo, setShowCoverageInfo] = useState(false);

  // Feedback Widget state
  const [feedbackVote, setFeedbackVote] = useState<'yes' | 'no' | 'unsure' | null>(null);
  const [feedbackCorrection, setFeedbackCorrection] = useState('suspicious');
  const [feedbackNotes, setFeedbackNotes] = useState('');
  const [feedbackSubmitted, setFeedbackSubmitted] = useState(false);

  // Relationship Graph state
  const [graphViewMode, setGraphViewMode] = useState<'graph' | 'table'>('graph');
  const [minConnections, setMinConnections] = useState(1);
  const [nodeTypeFilter, setNodeTypeFilter] = useState<Record<string, boolean>>({
    IP: true,
    Domain: true,
    Hash: true,
    URL: true,
    Email: true
  });

  // Investigations (Cases) state
  const [cases, setCases] = useState(MORE_FIXTURES.iocCases);
  const [selectedCaseId, setSelectedCaseId] = useState(MORE_FIXTURES.iocCases[0].id);
  const [newCaseName, setNewCaseName] = useState('');
  const [newCaseIoc, setNewCaseIoc] = useState('');
  const [newCaseNote, setNewCaseNote] = useState('');

  // Batch state
  const [batchText, setBatchText] = useState(
    '198.51.100.45\nevil-login-portal.com\na4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b\nbc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n+1-415-890-9912\npassword:Summer2026!\n8.8.8.8'
  );
  const [batchRunning, setBatchRunning] = useState(false);
  const [batchProgress, setBatchProgress] = useState(100);
  const [batchVerdictFilter, setBatchVerdictFilter] = useState('all');
  const [batchSearch, setBatchSearch] = useState('');
  const [batchResults, setBatchResults] = useState([
    { ioc: '198.51.100.45', type: 'IPv4', verdict: 'malicious' as VerdictType, score: 92 },
    { ioc: 'evil-login-portal.com', type: 'Domain', verdict: 'malicious' as VerdictType, score: 89 },
    { ioc: 'a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b', type: 'SHA-256', verdict: 'malicious' as VerdictType, score: 87 },
    { ioc: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', type: 'BTC Wallet', verdict: 'malicious' as VerdictType, score: 88 },
    { ioc: '+1-415-890-9912', type: 'Phone', verdict: 'suspicious' as VerdictType, score: 68 },
    { ioc: 'password:Summer2026! (SHA1:7B520...)', type: 'Password Hash', verdict: 'malicious' as VerdictType, score: 95 },
    { ioc: '8.8.8.8', type: 'IPv4', verdict: 'clean' as VerdictType, score: 2 }
  ]);

  // History state
  const [historyList, setHistoryList] = useState(MORE_FIXTURES.iocHistory);
  const [historySearch, setHistorySearch] = useState('');

  useEffect(() => {
    if (activeQuery && activeQuery !== searchInput) {
      setSearchInput(activeQuery);
    }
  }, [activeQuery]);

  useEffect(() => {
    if (batchPrefill && batchPrefill.length > 0) {
      setBatchText(batchPrefill.join('\n'));
      onClearBatchPrefill();
    }
  }, [batchPrefill, onClearBatchPrefill]);

  const executeLookup = (rawQuery: string) => {
    const { cleaned, wasDefanged } = refangIndicator(rawQuery);
    setSearchInput(cleaned);
    setActiveQuery(cleaned);
    setMainTab('lookup');
    setSubTab('lookup');
    setPipelineRunning(true);
    setPipelineStage(0);
    setFeedbackSubmitted(false);
    setFeedbackVote(null);

    if (wasDefanged) {
      onAddToast({
        type: 'info',
        title: 'Auto-Refanged Indicator',
        description: `Normalized "${rawQuery}" → "${cleaned}"`
      });
    }

    let stg = 0;
    const interval = setInterval(() => {
      stg += 1;
      if (stg >= 4) {
        clearInterval(interval);
        setPipelineRunning(false);
        setHistoryList((prev) => [
          {
            id: `hist-${Date.now()}`,
            ioc: cleaned,
            type: cleaned.includes(':') ? 'Specialized IOC' : cleaned.includes('.') ? 'IP/Domain' : 'Hash',
            verdict: cleaned === '8.8.8.8' ? 'clean' : 'malicious',
            score: cleaned === '8.8.8.8' ? 2 : 92,
            timestamp: 'Just now',
            cached: false
          },
          ...prev.filter((h) => h.ioc !== cleaned)
        ]);
      } else {
        setPipelineStage(stg);
      }
    }, 220);
  };

  const activeProfile = useMemo(() => {
    const key = activeQuery as keyof typeof MORE_FIXTURES.iocProfiles;
    if (MORE_FIXTURES.iocProfiles[key]) {
      return MORE_FIXTURES.iocProfiles[key];
    }
    const base = MORE_FIXTURES.iocProfiles['198.51.100.45'];
    if (activeQuery === '8.8.8.8') {
      return {
        ...base,
        ioc: '8.8.8.8',
        type: 'IPv4 Address (Google Public DNS)',
        verdict: 'clean' as VerdictType,
        score: 2,
        whyVerdict: 'Verified benign public DNS resolver operated by Google LLC (AS15169). 0/28 intelligence providers report malicious activity.',
        votes: { malicious: 0, suspicious: 0, clean: 26, unknown: 7 }
      };
    }
    return {
      ...base,
      ioc: activeQuery || '198.51.100.45',
      type: activeQuery.length === 64 ? 'SHA-256 Hash' : activeQuery.includes('http') ? 'URL' : 'Domain / IPv4 Indicator'
    };
  }, [activeQuery]);

  const baseProfile = MORE_FIXTURES.iocProfiles['198.51.100.45'];

  const runBatchEnrichment = () => {
    const lines = batchText
      .split('\n')
      .map((l) => refangIndicator(l).cleaned)
      .filter(Boolean)
      .slice(0, 100);
    if (lines.length === 0) return;
    setBatchRunning(true);
    setBatchProgress(20);
    setTimeout(() => {
      setBatchProgress(100);
      setBatchRunning(false);
      const computed = lines.map((line) => {
        const isPass = line.toLowerCase().startsWith('password:');
        const isClean = line === '8.8.8.8' || line === '1.1.1.1';
        return {
          ioc: isPass ? `${line.slice(0, 12)}*** (WebCrypto SHA-1: 7B520...)` : line,
          type: isPass ? 'Password SHA-1' : line.length === 64 ? 'SHA-256' : line.startsWith('bc1') ? 'BTC Wallet' : line.startsWith('+') ? 'Phone' : /^\d+\.\d+\.\d+\.\d+$/.test(line) ? 'IPv4' : 'Domain/URL',
          verdict: (isClean ? 'clean' : line.startsWith('+') ? 'suspicious' : 'malicious') as VerdictType,
          score: isClean ? 2 : line.startsWith('+') ? 68 : 91
        };
      });
      setBatchResults(computed);
      onAddToast({
        type: 'success',
        title: 'Batch IOC Enrichment Complete',
        description: `Processed ${computed.length} indicators via SSE pipeline.`
      });
    }, 550);
  };

  if (mainTab === 'overview') {
    return (
      <ToolOverviewTemplate
        tool={TOOLS_REGISTRY.ioc}
        stats={[
          { label: 'Configured Threat Feeds', value: '28 / 33 Active' },
          { label: 'Supported Indicator Types', value: '31 Formats' },
          { label: 'Batch Processing Capacity', value: '100 IOCs / SSE Stream' },
          { label: 'Export Schemas', value: 'STIX 2.1 · MISP · ECS · CSV' }
        ]}
        doesList={[
          'Automatically detects and refangs defanged indicators (198.51.100[.]45, hxxps://) and classifies 31 indicator types.',
          'Queries 33 threat intelligence providers in parallel and computes a weighted 0–100 consensus score.',
          'Provides specialized intelligence cards for Bitcoin/Ethereum wallets, E.164 phone numbers, and client-side WebCrypto SHA-1 password breach checks.',
          'Renders force-directed IOC relationship graphs and exports directly to STIX 2.1, MISP, Splunk/ECS/LEEF, CSV, and HTML.'
        ]}
        doesNotList={[
          'Never transmits plaintext passwords over the network — `password:` queries are hashed client-side using WebCrypto SHA-1 k-anonymity.',
          'Never spends live API quota when reloading historical cached lookups unless "Re-scan Live" is explicitly clicked.'
        ]}
        terminalTitle="secconflux-ioc-cli lookup 198.51.100.45 --sources=all --format=json"
        terminalOutput={`{\n  "indicator": "198.51.100.45",\n  "type": "IPv4",\n  "verdict": "MALICIOUS",\n  "composite_score": 92,\n  "consensus_votes": { "malicious": 19, "suspicious": 4, "clean": 3, "unknown": 7 },\n  "shodan_ports": [22, 80, 443, 8443, 50050],\n  "ja3s_signature": "Cobalt Strike TeamServer Default"\n}`}
        ctaLabel="Launch IOC Lookup →"
        onStart={() => {
          setMainTab('lookup');
          setSubTab('lookup');
        }}
      />
    );
  }

  return (
    <div className="space-y-5 max-w-7xl mx-auto pb-12">
      {/* Header Contextual Search & Coverage Bar */}
      <div className="rounded-xl p-3.5 sc-surface flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex-1 flex items-center gap-2">
          <input
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && searchInput.trim()) executeLookup(searchInput);
            }}
            placeholder="Enter IP, domain, SHA256, URL, BTC wallet, phone (+1...), or password:secret (auto-refangs [.] and hxxps)"
            className="w-full px-3.5 py-2 rounded-lg text-xs sc-mono border"
            style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          />
          <button
            type="button"
            onClick={() => executeLookup(searchInput)}
            className="px-4 py-2 rounded-lg text-xs font-semibold text-white sc-accent-bg shrink-0 cursor-pointer"
          >
            Lookup IOC
          </button>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowCoverageInfo(!showCoverageInfo)}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold border flex items-center gap-1.5 cursor-pointer"
            style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
          >
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span>28 / 33 Sources Active</span>
          </button>
        </div>
      </div>

      {showCoverageInfo && (
        <div className="rounded-xl p-4 sc-surface-raised text-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-bold">Configured Threat Intelligence Sources (28 Active · 5 Enterprise Keys Missing)</span>
            <button type="button" onClick={() => setShowCoverageInfo(false)} className="text-xs underline cursor-pointer">
              Close
            </button>
          </div>
          <p style={{ color: 'var(--color-text-secondary)' }}>
            Active: VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, GreyNoise, ThreatFox, URLHaus, MalwareBazaar, FeodoTracker, urlscan.io, Hudson Rock, Censys, CrowdSec, Pulsedive, crt.sh, WHOIS, DNS, HIBP k-Anonymity, Blockchair, BGPView, PhishTank, OpenPhish, Spamhaus, Talos, IPInfo, Robtex, SecurityTrails, Cloudflare Radar. Missing optional keys: Recorded Future, Mandiant, DomainTools, Intel471, Flashpoint.
          </p>
        </div>
      )}

      {/* 9.3 Sub-Tab: Lookup */}
      {subTab === 'lookup' && (
        <div className="space-y-5">
          {/* Quick Sample Indicator Pills */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span style={{ color: 'var(--color-text-secondary)' }}>Quick Samples:</span>
            {[
              { label: 'C2 IP: 198.51.100[.]45 (Auto-Refang)', val: '198.51.100[.]45' },
              { label: 'Domain: evil-login-portal.com', val: 'evil-login-portal.com' },
              { label: 'BTC Wallet: bc1qxy2...', val: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh' },
              { label: 'Phone: +1-415-890-9912', val: '+1-415-890-9912' },
              { label: 'Breached Password (k-Anon)', val: 'password:Summer2026!' },
              { label: 'Benign DNS: 8.8.8.8', val: '8.8.8.8' }
            ].map((smp) => (
              <button
                key={smp.val}
                type="button"
                onClick={() => executeLookup(smp.val)}
                className="px-2.5 py-1 rounded-full border sc-mono text-[11px] hover:opacity-90 cursor-pointer"
                style={{ backgroundColor: 'var(--color-surface)', borderColor: 'var(--color-border)' }}
              >
                {smp.label}
              </button>
            ))}
          </div>

          {/* 4-Stage Pipeline Progress Bar */}
          {pipelineRunning && (
            <div className="rounded-xl p-5 sc-surface space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold">Executing 4-Stage Enrichment Pipeline for {activeQuery}...</span>
                <button
                  type="button"
                  onClick={() => setPipelineRunning(false)}
                  className="text-red-400 underline cursor-pointer"
                >
                  Cancel
                </button>
              </div>
              <div className="grid grid-cols-4 gap-2">
                {IOC_PIPELINE_STAGES.map((stg, i) => (
                  <div
                    key={stg}
                    className="p-2.5 rounded-lg border text-xs text-center font-semibold"
                    style={{
                      backgroundColor: i <= pipelineStage ? 'var(--color-surface-raised)' : 'var(--color-canvas)',
                      borderColor: i === pipelineStage ? 'var(--color-border-focus)' : i < pipelineStage ? 'var(--color-clean)' : 'var(--color-border)'
                    }}
                  >
                    {i < pipelineStage ? '✓ ' : i === pipelineStage ? '⟳ ' : ''}
                    {stg}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ResultView Internal Sub-Tabs */}
          <div className="rounded-xl p-5 sc-surface space-y-5">
            {/* Top Summary Banner */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b" style={{ borderColor: 'var(--color-border)' }}>
              <div className="flex items-center gap-4">
                <ScoreRing score={activeProfile.score} max={100} size={80} label={activeProfile.verdict.toUpperCase()} />
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <VerdictBadge verdict={activeProfile.verdict} size="md" />
                    <span className="sc-mono text-xs px-2 py-0.5 rounded border" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                      {activeProfile.type}
                    </span>
                  </div>
                  <h2 className="text-lg font-bold sc-mono break-all">{activeProfile.ioc}</h2>
                  <p className="text-xs max-w-2xl leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
                    {activeProfile.whyVerdict}
                  </p>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() =>
                    onPinIoc({
                      value: activeProfile.ioc,
                      type: 'ip',
                      sourceTool: 'ioc',
                      sourceContext: `Score ${activeProfile.score}/100`,
                      verdict: activeProfile.verdict
                    })
                  }
                  className="px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  📌 Pin to Clipboard
                </button>
                <button
                  type="button"
                  onClick={() =>
                    onPivot({
                      fromTool: 'ioc',
                      fromLabel: `IOC Lookup: ${activeProfile.ioc}`,
                      fromMainTab: 'lookup',
                      fromSubTab: 'lookup',
                      toTool: 'events',
                      toMainTab: 'investigation',
                      toSubTab: 'events',
                      indicatorValue: activeProfile.ioc,
                      indicatorType: activeProfile.type
                    })
                  }
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                >
                  Search Windows Events →
                </button>
                <button
                  type="button"
                  onClick={() =>
                    onPivot({
                      fromTool: 'ioc',
                      fromLabel: `IOC Lookup: ${activeProfile.ioc}`,
                      fromMainTab: 'lookup',
                      fromSubTab: 'lookup',
                      toTool: 'phishing',
                      toMainTab: 'analysis',
                      toSubTab: 'dashboard',
                      indicatorValue: activeProfile.ioc,
                      indicatorType: activeProfile.type
                    })
                  }
                  className="px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  Check Phishing Emails →
                </button>
              </div>
            </div>

            {/* ResultView 5 Internal Tabs */}
            <div className="flex flex-wrap items-center gap-2 border-b pb-3" style={{ borderColor: 'var(--color-border-subtle)' }}>
              {[
                { id: 'investigation', label: '1. Investigation & Consensus' },
                { id: 'enrichment', label: '2. Deep Enrichment (Geo/DNS/SSL/Shodan)' },
                { id: 'sources', label: '3. Provider Audit (33 Sources)' },
                { id: 'relationships', label: '4. Relationship Graph (D3)' },
                { id: 'export', label: '5. Export (STIX / MISP / SIEM)' }
              ].map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setResultTab(t.id as any)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer ${
                    resultTab === t.id ? 'sc-accent-bg text-white' : 'border'
                  }`}
                  style={resultTab === t.id ? {} : { borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* Internal Tab 1: Investigation */}
            {resultTab === 'investigation' && (
              <div className="space-y-5">
                {/* Consensus Voting Bar */}
                <div className="p-4 rounded-xl border space-y-2.5" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}>
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold uppercase tracking-wider">Multi-Provider Consensus Voting Bar</span>
                    <div className="flex items-center gap-3 sc-mono text-[11px]">
                      <span className="text-red-400">Malicious: {activeProfile.votes.malicious}</span>
                      <span className="text-amber-400">Suspicious: {activeProfile.votes.suspicious}</span>
                      <span className="text-emerald-400">Clean: {activeProfile.votes.clean}</span>
                      <span style={{ color: 'var(--color-text-tertiary)' }}>Unknown/Skipped: {activeProfile.votes.unknown}</span>
                    </div>
                  </div>
                  <div className="h-3 rounded-full overflow-hidden flex" style={{ backgroundColor: 'var(--color-canvas)' }}>
                    <div style={{ width: `${(activeProfile.votes.malicious / 33) * 100}%`, backgroundColor: 'var(--color-malicious)' }} />
                    <div style={{ width: `${(activeProfile.votes.suspicious / 33) * 100}%`, backgroundColor: 'var(--color-suspicious)' }} />
                    <div style={{ width: `${(activeProfile.votes.clean / 33) * 100}%`, backgroundColor: 'var(--color-clean)' }} />
                    <div style={{ width: `${(activeProfile.votes.unknown / 33) * 100}%`, backgroundColor: 'var(--color-unknown)' }} />
                  </div>
                </div>

                {/* Specialized Cards for Wallet, Phone, or Password Breach */}
                {'wallet' in activeProfile && activeProfile.wallet && (
                  <div className="p-4 rounded-xl border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-malicious)' }}>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-amber-400">₿ Cryptocurrency Wallet Intelligence Card</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-xs">
                      <CopyKV label="Chain" value={activeProfile.wallet.chain} />
                      <CopyKV label="Current Balance" value={activeProfile.wallet.balance} />
                      <CopyKV label="Total Received" value={activeProfile.wallet.totalReceived} />
                      <CopyKV label="Transactions" value={String(activeProfile.wallet.txCount)} />
                      <CopyKV label="Funding Sources" value={activeProfile.wallet.fundingSources.join(', ')} mono={false} />
                      <CopyKV label="Sanctions / Attribution" value={activeProfile.wallet.sanctionsCheck} mono={false} />
                    </div>
                  </div>
                )}

                {'phoneIntel' in activeProfile && activeProfile.phoneIntel && (
                  <div className="p-4 rounded-xl border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-suspicious)' }}>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-amber-400">📞 E.164 Phone & Vishing Intelligence Card</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
                      <CopyKV label="Carrier" value={activeProfile.phoneIntel.carrier} mono={false} />
                      <CopyKV label="Line Type" value={activeProfile.phoneIntel.lineType} mono={false} />
                      <CopyKV label="Fraud Score" value={activeProfile.phoneIntel.fraudScore} />
                      <CopyKV label="Associated Campaigns" value={activeProfile.phoneIntel.recentCampaigns} mono={false} />
                    </div>
                  </div>
                )}

                {'passwordBreach' in activeProfile && activeProfile.passwordBreach && (
                  <div className="p-4 rounded-xl border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-malicious)' }}>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-red-400">🔐 Password Breach Card (Zero-Knowledge WebCrypto SHA-1)</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
                      <CopyKV label="Breach Exposure Count" value={activeProfile.passwordBreach.exposureCount.toLocaleString() + ' hits'} />
                      <CopyKV label="k-Anonymity Prefix" value={activeProfile.passwordBreach.kPrefix} />
                      <CopyKV label="Breach Corpora" value={activeProfile.passwordBreach.sources.join(', ')} mono={false} />
                      <CopyKV label="Action" value={activeProfile.passwordBreach.recommendation} mono={false} />
                    </div>
                  </div>
                )}

                {/* Provider Evidence Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {baseProfile.providers.slice(0, 9).map((prov) => (
                    <div
                      key={prov.name}
                      className="p-3.5 rounded-lg border space-y-1.5 text-xs"
                      style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold">{prov.name}</span>
                        <VerdictBadge verdict={prov.verdict} />
                      </div>
                      <p className="text-[11px] leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
                        {prov.summary}
                      </p>
                      <div className="flex items-center justify-between text-[10px] sc-mono pt-1" style={{ color: 'var(--color-text-tertiary)' }}>
                        <span>Confidence: {prov.confidence}%</span>
                        <span>Latency: {prov.latency}</span>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Inline Analyst Feedback Widget */}
                <div className="p-4 rounded-xl border space-y-3" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)' }}>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-xs font-bold">Analyst Verdict Feedback: Is this composite verdict accurate?</span>
                    <div className="flex items-center gap-2">
                      {(['yes', 'no', 'unsure'] as const).map((opt) => (
                        <button
                          key={opt}
                          type="button"
                          onClick={() => {
                            setFeedbackVote(opt);
                            if (opt !== 'no') {
                              setFeedbackSubmitted(true);
                              onAddToast({ type: 'success', title: 'Feedback Recorded', description: `Submitted "${opt.toUpperCase()}" feedback to /api/ioc/feedback.` });
                            }
                          }}
                          className={`px-3 py-1 rounded text-xs font-semibold border cursor-pointer ${
                            feedbackVote === opt ? 'sc-accent-bg text-white' : ''
                          }`}
                          style={feedbackVote === opt ? {} : { borderColor: 'var(--color-border)' }}
                        >
                          {opt === 'yes' ? '👍 Yes' : opt === 'no' ? '👎 No' : '🤔 Unsure'}
                        </button>
                      ))}
                    </div>
                  </div>

                  {feedbackVote === 'no' && !feedbackSubmitted && (
                    <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 pt-2">
                      <select
                        value={feedbackCorrection}
                        onChange={(e) => setFeedbackCorrection(e.target.value)}
                        className="px-2.5 py-1.5 rounded text-xs border"
                        style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                      >
                        <option value="clean">Correct Verdict: CLEAN</option>
                        <option value="suspicious">Correct Verdict: SUSPICIOUS</option>
                        <option value="malicious">Correct Verdict: MALICIOUS</option>
                      </select>
                      <input
                        type="text"
                        value={feedbackNotes}
                        onChange={(e) => setFeedbackNotes(e.target.value)}
                        placeholder="Optional false-positive rationale or analyst note..."
                        className="flex-1 px-3 py-1.5 rounded text-xs border"
                        style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                      />
                      <button
                        type="button"
                        onClick={() => {
                          setFeedbackSubmitted(true);
                          onAddToast({ type: 'success', title: 'Verdict Override Submitted', description: `Logged correction (${feedbackCorrection.toUpperCase()}) to /api/ioc/feedback.` });
                        }}
                        className="px-3.5 py-1.5 rounded text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                      >
                        Submit Feedback
                      </button>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Internal Tab 2: Enrichment */}
            {resultTab === 'enrichment' && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
                <div className="p-4 rounded-xl border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}>
                  <h4 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                    🌍 GeoIP & Autonomous System (ASN)
                  </h4>
                  <CopyKV label="Country / City" value={`${baseProfile.geo.country} — ${baseProfile.geo.city}`} mono={false} />
                  <CopyKV label="ASN" value={baseProfile.geo.asn} />
                  <CopyKV label="Organization" value={baseProfile.geo.org} mono={false} />
                  <CopyKV label="Coordinates" value={baseProfile.geo.coords} />
                </div>

                <div className="p-4 rounded-xl border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}>
                  <h4 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                    🔒 TLS Certificate & JA3S Fingerprint
                  </h4>
                  <CopyKV label="Subject CN" value={baseProfile.ssl.subject} />
                  <CopyKV label="JA3S Fingerprint" value={baseProfile.ssl.ja3s} />
                  <CopyKV label="Serial Number" value={baseProfile.ssl.serial} />
                  <CopyKV label="Validity Window" value={`${baseProfile.ssl.validFrom} → ${baseProfile.ssl.validTo}`} />
                </div>

                <div className="p-4 rounded-xl border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}>
                  <h4 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                    🛰 Shodan Host Exposure & Vulnerabilities
                  </h4>
                  <CopyKV label="Operating System" value={baseProfile.shodan.os} mono={false} />
                  <CopyKV label="Open Ports" value={baseProfile.shodan.ports.join(', ')} />
                  <CopyKV label="Flagged CVEs" value={baseProfile.shodan.vulns.join(' · ')} />
                  <div className="space-y-1 pt-1">
                    {baseProfile.shodan.services.map((s) => (
                      <div key={s.port} className="sc-mono text-[11px] p-1.5 rounded" style={{ backgroundColor: 'var(--color-canvas)' }}>
                        Port {s.port}/{s.proto}: {s.banner}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-4 rounded-xl border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}>
                  <h4 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                    📋 Passive DNS, WHOIS & Hudson Rock Infostealer
                  </h4>
                  <CopyKV label="WHOIS Registrar" value={`${baseProfile.whois.registrar} (Created ${baseProfile.whois.created})`} mono={false} />
                  <CopyKV label="AbuseIPDB Score" value={`${baseProfile.abuseIpdb.confidenceScore}% (${baseProfile.abuseIpdb.totalReports} reports)`} />
                  <CopyKV label="Hudson Rock Stealers" value={`${baseProfile.hudsonRock.compromisedHosts} hosts (${baseProfile.hudsonRock.stealerFamilies.join(', ')})`} />
                  <CopyKV label="urlscan.io DOM" value={baseProfile.urlscan.domStats} mono={false} />
                </div>
              </div>
            )}

            {/* Internal Tab 3: Sources Audit */}
            {resultTab === 'sources' && (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                      <th className="py-2.5 px-3">Provider Name</th>
                      <th className="py-2.5 px-3">Execution Status</th>
                      <th className="py-2.5 px-3">Latency</th>
                      <th className="py-2.5 px-3">Verdict</th>
                      <th className="py-2.5 px-3">Evidence / Missing Key Hint</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
                    {baseProfile.providers.map((p) => (
                      <tr key={p.name}>
                        <td className="py-2.5 px-3 font-bold">{p.name}</td>
                        <td className="py-2.5 px-3 sc-mono">
                          {p.status === 'queried' ? '✅ queried' : '⏭ skipped'}
                        </td>
                        <td className="py-2.5 px-3 sc-mono">{p.latency}</td>
                        <td className="py-2.5 px-3">
                          <VerdictBadge verdict={p.verdict} />
                        </td>
                        <td className="py-2.5 px-3" style={{ color: 'var(--color-text-secondary)' }}>
                          {p.summary} {'missingKey' in p && p.missingKey ? `(${p.missingKey})` : ''}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Internal Tab 4: Relationships (Interactive SVG Force Graph + Table Toggle) */}
            {resultTab === 'relationships' && (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    {Object.keys(nodeTypeFilter).map((nt) => (
                      <label key={nt} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded border cursor-pointer" style={{ borderColor: 'var(--color-border)' }}>
                        <input
                          type="checkbox"
                          checked={nodeTypeFilter[nt]}
                          onChange={(e) => setNodeTypeFilter({ ...nodeTypeFilter, [nt]: e.target.checked })}
                        />
                        <span>{nt}</span>
                      </label>
                    ))}
                    <label className="inline-flex items-center gap-2 ml-2">
                      <span style={{ color: 'var(--color-text-secondary)' }}>Min Connections: {minConnections}</span>
                      <input
                        type="range"
                        min={1}
                        max={4}
                        value={minConnections}
                        onChange={(e) => setMinConnections(Number(e.target.value))}
                      />
                    </label>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setGraphViewMode('graph')}
                      className={`px-3 py-1 rounded text-xs font-semibold cursor-pointer ${graphViewMode === 'graph' ? 'sc-accent-bg text-white' : 'border'}`}
                      style={graphViewMode === 'graph' ? {} : { borderColor: 'var(--color-border)' }}
                    >
                      Force Graph View
                    </button>
                    <button
                      type="button"
                      onClick={() => setGraphViewMode('table')}
                      className={`px-3 py-1 rounded text-xs font-semibold cursor-pointer ${graphViewMode === 'table' ? 'sc-accent-bg text-white' : 'border'}`}
                      style={graphViewMode === 'table' ? {} : { borderColor: 'var(--color-border)' }}
                    >
                      Table Fallback View
                    </button>
                  </div>
                </div>

                {graphViewMode === 'graph' ? (
                  <div className="rounded-xl border p-4 relative overflow-hidden" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)' }}>
                    <div className="text-[11px] mb-2" style={{ color: 'var(--color-text-secondary)' }}>
                      Click any node in the relationship graph to pivot and execute a live lookup for that indicator:
                    </div>
                    <svg viewBox="0 0 680 340" className="w-full h-72">
                      {baseProfile.relationships.edges.map((edge, idx) => {
                        const s = baseProfile.relationships.nodes.find((n) => n.id === edge.source);
                        const t = baseProfile.relationships.nodes.find((n) => n.id === edge.target);
                        if (!s || !t) return null;
                        if (!nodeTypeFilter[s.type] || !nodeTypeFilter[t.type]) return null;
                        if (s.connections < minConnections || t.connections < minConnections) return null;
                        return (
                          <g key={idx}>
                            <line x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke="#4f6ef7" strokeWidth="2" className="sc-flow-edge" />
                            <text
                              x={(s.x + t.x) / 2}
                              y={(s.y + t.y) / 2 - 5}
                              fill="#94a3b8"
                              fontSize="10"
                              textAnchor="middle"
                            >
                              {edge.relation}
                            </text>
                          </g>
                        );
                      })}
                      {baseProfile.relationships.nodes
                        .filter((n) => nodeTypeFilter[n.type] && n.connections >= minConnections)
                        .map((node) => {
                          const colorMap: Record<string, string> = {
                            IP: '#ef4444',
                            Domain: '#f59e0b',
                            Hash: '#8b5cf6',
                            URL: '#06b6d4',
                            Email: '#ec4899'
                          };
                          return (
                            <g
                              key={node.id}
                              className="cursor-pointer"
                              onClick={() => executeLookup(node.id)}
                            >
                              <circle cx={node.x} cy={node.y} r="22" fill={colorMap[node.type] || '#6366f1'} fillOpacity="0.22" stroke={colorMap[node.type] || '#6366f1'} strokeWidth="2" />
                              <text x={node.x} y={node.y + 4} fill="#f8fafc" fontSize="10" fontWeight="bold" textAnchor="middle">
                                {node.type}
                              </text>
                              <text x={node.x} y={node.y + 36} fill="#e2e8f0" fontSize="11" textAnchor="middle">
                                {node.label}
                              </text>
                            </g>
                          );
                        })}
                    </svg>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                          <th className="py-2 px-3">Indicator Node</th>
                          <th className="py-2 px-3">Type</th>
                          <th className="py-2 px-3">Connections</th>
                          <th className="py-2 px-3 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
                        {baseProfile.relationships.nodes
                          .filter((n) => nodeTypeFilter[n.type] && n.connections >= minConnections)
                          .map((n) => (
                            <tr key={n.id}>
                              <td className="py-2 px-3 sc-mono font-bold">{n.id}</td>
                              <td className="py-2 px-3">{n.type}</td>
                              <td className="py-2 px-3 sc-mono">{n.connections}</td>
                              <td className="py-2 px-3 text-right">
                                <button
                                  type="button"
                                  onClick={() => executeLookup(n.id)}
                                  className="px-2.5 py-1 rounded text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                                >
                                  Pivot Lookup →
                                </button>
                              </td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* Internal Tab 5: Export */}
            {resultTab === 'export' && (
              <div className="space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-1.5">
                    {(['STIX 2.1', 'MISP', 'SIEM', 'CSV', 'HTML Report'] as const).map((fmt) => (
                      <button
                        key={fmt}
                        type="button"
                        onClick={() => setExportFormat(fmt)}
                        className={`px-3 py-1 rounded text-xs font-semibold cursor-pointer ${
                          exportFormat === fmt ? 'sc-accent-bg text-white' : 'border'
                        }`}
                        style={exportFormat === fmt ? {} : { borderColor: 'var(--color-border)' }}
                      >
                        {fmt}
                      </button>
                    ))}
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      downloadFileBlob(`ioc-${activeProfile.ioc}-${exportFormat.toLowerCase()}.txt`, `SecConflux Export (${exportFormat}) for ${activeProfile.ioc}`);
                      onAddToast({ type: 'success', title: `Exported ${exportFormat}`, description: `Downloaded ${exportFormat} bundle for ${activeProfile.ioc}.` });
                    }}
                    className="px-4 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                  >
                    ⬇ Download {exportFormat}
                  </button>
                </div>

                <pre className="p-4 rounded-xl sc-mono text-xs overflow-x-auto leading-relaxed" style={{ backgroundColor: 'var(--color-canvas)' }}>
                  {exportFormat === 'STIX 2.1'
                    ? `{\n  "type": "bundle",\n  "id": "bundle--secconflux-99412",\n  "objects": [\n    {\n      "type": "indicator",\n      "spec_version": "2.1",\n      "name": "${activeProfile.ioc}",\n      "pattern": "[ipv4-addr:value = '${activeProfile.ioc}']",\n      "confidence": ${activeProfile.score}\n    }\n  ]\n}`
                    : exportFormat === 'MISP'
                    ? `{\n  "Event": {\n    "info": "SecConflux IOC Enrichment: ${activeProfile.ioc}",\n    "threat_level_id": "1",\n    "Attribute": [{ "type": "ip-dst", "value": "${activeProfile.ioc}", "to_ids": true }]\n  }\n}`
                    : exportFormat === 'SIEM'
                    ? `CEF:0|SecConflux|IOCPlatform|2.0|100|Malicious IOC Detected|9|dst=${activeProfile.ioc} cs1Label=Verdict cs1=${activeProfile.verdict.toUpperCase()} cn1=${activeProfile.score}`
                    : exportFormat === 'CSV'
                    ? `indicator,type,verdict,score,malicious_votes\n"${activeProfile.ioc}","${activeProfile.type}","${activeProfile.verdict}",${activeProfile.score},${activeProfile.votes.malicious}`
                    : `<!DOCTYPE html><html><body><h1>SecConflux IOC Report: ${activeProfile.ioc}</h1><p>Verdict: ${activeProfile.verdict.toUpperCase()} (${activeProfile.score}/100)</p></body></html>`}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 9.4 Sub-Tab: Investigations */}
      {subTab === 'investigations' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          <div className="lg:col-span-4 rounded-xl p-4 sc-surface space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Active Investigation Cases ({cases.length})
            </h3>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={newCaseName}
                onChange={(e) => setNewCaseName(e.target.value)}
                placeholder="New case title..."
                className="flex-1 px-3 py-1.5 rounded-lg text-xs border"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              />
              <button
                type="button"
                onClick={() => {
                  if (!newCaseName.trim()) return;
                  const created = {
                    id: `case-${Date.now()}`,
                    name: newCaseName.trim(),
                    created: 'Just now',
                    status: 'Open',
                    iocs: []
                  };
                  setCases([created, ...cases]);
                  setSelectedCaseId(created.id);
                  setNewCaseName('');
                  onAddToast({ type: 'success', title: 'Investigation Case Created', description: created.name });
                }}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer"
              >
                + Create
              </button>
            </div>
            <div className="space-y-2">
              {cases.map((c) => (
                <div
                  key={c.id}
                  onClick={() => setSelectedCaseId(c.id)}
                  className="p-3 rounded-lg border cursor-pointer transition"
                  style={{
                    backgroundColor: selectedCaseId === c.id ? 'var(--color-surface-raised)' : 'var(--color-canvas)',
                    borderColor: selectedCaseId === c.id ? 'var(--color-border-focus)' : 'var(--color-border)'
                  }}
                >
                  <div className="text-xs font-bold">{c.name}</div>
                  <div className="text-[11px] flex items-center justify-between mt-1" style={{ color: 'var(--color-text-secondary)' }}>
                    <span>{c.iocs.length} IOCs</span>
                    <span>{c.created}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="lg:col-span-8 rounded-xl p-5 sc-surface space-y-4">
            {(() => {
              const activeCase = cases.find((c) => c.id === selectedCaseId) || cases[0];
              return (
                <>
                  <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: 'var(--color-border)' }}>
                    <div>
                      <h3 className="text-base font-bold">{activeCase.name}</h3>
                      <div className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
                        Created: {activeCase.created} · Status: {activeCase.status}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        if (cases.length <= 1) return;
                        const rem = cases.filter((x) => x.id !== activeCase.id);
                        setCases(rem);
                        setSelectedCaseId(rem[0].id);
                        onAddToast({ type: 'info', title: 'Case Deleted', description: activeCase.name });
                      }}
                      className="px-2.5 py-1 rounded text-xs border border-red-500/40 text-red-400 cursor-pointer"
                    >
                      Delete Case
                    </button>
                  </div>

                  {/* Add IOC to Case */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    <input
                      type="text"
                      value={newCaseIoc}
                      onChange={(e) => setNewCaseIoc(e.target.value)}
                      placeholder="Indicator (e.g., 203.0.113.88)"
                      className="px-3 py-1.5 rounded text-xs sc-mono border"
                      style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                    />
                    <input
                      type="text"
                      value={newCaseNote}
                      onChange={(e) => setNewCaseNote(e.target.value)}
                      placeholder="Markdown note..."
                      className="px-3 py-1.5 rounded text-xs border"
                      style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                    />
                    <button
                      type="button"
                      onClick={() => {
                        if (!newCaseIoc.trim()) return;
                        setCases(
                          cases.map((cs) =>
                            cs.id === activeCase.id
                              ? {
                                  ...cs,
                                  iocs: [
                                    ...cs.iocs,
                                    { value: newCaseIoc.trim(), type: 'Indicator', verdict: 'suspicious' as VerdictType, notes: newCaseNote || 'Added by analyst.' }
                                  ]
                                }
                              : cs
                          )
                        );
                        setNewCaseIoc('');
                        setNewCaseNote('');
                      }}
                      className="px-3 py-1.5 rounded text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                    >
                      + Attach IOC to Case
                    </button>
                  </div>

                  <div className="space-y-2.5">
                    {activeCase.iocs.map((entry, idx) => (
                      <div
                        key={idx}
                        className="p-3.5 rounded-lg border space-y-1.5"
                        style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                      >
                        <div className="flex items-center justify-between">
                          <span className="sc-mono text-xs font-bold">{entry.value}</span>
                          <div className="flex items-center gap-2">
                            <VerdictBadge verdict={entry.verdict} />
                            <button
                              type="button"
                              onClick={() => executeLookup(entry.value)}
                              className="text-xs underline cursor-pointer"
                              style={{ color: 'var(--accent-from)' }}
                            >
                              Lookup →
                            </button>
                          </div>
                        </div>
                        <div className="text-xs leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
                          {entry.notes}
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              );
            })()}
          </div>
        </div>
      )}

      {/* 9.5 Sub-Tab: Batch */}
      {subTab === 'batch' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          <div className="lg:col-span-5 rounded-xl p-5 sc-surface space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Batch IOC Input (Up to 100 IOCs)
              </h3>
              <span className="sc-mono text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>
                WebCrypto SHA-1 Active
              </span>
            </div>
            <textarea
              rows={8}
              value={batchText}
              onChange={(e) => setBatchText(e.target.value)}
              className="w-full p-3 rounded-lg text-xs sc-mono border"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
            <div className="flex items-center justify-between gap-2">
              <button
                type="button"
                onClick={runBatchEnrichment}
                disabled={batchRunning}
                className="px-4 py-2 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer"
              >
                {batchRunning ? 'Processing SSE Stream...' : '▶ Run Batch Enrichment'}
              </button>
              <button
                type="button"
                onClick={() => {
                  downloadFileBlob('batch-ioc-results.json', JSON.stringify(batchResults, null, 2));
                  onAddToast({ type: 'success', title: 'Batch JSON Exported', description: `${batchResults.length} results downloaded.` });
                }}
                className="px-3 py-2 rounded-lg text-xs font-medium border cursor-pointer"
                style={{ borderColor: 'var(--color-border)' }}
              >
                ⬇ Export Batch JSON
              </button>
            </div>
          </div>

          <div className="lg:col-span-7 rounded-xl p-5 sc-surface space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-1.5">
                {['all', 'malicious', 'suspicious', 'clean'].map((vf) => (
                  <button
                    key={vf}
                    type="button"
                    onClick={() => setBatchVerdictFilter(vf)}
                    className={`px-2.5 py-1 rounded-full text-xs font-semibold uppercase cursor-pointer ${
                      batchVerdictFilter === vf ? 'sc-accent-bg text-white' : 'border'
                    }`}
                    style={batchVerdictFilter === vf ? {} : { borderColor: 'var(--color-border)' }}
                  >
                    {vf}
                  </button>
                ))}
              </div>
              <input
                type="text"
                value={batchSearch}
                onChange={(e) => setBatchSearch(e.target.value)}
                placeholder="Filter batch results..."
                className="px-3 py-1 rounded text-xs sc-mono border"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              />
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                    <th className="py-2 px-3">Indicator</th>
                    <th className="py-2 px-3">Type</th>
                    <th className="py-2 px-3">Verdict</th>
                    <th className="py-2 px-3">Score</th>
                    <th className="py-2 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
                  {batchResults
                    .filter((r) => (batchVerdictFilter === 'all' ? true : r.verdict === batchVerdictFilter))
                    .filter((r) => r.ioc.toLowerCase().includes(batchSearch.toLowerCase()))
                    .map((r, i) => (
                      <tr key={i}>
                        <td className="py-2 px-3 sc-mono font-bold break-all">{r.ioc}</td>
                        <td className="py-2 px-3">{r.type}</td>
                        <td className="py-2 px-3">
                          <VerdictBadge verdict={r.verdict} />
                        </td>
                        <td className="py-2 px-3 sc-mono font-bold">{r.score}/100</td>
                        <td className="py-2 px-3 text-right">
                          <button
                            type="button"
                            onClick={() => executeLookup(r.ioc.split(' ')[0])}
                            className="px-2.5 py-1 rounded text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                          >
                            Inspect →
                          </button>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* 9.6 Sub-Tab: History */}
      {subTab === 'history' && (
        <div className="rounded-xl p-5 sc-surface space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-bold">Cached Lookup History (Zero API Quota Spend on Reload)</h3>
              <p className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
                Click any historical entry to reload its cached enrichment or click "Re-scan Live" to query fresh feeds
              </p>
            </div>
            <input
              type="text"
              value={historySearch}
              onChange={(e) => setHistorySearch(e.target.value)}
              placeholder="Filter history..."
              className="px-3 py-1.5 rounded-lg text-xs sc-mono border"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
          </div>

          <div className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
            {historyList
              .filter((h) => h.ioc.toLowerCase().includes(historySearch.toLowerCase()))
              .map((h) => (
                <div key={h.id} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                  <div className="flex items-center gap-3">
                    <VerdictBadge verdict={h.verdict} label={`${h.score}/100`} />
                    <span className="sc-mono font-bold">{h.ioc}</span>
                    <span className="px-2 py-0.5 rounded border text-[10px]" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                      {h.type}
                    </span>
                    <span style={{ color: 'var(--color-text-tertiary)' }}>{h.timestamp}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setActiveQuery(h.ioc);
                        setSearchInput(h.ioc);
                        setSubTab('lookup');
                        onAddToast({ type: 'info', title: 'Loaded Cached Result', description: `Zero API quota spent for ${h.ioc}.` });
                      }}
                      className="px-3 py-1 rounded border font-medium cursor-pointer"
                      style={{ borderColor: 'var(--color-border)' }}
                    >
                      Reload Cached
                    </button>
                    <button
                      type="button"
                      onClick={() => executeLookup(h.ioc)}
                      className="px-3 py-1 rounded font-semibold text-white sc-accent-bg cursor-pointer"
                    >
                      ↻ Re-scan Live
                    </button>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
};
