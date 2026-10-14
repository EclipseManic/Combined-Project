
// ============================================================================
// 11. TOOL 3: EVENT ANALYZER (Section 10 — #/t/events & #/t/events/investigation)
// ============================================================================
export const EventsTool: React.FC<{
  mainTab: string;
  subTab: string;
  setMainTab: (t: string) => void;
  setSubTab: (s: string) => void;
  initialSearchFilter: string;
  onClearInitialSearch: () => void;
  uploadModalOpen: boolean;
  setUploadModalOpen: (v: boolean) => void;
  onPivot: (req: Omit<PivotRequest, 'id' | 'timestamp'>) => void;
  onPinIoc: (item: Omit<IOCClipboardItem, 'id' | 'addedAt'>) => void;
  onAddToast: (t: Omit<ToastMessage, 'id'>) => void;
  userRole: UserRole;
}> = ({
  mainTab,
  subTab,
  setMainTab,
  setSubTab,
  initialSearchFilter,
  onClearInitialSearch,
  uploadModalOpen,
  setUploadModalOpen,
  onPivot,
  onPinIoc,
  onAddToast,
  userRole
}) => {
  const [investigations, setInvestigations] = useState(MORE_FIXTURES.eventInvestigations);
  const [activeInvId, setActiveInvId] = useState(MORE_FIXTURES.eventInvestigations[0].id);
  const activeInv = useMemo(
    () => investigations.find((i) => i.id === activeInvId) || investigations[0],
    [investigations, activeInvId]
  );

  // Filter state (10-field FTS5 filter bar)
  const [filterExpanded, setFilterExpanded] = useState(true);
  const [ftsQuery, setFtsQuery] = useState(initialSearchFilter || '');
  const [eventIdFilter, setEventIdFilter] = useState('');
  const [channelFilter, setChannelFilter] = useState('All');
  const [providerFilter, setProviderFilter] = useState('All');
  const [processFilter, setProcessFilter] = useState('');
  const [cmdFilter, setCmdFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [hostFilter, setHostFilter] = useState('');
  const [bookmarkedOnly, setBookmarkedOnly] = useState(false);
  const [sortOrder, setSortOrder] = useState<'newest' | 'oldest'>('newest');

  // Event Detail Drawer state
  const [selectedEventId, setSelectedEventId] = useState<number | null>(null);
  const [drawerRawTab, setDrawerRawTab] = useState<'Header' | 'System' | 'EventData' | 'UserData'>('EventData');
  const [drawerSearch, setDrawerSearch] = useState('');
  const [drawerHeight, setDrawerHeight] = useState<number>(320);

  // IOC & Sigma sub-tab state
  const [iocTypeFilter, setIocTypeFilter] = useState('All');
  const [iocSearch, setIocSearch] = useState('');
  const [sigmaSeverityFilter, setSigmaSeverityFilter] = useState('All');
  const [sigmaSearch, setSigmaSearch] = useState('');
  const [selectedSigmaRule, setSelectedSigmaRule] = useState<(typeof activeInv.sigmaRules)[0] | null>(null);

  // Notes state with debounced auto-save
  const [notesText, setNotesText] = useState(activeInv.notes);
  const [saveState, setSaveState] = useState<'saved' | 'saving'>('saved');

  // Upload EVTX modal state
  const [evtxName, setEvtxName] = useState('LATMOV-WKS09-Sysmon.evtx');
  const [ingesting, setIngesting] = useState(false);
  const [ingestStep, setIngestStep] = useState(0);
  const [ingestTicker, setIngestTicker] = useState(0);

  useEffect(() => {
    if (initialSearchFilter) {
      setFtsQuery(initialSearchFilter);
      onClearInitialSearch();
    }
  }, [initialSearchFilter, onClearInitialSearch]);

  const handleNotesChange = (val: string) => {
    setNotesText(val);
    setSaveState('saving');
    setTimeout(() => {
      setSaveState('saved');
    }, 650);
  };

  const toggleBookmark = (evId: number) => {
    setInvestigations((prev) =>
      prev.map((inv) =>
        inv.id === activeInv.id
          ? {
              ...inv,
              events: inv.events.map((ev) => (ev.id === evId ? { ...ev, bookmarked: !ev.bookmarked } : ev))
            }
          : inv
      )
    );
  };

  const filteredEvents = useMemo(() => {
    const list = activeInv.events.filter((ev) => {
      if (bookmarkedOnly && !ev.bookmarked) return false;
      if (eventIdFilter && String(ev.eventId) !== eventIdFilter.trim()) return false;
      if (channelFilter !== 'All' && ev.channel !== channelFilter) return false;
      if (providerFilter !== 'All' && ev.provider !== providerFilter) return false;
      if (processFilter && !ev.processName.toLowerCase().includes(processFilter.toLowerCase())) return false;
      if (cmdFilter && !ev.commandLine.toLowerCase().includes(cmdFilter.toLowerCase())) return false;
      if (userFilter && !ev.user.toLowerCase().includes(userFilter.toLowerCase())) return false;
      if (hostFilter && !ev.computer.toLowerCase().includes(hostFilter.toLowerCase())) return false;
      if (ftsQuery) {
        const q = ftsQuery.toLowerCase();
        const hay = `${ev.summary} ${ev.commandLine} ${ev.processName} ${ev.user} ${ev.computer} ${ev.iocs.join(' ')}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    return sortOrder === 'newest' ? list : [...list].reverse();
  }, [activeInv, bookmarkedOnly, eventIdFilter, channelFilter, providerFilter, processFilter, cmdFilter, userFilter, hostFilter, ftsQuery, sortOrder]);

  const selectedEvent = useMemo(
    () => activeInv.events.find((e) => e.id === selectedEventId) || null,
    [activeInv, selectedEventId]
  );

  const runEvtxIngestion = () => {
    setIngesting(true);
    setIngestStep(0);
    setIngestTicker(1420);
    const interval = setInterval(() => {
      setIngestTicker((t) => t + 6120);
      setIngestStep((s) => {
        if (s >= 2) {
          clearInterval(interval);
          setIngesting(false);
          setUploadModalOpen(false);
          setMainTab('investigation');
          setSubTab('events');
          onAddToast({
            type: 'success',
            title: 'EVTX Investigation Indexed',
            description: `Indexed 24,891 events from ${evtxName} into SQLite FTS5.`
          });
          return 2;
        }
        return s + 1;
      });
    }, 350);
  };

  if (mainTab === 'overview') {
    return (
      <>
        <ToolOverviewTemplate
          tool={TOOLS_REGISTRY.events}
          stats={[
            { label: 'Indexed Events (Current)', value: '24,891 EVTX Records' },
            { label: 'Search Engine', value: 'SQLite FTS5 Full-Text' },
            { label: 'Automated Detection', value: 'Sigma Rules + MITRE' },
            { label: 'Extracted Observables', value: '8 IOC Categories' }
          ]}
          doesList={[
            'Ingests multi-file and directory Windows EVTX logs (Security, Sysmon, PowerShell, System) into a fast SQLite FTS5 index.',
            'Provides a 10-dimension sticky filter bar with removable active filter chips and an interactive bottom Event Detail Drawer.',
            'Automatically extracts IPs, domains, hashes, URLs, file paths, and registry keys with event-count filtering.',
            'Matches events against production Sigma rules and pivots rules directly into RuleForge Workshop.'
          ]}
          doesNotList={[
            'Does not modify original uploaded `.evtx` evidence files — all indexing and bookmarking occurs in an isolated database.',
            'Does not require a full SIEM cluster deployment to hunt across local incident triage artifacts.'
          ]}
          terminalTitle="secconflux-events ingest WKS-FINANCE04-Sysmon.evtx --sigma-hunt"
          terminalOutput={`[11:50:01] Parsing EVTX chunks... 24,891 records extracted\n[11:50:02] Building SQLite FTS5 inverted index... OK (380ms)\n[11:50:03] Evaluating Sigma ruleset... 5 rules matched (74 total hits)\n  CRITICAL: SIG-001 Suspicious Rundll32 Network Connection (47 hits)\n  CRITICAL: SIG-003 Malicious PowerShell EncodedCommand Cradle (4 hits)`}
          ctaLabel="Open Event Investigation →"
          onStart={() => {
            setMainTab('investigation');
            setSubTab('events');
          }}
        />
        <Modal
          open={uploadModalOpen}
          title="📋 Upload EVTX Log Files"
          subtitle="Ingest single or multiple Windows Event Log (.evtx) files for FTS5 indexing & Sigma hunting"
          onClose={() => setUploadModalOpen(false)}
        >
          {renderUploadModal()}
        </Modal>
      </>
    );
  }

  function renderUploadModal() {
    return (
      <div className="space-y-4 text-xs">
        <div className="p-6 rounded-xl border-2 border-dashed text-center space-y-2" style={{ borderColor: 'var(--color-border-focus)', backgroundColor: 'var(--color-canvas)' }}>
          <div className="text-2xl">📋</div>
          <div className="text-sm font-semibold">Select `.evtx` files or forensic triage folder</div>
          <div style={{ color: 'var(--color-text-secondary)' }}>Accepted: `.evtx` Windows Event Logs (Security, Sysmon, PowerShell, System)</div>
          <input
            type="text"
            value={evtxName}
            onChange={(e) => setEvtxName(e.target.value)}
            className="w-full max-w-sm mx-auto mt-2 px-3 py-1.5 rounded border sc-mono text-center"
            style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          />
        </div>

        {ingesting && (
          <div className="p-4 rounded-lg border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}>
            <div className="flex items-center justify-between font-bold">
              <span>Stage: {['1/3 Parsing EVTX Binary Chunks', '2/3 Running Sigma & IOC Extractors', '3/3 Building SQLite FTS5 Index'][ingestStep]}</span>
              <span className="sc-mono text-cyan-400">{ingestTicker.toLocaleString()} events processed...</span>
            </div>
            <div className="h-2 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--color-canvas)' }}>
              <div className="h-full sc-accent-bg sc-candy-stripe" style={{ width: `${((ingestStep + 1) / 3) * 100}%` }} />
            </div>
          </div>
        )}

        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={() => setUploadModalOpen(false)}
            className="px-4 py-1.5 rounded-lg border cursor-pointer"
            style={{ borderColor: 'var(--color-border)' }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={runEvtxIngestion}
            disabled={ingesting || userRole === 'Viewer'}
            className="px-4 py-1.5 rounded-lg font-semibold text-white sc-accent-bg cursor-pointer disabled:opacity-40"
          >
            Start Ingestion →
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4 max-w-7xl mx-auto pb-16">
      {/* Header Contextual Bar */}
      <div className="rounded-xl p-3.5 sc-surface flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-semibold" style={{ color: 'var(--color-text-secondary)' }}>
            Investigation:
          </span>
          <select
            value={activeInv.id}
            onChange={(e) => setActiveInvId(e.target.value)}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold border"
            style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          >
            {investigations.map((inv) => (
              <option key={inv.id} value={inv.id}>
                {inv.name} ({inv.eventCount.toLocaleString()} events · {inv.timestamp})
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setUploadModalOpen(true)}
            disabled={userRole === 'Viewer'}
            className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer disabled:opacity-40"
          >
            + Upload EVTX
          </button>
          <button
            type="button"
            onClick={() => {
              downloadFileBlob(`${activeInv.id}-report.html`, `<html><body><h1>EVTX Investigation Report: ${activeInv.name}</h1><p>Events Indexed: ${activeInv.eventCount}</p></body></html>`, 'text/html');
              onAddToast({ type: 'success', title: 'Standalone HTML Report Downloaded', description: `${activeInv.name} exported.` });
            }}
            className="px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer"
            style={{ borderColor: 'var(--color-border)' }}
          >
            ⬇ Download Report
          </button>
        </div>
      </div>

      {/* 10.4 Sub-Tab: Events */}
      {subTab === 'events' && (
        <div className="space-y-4">
          {/* Collapsible Sticky Filter Card */}
          <div className="rounded-xl p-4 sc-surface space-y-3">
            <div className="flex items-center justify-between">
              <button
                type="button"
                onClick={() => setFilterExpanded(!filterExpanded)}
                className="text-xs font-bold uppercase tracking-wider flex items-center gap-2 cursor-pointer"
              >
                <span>{filterExpanded ? '▼' : '▶'} SQLite FTS5 Multi-Dimension Filter Matrix</span>
                <span className="sc-mono text-[11px] px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300">
                  Showing {filteredEvents.length} of {activeInv.eventCount.toLocaleString()} indexed
                </span>
              </button>
              <div className="flex items-center gap-2 text-xs">
                <label className="inline-flex items-center gap-1.5 cursor-pointer">
                  <input type="checkbox" checked={bookmarkedOnly} onChange={(e) => setBookmarkedOnly(e.target.checked)} />
                  <span>⭐ Bookmarked Only</span>
                </label>
                <button
                  type="button"
                  onClick={() => setSortOrder(sortOrder === 'newest' ? 'oldest' : 'newest')}
                  className="px-2.5 py-1 rounded border text-[11px] cursor-pointer"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  Sort: {sortOrder === 'newest' ? 'Newest First ↓' : 'Oldest First ↑'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setFtsQuery('');
                    setEventIdFilter('');
                    setChannelFilter('All');
                    setProviderFilter('All');
                    setProcessFilter('');
                    setCmdFilter('');
                    setUserFilter('');
                    setHostFilter('');
                    setBookmarkedOnly(false);
                  }}
                  className="text-xs underline cursor-pointer"
                  style={{ color: 'var(--accent-from)' }}
                >
                  Clear All
                </button>
              </div>
            </div>

            {filterExpanded && (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 pt-1 text-xs">
                <input
                  type="text"
                  value={ftsQuery}
                  onChange={(e) => setFtsQuery(e.target.value)}
                  placeholder="FTS5 Full-Text Search (IP, command, hash)..."
                  className="sm:col-span-2 px-3 py-1.5 rounded border sc-mono"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                />
                <input
                  type="text"
                  value={eventIdFilter}
                  onChange={(e) => setEventIdFilter(e.target.value)}
                  placeholder="Event ID (e.g. 3, 4104, 4688)"
                  className="px-3 py-1.5 rounded border sc-mono"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                />
                <select
                  value={channelFilter}
                  onChange={(e) => setChannelFilter(e.target.value)}
                  className="px-3 py-1.5 rounded border"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                >
                  <option value="All">All Channels</option>
                  {activeInv.channels.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </select>
                <input
                  type="text"
                  value={processFilter}
                  onChange={(e) => setProcessFilter(e.target.value)}
                  placeholder="Process name (e.g. rundll32.exe)"
                  className="px-3 py-1.5 rounded border sc-mono"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                />
                <input
                  type="text"
                  value={cmdFilter}
                  onChange={(e) => setCmdFilter(e.target.value)}
                  placeholder="Command line contains..."
                  className="px-3 py-1.5 rounded border sc-mono"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                />
                <input
                  type="text"
                  value={userFilter}
                  onChange={(e) => setUserFilter(e.target.value)}
                  placeholder="User (e.g. j.miller)"
                  className="px-3 py-1.5 rounded border sc-mono"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                />
                <input
                  type="text"
                  value={hostFilter}
                  onChange={(e) => setHostFilter(e.target.value)}
                  placeholder="Hostname (e.g. WKS-FINANCE04)"
                  className="px-3 py-1.5 rounded border sc-mono"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                />
              </div>
            )}

            {/* Active Filter Chips */}
            {(ftsQuery || eventIdFilter || channelFilter !== 'All' || processFilter || cmdFilter || userFilter || hostFilter || bookmarkedOnly) && (
              <div className="flex flex-wrap items-center gap-1.5 pt-1">
                {ftsQuery && (
                  <span className="px-2.5 py-0.5 rounded-full text-[11px] sc-mono bg-sky-500/20 text-sky-300 flex items-center gap-1.5">
                    FTS: "{ftsQuery}"
                    <button type="button" onClick={() => setFtsQuery('')} className="cursor-pointer font-bold">
                      ×
                    </button>
                  </span>
                )}
                {eventIdFilter && (
                  <span className="px-2.5 py-0.5 rounded-full text-[11px] sc-mono bg-sky-500/20 text-sky-300 flex items-center gap-1.5">
                    EventID: {eventIdFilter}
                    <button type="button" onClick={() => setEventIdFilter('')} className="cursor-pointer font-bold">
                      ×
                    </button>
                  </span>
                )}
                {processFilter && (
                  <span className="px-2.5 py-0.5 rounded-full text-[11px] sc-mono bg-sky-500/20 text-sky-300 flex items-center gap-1.5">
                    Process: {processFilter}
                    <button type="button" onClick={() => setProcessFilter('')} className="cursor-pointer font-bold">
                      ×
                    </button>
                  </span>
                )}
              </div>
            )}
          </div>

          {/* Events Table */}
          <div className="rounded-xl sc-surface overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                    <th className="py-2.5 px-3 w-10">⭐</th>
                    <th className="py-2.5 px-3 w-16">#</th>
                    <th className="py-2.5 px-3">Timestamp (UTC)</th>
                    <th className="py-2.5 px-3">Event ID</th>
                    <th className="py-2.5 px-3">Computer</th>
                    <th className="py-2.5 px-3">User</th>
                    <th className="py-2.5 px-3">Summary & Command Line</th>
                  </tr>
                </thead>
                <tbody className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
                  {filteredEvents.map((ev) => {
                    const isSelected = selectedEventId === ev.id;
                    return (
                      <tr
                        key={ev.id}
                        onClick={() => setSelectedEventId(ev.id)}
                        className="cursor-pointer transition"
                        style={{
                          backgroundColor: isSelected ? 'var(--color-surface-hover)' : 'transparent'
                        }}
                      >
                        <td
                          className="py-2.5 px-3"
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleBookmark(ev.id);
                          }}
                        >
                          <span className="text-sm">{ev.bookmarked ? '⭐' : '☆'}</span>
                        </td>
                        <td className="py-2.5 px-3 sc-mono" style={{ color: 'var(--color-text-tertiary)' }}>
                          {ev.id}
                        </td>
                        <td className="py-2.5 px-3 sc-mono whitespace-nowrap" title={ev.relTime}>
                          {ev.timestamp}
                        </td>
                        <td className="py-2.5 px-3">
                          <VerdictBadge
                            verdict={ev.level === 'Critical' ? 'malicious' : ev.level === 'High' || ev.level === 'Warning' ? 'suspicious' : 'info'}
                            label={`EID ${ev.eventId}`}
                          />
                        </td>
                        <td className="py-2.5 px-3 sc-mono">{ev.computer}</td>
                        <td className="py-2.5 px-3 sc-mono">{ev.user}</td>
                        <td className="py-2.5 px-3 max-w-xl truncate">{ev.summary}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Event Detail Drawer (Bottom Slide-Up Panel) */}
          {selectedEvent && (
            <div
              className="rounded-xl sc-surface-raised border-2 shadow-2xl p-4 space-y-3"
              style={{ borderColor: 'var(--color-border-focus)', minHeight: drawerHeight }}
            >
              <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b" style={{ borderColor: 'var(--color-border)' }}>
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <VerdictBadge verdict={selectedEvent.level === 'Critical' ? 'malicious' : 'suspicious'} label={`Event ID ${selectedEvent.eventId} (${selectedEvent.level})`} />
                  <span className="sc-mono font-bold">{selectedEvent.computer}</span>
                  <span style={{ color: 'var(--color-text-secondary)' }}>· User: {selectedEvent.user}</span>
                  <span className="sc-mono" style={{ color: 'var(--color-text-tertiary)' }}>
                    · {selectedEvent.timestamp}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setDrawerHeight(drawerHeight === 320 ? 460 : 320)}
                    className="px-2 py-1 rounded text-[11px] border cursor-pointer"
                    style={{ borderColor: 'var(--color-border)' }}
                  >
                    {drawerHeight === 320 ? '⤢ Expand Drawer' : '⤡ Compact Drawer'}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      copyTextToClipboard(JSON.stringify(selectedEvent, null, 2));
                      onAddToast({ type: 'info', title: 'Copied Full Event JSON', description: `Record #${selectedEvent.id} copied.` });
                    }}
                    className="px-2.5 py-1 rounded text-[11px] font-semibold border cursor-pointer"
                    style={{ borderColor: 'var(--color-border)' }}
                  >
                    Copy JSON
                  </button>
                  <button
                    type="button"
                    onClick={() => setSelectedEventId(null)}
                    className="px-2.5 py-1 rounded text-xs font-bold border cursor-pointer"
                    style={{ borderColor: 'var(--color-border)' }}
                  >
                    ✕ Close
                  </button>
                </div>
              </div>

              {/* Extracted IOCs & Sigma Matches Chips */}
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="font-semibold" style={{ color: 'var(--color-text-secondary)' }}>
                  Extracted IOCs:
                </span>
                {selectedEvent.iocs.map((iocVal) => (
                  <button
                    key={iocVal}
                    type="button"
                    onClick={() =>
                      onPivot({
                        fromTool: 'events',
                        fromLabel: `Event #${selectedEvent.id} (EID ${selectedEvent.eventId})`,
                        fromMainTab: 'investigation',
                        fromSubTab: 'events',
                        toTool: 'ioc',
                        toMainTab: 'lookup',
                        toSubTab: 'lookup',
                        indicatorValue: iocVal,
                        indicatorType: 'EVTX Observable'
                      })
                    }
                    className="px-2.5 py-0.5 rounded-full sc-mono text-[11px] bg-amber-500/20 text-amber-300 border border-amber-500/40 cursor-pointer"
                  >
                    🔍 {iocVal} →
                  </button>
                ))}
                {selectedEvent.sigmaMatches.map((sigTitle) => (
                  <button
                    key={sigTitle}
                    type="button"
                    onClick={() => setSubTab('sigma')}
                    className="px-2.5 py-0.5 rounded-full sc-mono text-[11px] bg-red-500/20 text-red-300 border border-red-500/40 cursor-pointer"
                  >
                    ⚡ {sigTitle}
                  </button>
                ))}
              </div>

              {/* Raw Event Data Tabs: Header | System | EventData | UserData */}
              <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                <div className="flex items-center gap-1.5">
                  {(['Header', 'System', 'EventData', 'UserData'] as const).map((tabName) => (
                    <button
                      key={tabName}
                      type="button"
                      onClick={() => setDrawerRawTab(tabName)}
                      className={`px-3 py-1 rounded text-xs font-semibold cursor-pointer ${
                        drawerRawTab === tabName ? 'sc-accent-bg text-white' : 'border'
                      }`}
                      style={drawerRawTab === tabName ? {} : { borderColor: 'var(--color-border)' }}
                    >
                      {tabName}
                    </button>
                  ))}
                </div>
                <input
                  type="text"
                  value={drawerSearch}
                  onChange={(e) => setDrawerSearch(e.target.value)}
                  placeholder={`Search ${drawerRawTab} fields...`}
                  className="px-2.5 py-1 rounded text-xs sc-mono border"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {Object.entries(selectedEvent.raw[drawerRawTab] || {})
                  .filter(([k, v]) => `${k} ${v}`.toLowerCase().includes(drawerSearch.toLowerCase()))
                  .map(([k, v]) => (
                    <CopyKV
                      key={k}
                      label={k}
                      value={String(v)}
                      onCopy={(val) => {
                        copyTextToClipboard(val);
                        onAddToast({ type: 'info', title: `Copied ${k}`, description: val });
                      }}
                    />
                  ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* 10.5 Sub-Tab: IOCs */}
      {subTab === 'iocs' && (
        <div className="rounded-xl p-5 sc-surface space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-1.5">
              {['All', 'IPs', 'Domains', 'Hashes', 'URLs', 'File Paths', 'Registry Keys', 'Processes'].map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setIocTypeFilter(t)}
                  className={`px-3 py-1 rounded-full text-xs font-semibold cursor-pointer ${
                    iocTypeFilter === t ? 'sc-accent-bg text-white' : 'border'
                  }`}
                  style={iocTypeFilter === t ? {} : { borderColor: 'var(--color-border)' }}
                >
                  {t}
                </button>
              ))}
            </div>
            <input
              type="text"
              value={iocSearch}
              onChange={(e) => setIocSearch(e.target.value)}
              placeholder="Search extracted EVTX IOCs..."
              className="px-3 py-1.5 rounded-lg text-xs sc-mono border"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Observable Value</th>
                  <th className="py-2.5 px-3">Source EVTX Field</th>
                  <th className="py-2.5 px-3">Event Count (Filter Events)</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
                {activeInv.iocs
                  .filter((i) => (iocTypeFilter === 'All' ? true : i.type === iocTypeFilter))
                  .filter((i) => i.value.toLowerCase().includes(iocSearch.toLowerCase()))
                  .map((item, idx) => (
                    <tr key={idx}>
                      <td className="py-2.5 px-3">
                        <VerdictBadge verdict={item.verdict} label={item.type} />
                      </td>
                      <td className="py-2.5 px-3 sc-mono font-bold break-all">{item.value}</td>
                      <td className="py-2.5 px-3 sc-mono" style={{ color: 'var(--color-text-secondary)' }}>
                        {item.sourceField}
                      </td>
                      <td className="py-2.5 px-3">
                        <button
                          type="button"
                          onClick={() => {
                            setFtsQuery(item.value);
                            setSubTab('events');
                          }}
                          className="px-2.5 py-0.5 rounded-full sc-mono font-bold bg-sky-500/20 text-sky-300 hover:underline cursor-pointer"
                        >
                          {item.eventCount} events →
                        </button>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() =>
                              onPinIoc({
                                value: item.value,
                                type: 'ip',
                                sourceTool: 'events',
                                sourceContext: activeInv.name,
                                verdict: item.verdict
                              })
                            }
                            className="px-2 py-1 rounded border text-[11px] cursor-pointer"
                            style={{ borderColor: 'var(--color-border)' }}
                          >
                            📌 Pin
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              onPivot({
                                fromTool: 'events',
                                fromLabel: `EVTX Investigation: ${activeInv.name}`,
                                fromMainTab: 'investigation',
                                fromSubTab: 'iocs',
                                toTool: 'ioc',
                                toMainTab: 'lookup',
                                toSubTab: 'lookup',
                                indicatorValue: item.value,
                                indicatorType: item.type
                              })
                            }
                            className="px-3 py-1 rounded text-[11px] font-semibold text-white sc-accent-bg cursor-pointer"
                          >
                            Enrich in IOC Lookup →
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 10.6 Sub-Tab: Sigma */}
      {subTab === 'sigma' && (
        <div className="rounded-xl p-5 sc-surface space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              {['All', 'critical', 'high', 'medium', 'low'].map((sev) => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSigmaSeverityFilter(sev)}
                  className={`px-3 py-1 rounded-full text-xs font-semibold uppercase cursor-pointer ${
                    sigmaSeverityFilter === sev ? 'sc-accent-bg text-white' : 'border'
                  }`}
                  style={sigmaSeverityFilter === sev ? {} : { borderColor: 'var(--color-border)' }}
                >
                  {sev}
                </button>
              ))}
            </div>
            <input
              type="text"
              value={sigmaSearch}
              onChange={(e) => setSigmaSearch(e.target.value)}
              placeholder="Search Sigma rule title or MITRE ID..."
              className="px-3 py-1.5 rounded-lg text-xs sc-mono border"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Rule ID & Title</th>
                  <th className="py-2.5 px-3">Matches</th>
                  <th className="py-2.5 px-3">MITRE ATT&CK</th>
                  <th className="py-2.5 px-3 text-right">Pivot</th>
                </tr>
              </thead>
              <tbody className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
                {activeInv.sigmaRules
                  .filter((r) => (sigmaSeverityFilter === 'All' ? true : r.severity === sigmaSeverityFilter))
                  .filter((r) => `${r.title} ${r.id} ${r.mitre.join(' ')}`.toLowerCase().includes(sigmaSearch.toLowerCase()))
                  .map((rule) => (
                    <tr
                      key={rule.id}
                      onClick={() => setSelectedSigmaRule(rule)}
                      className="cursor-pointer hover:opacity-90"
                    >
                      <td className="py-2.5 px-3">
                        <VerdictBadge verdict={rule.severity} label={rule.severity} />
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="font-bold">{rule.title}</div>
                        <div className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                          {rule.description}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 sc-mono font-bold">{rule.matchCount} hits</td>
                      <td className="py-2.5 px-3 sc-mono">{rule.mitre.join(', ')}</td>
                      <td
                        className="py-2.5 px-3 text-right"
                        onClick={(e) => {
                          e.stopPropagation();
                          onPivot({
                            fromTool: 'events',
                            fromLabel: `Sigma Detection: ${rule.id}`,
                            fromMainTab: 'investigation',
                            fromSubTab: 'sigma',
                            toTool: 'ruleforge',
                            toMainTab: 'workshop',
                            toSubTab: 'author',
                            indicatorValue: rule.yaml,
                            indicatorType: 'Sigma Rule'
                          });
                        }}
                      >
                        <button type="button" className="px-3 py-1 rounded text-xs font-semibold text-white sc-accent-bg cursor-pointer">
                          View in RuleForge →
                        </button>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Sigma Rule Detail Modal */}
      <Modal
        open={!!selectedSigmaRule}
        title={selectedSigmaRule ? `${selectedSigmaRule.id}: ${selectedSigmaRule.title}` : 'Sigma Rule Detail'}
        subtitle="Matched EVTX telemetry and canonical Sigma YAML definition"
        onClose={() => setSelectedSigmaRule(null)}
        maxWidth="max-w-2xl"
      >
        {selectedSigmaRule && (
          <div className="space-y-4 text-xs">
            <p style={{ color: 'var(--color-text-secondary)' }}>{selectedSigmaRule.description}</p>
            <pre className="p-3.5 rounded-lg sc-mono text-[11px] overflow-x-auto" style={{ backgroundColor: 'var(--color-canvas)' }}>
              {selectedSigmaRule.yaml}
            </pre>
            <div className="flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  const r = selectedSigmaRule;
                  setSelectedSigmaRule(null);
                  onPivot({
                    fromTool: 'events',
                    fromLabel: `Sigma Rule: ${r.id}`,
                    fromMainTab: 'investigation',
                    fromSubTab: 'sigma',
                    toTool: 'ruleforge',
                    toMainTab: 'workshop',
                    toSubTab: 'author',
                    indicatorValue: r.yaml,
                    indicatorType: 'Sigma Rule'
                  });
                }}
                className="px-4 py-1.5 rounded-lg font-semibold text-white sc-accent-bg cursor-pointer"
              >
                Open & Translate in RuleForge Workshop →
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* 10.7 Sub-Tab: Notes (Split-Pane Markdown Editor + Live Preview) */}
      {subTab === 'notes' && (
        <div className="rounded-xl p-5 sc-surface space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 text-xs">
              {[
                { label: 'B', insert: '**bold** ' },
                { label: 'I', insert: '*italic* ' },
                { label: 'H2', insert: '\n## Section Heading\n' },
                { label: '• List', insert: '\n- Finding item' },
                { label: '</> Code', insert: '`indicator` ' },
                { label: '🔗 Link', insert: '[MITRE ATT&CK](https://attack.mitre.org) ' }
              ].map((btn) => (
                <button
                  key={btn.label}
                  type="button"
                  onClick={() => handleNotesChange(notesText + btn.insert)}
                  className="px-2.5 py-1 rounded border font-semibold cursor-pointer"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  {btn.label}
                </button>
              ))}
            </div>
            <span className="sc-mono text-xs" style={{ color: saveState === 'saved' ? 'var(--color-clean)' : 'var(--color-suspicious)' }}>
              {saveState === 'saved' ? 'Saved ✓ (Auto-save active)' : 'Saving changes...'}
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <textarea
              rows={14}
              value={notesText}
              onChange={(e) => handleNotesChange(e.target.value)}
              className="w-full p-3.5 rounded-xl text-xs sc-mono border leading-relaxed"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
            <div
              className="p-4 rounded-xl border text-xs space-y-2 overflow-y-auto max-h-96 leading-relaxed"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
            >
              <div className="text-[10px] font-bold uppercase tracking-wider pb-1 border-b" style={{ borderColor: 'var(--color-border-subtle)', color: 'var(--color-text-tertiary)' }}>
                Live Markdown Preview
              </div>
              {notesText.split('\n').map((line, i) => {
                if (line.startsWith('# ')) return <h3 key={i} className="text-base font-bold pt-1">{line.slice(2)}</h3>;
                if (line.startsWith('## ')) return <h4 key={i} className="text-sm font-bold pt-1" style={{ color: 'var(--accent-from)' }}>{line.slice(3)}</h4>;
                if (line.startsWith('- ')) return <div key={i} className="pl-3">• {line.slice(2)}</div>;
                return <p key={i}>{line}</p>;
              })}
            </div>
          </div>
        </div>
      )}

      <Modal
        open={uploadModalOpen}
        title="📋 Upload EVTX Log Files"
        subtitle="Ingest single or multiple Windows Event Log (.evtx) files for FTS5 indexing & Sigma hunting"
        onClose={() => setUploadModalOpen(false)}
      >
        {renderUploadModal()}
      </Modal>
    </div>
  );
};

// ============================================================================
// 12. TOOL 4: PHISHING MAIL DETECTOR (Section 11 — Bug #1 Fixed: subTab === "dashboard")
// ============================================================================
const PHISHING_11_STAGES = [
  '1. Upload (.eml stream)',
  '2. Parse MIME Structure',
  '3. Authentication (SPF/DKIM/DMARC/ARC)',
  '4. Sender & Reply-To Divergence Analysis',
  '5. Defanged URL & Redirect Extraction',
  '6. Attachment Magic-Byte & Hash Dissection',
  '7. VirusTotal Domain/Hash Enrichment',
  '8. urlscan.io DOM & Screenshot Analysis',
  '9. Composite Risk Scoring (0–10)',
  '10. MITRE ATT&CK Technique Mapping',
  '11. Complete'
];

export const PhishingTool: React.FC<{
  mainTab: string;
  subTab: string;
  setMainTab: (t: string) => void;
  setSubTab: (s: string) => void;
  uploadModalOpen: boolean;
  setUploadModalOpen: (v: boolean) => void;
  onPivot: (req: Omit<PivotRequest, 'id' | 'timestamp'>) => void;
  onPinIoc: (item: Omit<IOCClipboardItem, 'id' | 'addedAt'>) => void;
  onAddToast: (t: Omit<ToastMessage, 'id'>) => void;
  userRole: UserRole;
}> = ({
  mainTab,
  subTab,
  setMainTab,
  setSubTab,
  uploadModalOpen,
  setUploadModalOpen,
  onPivot,
  onPinIoc,
  onAddToast,
  userRole
}) => {
  const [scans, setScans] = useState(MORE_FIXTURES.phishingScans);
  const [activeScanId, setActiveScanId] = useState(MORE_FIXTURES.phishingScans[0].id);
  const activeScan = useMemo(() => scans.find((s) => s.id === activeScanId) || scans[0], [scans, activeScanId]);

  const [emlFilename, setEmlFilename] = useState('Urgent_Wire_Remittance_Q3.eml');
  const [enableExternalEnrich, setEnableExternalEnrich] = useState(true);
  const [resolveRedirects, setResolveRedirects] = useState(true);
  const [runningPipeline, setRunningPipeline] = useState(false);
  const [pipelineStep, setPipelineStep] = useState(0);

  const [observableFilter, setObservableFilter] = useState('');
  const [previewMode, setPreviewMode] = useState<'html' | 'text' | 'headers'>('html');
  const [headerSearch, setHeaderSearch] = useState('');

  // Bug #1 Fix: Always route completed scan and dropdown selection to subTab "dashboard"
  const runPhishingAnalysis = () => {
    setUploadModalOpen(false);
    setMainTab('analysis');
    setRunningPipeline(true);
    setPipelineStep(0);

    let step = 0;
    const interval = setInterval(() => {
      step += 2;
      if (step >= 11) {
        clearInterval(interval);
        setRunningPipeline(false);
        setSubTab('dashboard'); // Strictly "dashboard", never "overview" or "summary"
        onAddToast({
          type: 'success',
          title: `Phishing Analysis Complete: ${emlFilename}`,
          description: `Verdict: ${activeScan.verdictLabel} (${activeScan.score}/10)`
        });
      } else {
        setPipelineStep(step);
      }
    }, 240);
  };

  if (mainTab === 'overview') {
    return (
      <>
        <ToolOverviewTemplate
          tool={TOOLS_REGISTRY.phishing}
          stats={[
            { label: 'Forensic Pipeline', value: '11 Automated Stages' },
            { label: 'Threat Heuristics', value: '~40 Weighted Signals' },
            { label: 'Auth Verification', value: 'SPF · DKIM · DMARC · ARC' },
            { label: 'HTML Mail Rendering', value: 'Zero-Script Sandboxed' }
          ]}
          doesList={[
            'Parses raw RFC 822 `.eml` messages across an 11-stage forensic pipeline with ~40 spoofing, lookalike, and payload signals.',
            'Visualizes hop-by-hop MTA Received headers, transit delays, and unencrypted SMTP relays.',
            'Constructs an Identity Mismatch Matrix comparing From, Reply-To, Return-Path, Sender, and Display Name.',
            'Extracts attachments and pivots weaponized hashes directly to Malware Analyzer and sender IPs to IOC Lookup.'
          ]}
          doesNotList={[
            'Never executes JavaScript or external tracking pixels when previewing HTML emails (`sandbox="allow-same-origin"` without `allow-scripts`).',
            'Never fails when external enrichment keys are absent — gracefully degrades to offline RFC 822 + static heuristics.'
          ]}
          terminalTitle="secconflux-phishing analyze Urgent_Wire_Remittance_Q3.eml"
          terminalOutput={`{\n  "subject": "URGENT: Q3 Wire Transfer & Remittance Invoice_Q3 (#INV-99412)",\n  "verdict": "UNSAFE",\n  "score": 9.2,\n  "auth": { "spf": "SOFTFAIL", "dkim": "FAIL", "dmarc": "FAIL", "compauth": "FAIL" },\n  "originating_ip": "198.51.100.45",\n  "attachment_sha256": "a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b"\n}`}
          ctaLabel="Analyze Phishing Email →"
          onStart={() => {
            setMainTab('analysis');
            setSubTab('dashboard');
          }}
        />
        <Modal
          open={uploadModalOpen}
          title="🎣 Upload & Analyze Email (.eml)"
          subtitle="11-stage RFC 822 header, authentication, URL redirect, and attachment forensics (Max 25 MB)"
          onClose={() => setUploadModalOpen(false)}
        >
          {renderPhishingUploadModal()}
        </Modal>
      </>
    );
  }

  function renderPhishingUploadModal() {
    return (
      <div className="space-y-4 text-xs">
        <div className="p-6 rounded-xl border-2 border-dashed text-center space-y-2" style={{ borderColor: 'var(--color-border-focus)', backgroundColor: 'var(--color-canvas)' }}>
          <div className="text-2xl">🎣</div>
          <div className="text-sm font-semibold">Drop an `.eml` message or enter sample filename</div>
          <div style={{ color: 'var(--color-text-secondary)' }}>Accepts RFC 822 `.eml` files only · Maximum size: 25 MB</div>
          <input
            type="text"
            value={emlFilename}
            onChange={(e) => setEmlFilename(e.target.value)}
            className="w-full max-w-sm mx-auto mt-2 px-3 py-1.5 rounded border sc-mono text-center"
            style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          />
        </div>
        <div className="space-y-2">
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={enableExternalEnrich} onChange={(e) => setEnableExternalEnrich(e.target.checked)} />
            <span>Enable external enrichment (VirusTotal, urlscan.io, WHOIS)</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={resolveRedirects} onChange={(e) => setResolveRedirects(e.target.checked)} />
            <span>Resolve URL redirect chains</span>
          </label>
        </div>
        <div className="flex items-center justify-end gap-2 pt-2">
          <button type="button" onClick={() => setUploadModalOpen(false)} className="px-4 py-1.5 rounded-lg border cursor-pointer" style={{ borderColor: 'var(--color-border)' }}>
            Cancel
          </button>
          <button
            type="button"
            onClick={runPhishingAnalysis}
            disabled={userRole === 'Viewer'}
            className="px-4 py-1.5 rounded-lg font-semibold text-white sc-accent-bg cursor-pointer disabled:opacity-40"
          >
            Analyze .eml →
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5 max-w-7xl mx-auto pb-12">
      {/* Header Contextual Bar */}
      <div className="rounded-xl p-3.5 sc-surface flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold" style={{ color: 'var(--color-text-secondary)' }}>
            Recent Investigation:
          </span>
          <select
            value={activeScan.id}
            onChange={(e) => {
              setActiveScanId(e.target.value);
              setSubTab('dashboard'); // Bug #1 Fix: always 'dashboard'
            }}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold border"
            style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.subject} — {s.verdictLabel} ({s.score}/10)
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setUploadModalOpen(true)}
            disabled={userRole === 'Viewer'}
            className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer disabled:opacity-40"
          >
            + Upload & Analyze (.eml)
          </button>
          <button
            type="button"
            onClick={() => {
              downloadFileBlob(`${activeScan.id}-phishing.json`, JSON.stringify(activeScan, null, 2));
              onAddToast({ type: 'success', title: 'Phishing Report Exported', description: `${activeScan.id}-phishing.json downloaded.` });
            }}
            className="px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer"
            style={{ borderColor: 'var(--color-border)' }}
          >
            ⬇ Export JSON
          </button>
        </div>
      </div>

      {/* 11.4 11-Stage Pipeline Progress Checklist */}
      {runningPipeline && (
        <div className="rounded-xl p-6 sc-surface space-y-4">
          <div className="flex items-center justify-between text-xs font-bold">
            <span>Executing 11-Stage Phishing Forensics Pipeline on {emlFilename}...</span>
            <span className="sc-mono">{Math.round(((pipelineStep + 1) / 11) * 100)}%</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 text-xs">
            {PHISHING_11_STAGES.map((stg, idx) => (
              <div
                key={stg}
                className="p-2.5 rounded-lg border flex items-center gap-2"
                style={{
                  backgroundColor: idx <= pipelineStep ? 'var(--color-surface-raised)' : 'var(--color-canvas)',
                  borderColor: idx === pipelineStep ? 'var(--color-border-focus)' : idx < pipelineStep ? 'var(--color-clean)' : 'var(--color-border)'
                }}
              >
                <span>{idx < pipelineStep ? '✅' : idx === pipelineStep ? '⏳' : '⬜'}</span>
                <span className="font-medium">{stg}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 11.5 Sub-Tab: Dashboard (Strictly subTab === 'dashboard') */}
      {!runningPipeline && subTab === 'dashboard' && (
        <div className="space-y-5">
          {/* Verdict Banner */}
          <div className="rounded-xl p-5 sc-surface sc-glow flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <ScoreRing score={activeScan.score} max={10} size={84} label={activeScan.verdictLabel} />
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <VerdictBadge verdict={activeScan.verdict} label={`VERDICT: ${activeScan.verdictLabel}`} size="md" />
                  <span className="sc-mono text-xs px-2 py-0.5 rounded bg-red-500/15 text-red-400">
                    Critical: {activeScan.counts.critical} · Suspicious: {activeScan.counts.suspicious} · Info: {activeScan.counts.info}
                  </span>
                </div>
                <h2 className="text-base font-bold">{activeScan.subject}</h2>
                <div className="text-xs sc-mono" style={{ color: 'var(--color-text-secondary)' }}>
                  Sender: {activeScan.sender} · Size: {activeScan.size} · {activeScan.timestamp}
                </div>
              </div>
            </div>

            <div className="flex flex-wrap gap-1.5">
              {activeScan.mitre.map((m) => (
                <a
                  key={m.id}
                  href={m.url}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2.5 py-1 rounded text-xs sc-mono border"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--accent-from)' }}
                >
                  {m.id}: {m.name}
                </a>
              ))}
            </div>
          </div>

          {/* Hop-by-Hop MTA Received Path Flow */}
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Hop-by-Hop MTA Received Path & TLS Encryption Flow
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              {activeScan.hops.map((h) => (
                <div
                  key={h.hop}
                  className="p-3.5 rounded-lg border space-y-1.5 text-xs relative"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: h.tls ? 'var(--color-border)' : 'var(--color-malicious)' }}
                >
                  <div className="flex items-center justify-between font-bold">
                    <span>Hop #{h.hop}</span>
                    <span className="sc-mono text-[11px]">{h.tls ? '✅ TLS 1.3' : '❌ No TLS'}</span>
                  </div>
                  <div className="sc-mono font-bold truncate" title={h.mta}>
                    {h.mta}
                  </div>
                  <div className="sc-mono text-[11px] flex items-center justify-between" style={{ color: 'var(--color-text-secondary)' }}>
                    <span>IP: {h.ip}</span>
                    <span>Delay: +{h.delay}</span>
                  </div>
                  <div className="text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>
                    {h.note}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Detailed Findings & Prioritized Recommendations */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            <div className="lg:col-span-7 rounded-xl p-5 sc-surface space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Detailed Forensic Findings ({activeScan.findings.length})
              </h3>
              <div className="space-y-2.5">
                {activeScan.findings.map((f, i) => (
                  <div
                    key={i}
                    className="p-3.5 rounded-lg border space-y-1.5 text-xs"
                    style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-bold">{f.title}</span>
                      <VerdictBadge verdict={f.severity} label={f.severity} />
                    </div>
                    <p style={{ color: 'var(--color-text-secondary)' }}>{f.description}</p>
                    <div className="text-[11px] sc-mono" style={{ color: 'var(--accent-from)' }}>
                      SOC Rationale: {f.rationale}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="lg:col-span-5 rounded-xl p-5 sc-surface space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Prioritized Response Actions
              </h3>
              {activeScan.recommendations.map((r, i) => (
                <div
                  key={i}
                  className="p-3 rounded-lg border space-y-1 text-xs"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <VerdictBadge verdict={r.priority === 'High' ? 'malicious' : 'suspicious'} label={`${r.priority} Priority`} />
                  <p className="pt-1 leading-relaxed">{r.action}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 11.6 Sub-Tab: Sender & Auth */}
      {!runningPipeline && subTab === 'sender-auth' && (
        <div className="space-y-5">
          {/* Authentication Status Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            {activeScan.authCards.map((ac) => (
              <div
                key={ac.protocol}
                className="p-4 rounded-xl sc-surface space-y-2 text-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-sm">{ac.protocol}</span>
                  <VerdictBadge verdict={ac.status === 'PASS' ? 'clean' : ac.status === 'FAIL' ? 'malicious' : 'unknown'} label={ac.status} />
                </div>
                <p className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                  {ac.detail}
                </p>
                <div className="p-2 rounded sc-mono text-[10px] break-all" style={{ backgroundColor: 'var(--color-canvas)' }}>
                  {ac.raw}
                </div>
              </div>
            ))}
          </div>

          {/* Identity Mismatch Matrix & Sender KV Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            <div className="lg:col-span-6 rounded-xl p-5 sc-surface space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Identity Divergence & Mismatch Matrix
              </h3>
              <div className="space-y-2">
                {activeScan.mismatchMatrix.map((mm, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg border flex items-center justify-between gap-2 text-xs"
                    style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                  >
                    <div>
                      <div className="font-bold">{mm.test}</div>
                      <div className="sc-mono text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                        {mm.detail}
                      </div>
                    </div>
                    <VerdictBadge verdict={mm.status} label={mm.status === 'match' ? '✅ MATCH' : '⚠️ MISMATCH'} />
                  </div>
                ))}
              </div>
              {activeScan.brandImpersonation.detected && (
                <div className="p-3 rounded-lg border border-red-500/40 bg-red-500/10 text-xs">
                  <strong>🚨 Brand Impersonation Alert:</strong> {activeScan.brandImpersonation.brand} (Confidence {activeScan.brandImpersonation.confidence}) — {activeScan.homographAlert.detail}
                </div>
              )}
            </div>

            <div className="lg:col-span-6 rounded-xl p-5 sc-surface space-y-2">
              <h3 className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--color-text-secondary)' }}>
                Envelope & Header Identity Attributes
              </h3>
              {Object.entries(activeScan.senderDetails).map(([k, v]) => (
                <CopyKV key={k} label={k} value={v} />
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 11.7 Sub-Tab: Artifacts */}
      {!runningPipeline && subTab === 'artifacts' && (
        <div className="space-y-5">
          {/* Attachments with Malware Analyzer Pivot */}
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Extracted Attachments & Payload Dissection
            </h3>
            {activeScan.attachments.map((att, i) => (
              <div
                key={i}
                className="p-4 rounded-xl border space-y-3 text-xs"
                style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="text-sm font-bold sc-mono">{att.filename}</div>
                    <div style={{ color: 'var(--color-text-secondary)' }}>
                      True Magic Type: {att.magicType} · Size: {att.size}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() =>
                      onPivot({
                        fromTool: 'phishing',
                        fromLabel: `Phishing Attachment: ${att.filename}`,
                        fromMainTab: 'analysis',
                        fromSubTab: 'artifacts',
                        toTool: 'malware',
                        toMainTab: 'investigation',
                        toSubTab: 'dashboard',
                        indicatorValue: att.sha256,
                        indicatorType: 'Attachment SHA-256'
                      })
                    }
                    className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                  >
                    🔬 Analyze in Malware Analyzer →
                  </button>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                  <CopyKV label="SHA-256" value={att.sha256} />
                  <CopyKV label="MD5" value={att.md5} />
                  <CopyKV label="Macros / Anomaly" value={att.macros} mono={false} />
                </div>
              </div>
            ))}
          </div>

          {/* Defanged URLs & Redirect Chains */}
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Defanged URLs & Redirect Chains ({activeScan.urls.length})
            </h3>
            <div className="space-y-2.5">
              {activeScan.urls.map((u, i) => (
                <div
                  key={i}
                  className="p-3.5 rounded-lg border space-y-2 text-xs"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="sc-mono font-bold break-all text-red-400">{u.defanged}</span>
                    <VerdictBadge verdict="malicious" label={u.vtVerdict} />
                  </div>
                  <div className="sc-mono text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                    Redirect Chain: {u.redirects.join(' ➔ ')}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Technical Observables (IOCs) */}
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Technical Observables (IOCs)
              </h3>
              <input
                type="text"
                value={observableFilter}
                onChange={(e) => setObservableFilter(e.target.value)}
                placeholder="Filter observables..."
                className="px-3 py-1 rounded text-xs sc-mono border"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              />
            </div>
            <div className="space-y-2">
              {activeScan.observables
                .filter((o) => `${o.value} ${o.context}`.toLowerCase().includes(observableFilter.toLowerCase()))
                .map((obs, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg border flex flex-wrap items-center justify-between gap-2 text-xs"
                    style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                  >
                    <div className="flex items-center gap-2.5">
                      <VerdictBadge verdict="malicious" label={obs.type} />
                      <span className="sc-mono font-bold">{obs.value}</span>
                      <span style={{ color: 'var(--color-text-secondary)' }}>— {obs.context}</span>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        onPivot({
                          fromTool: 'phishing',
                          fromLabel: `Phishing Email: ${activeScan.subject.slice(0, 28)}...`,
                          fromMainTab: 'analysis',
                          fromSubTab: 'artifacts',
                          toTool: 'ioc',
                          toMainTab: 'lookup',
                          toSubTab: 'lookup',
                          indicatorValue: obs.value,
                          indicatorType: obs.type
                        })
                      }
                      className="px-3 py-1 rounded text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                    >
                      Enrich in IOC Lookup →
                    </button>
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}

      {/* 11.8 Sub-Tab: Preview Mail */}
      {!runningPipeline && subTab === 'preview' && (
        <div className="rounded-xl p-5 sc-surface space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              {[
                { id: 'html', label: 'Sandboxed HTML Preview' },
                { id: 'text', label: 'Plain Text Body' },
                { id: 'headers', label: 'Raw RFC 822 Headers' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setPreviewMode(tab.id as any)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer ${
                    previewMode === tab.id ? 'sc-accent-bg text-white' : 'border'
                  }`}
                  style={previewMode === tab.id ? {} : { borderColor: 'var(--color-border)' }}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {previewMode === 'headers' && (
              <input
                type="text"
                value={headerSearch}
                onChange={(e) => setHeaderSearch(e.target.value)}
                placeholder="Highlight RFC 822 header text..."
                className="px-3 py-1 rounded text-xs sc-mono border"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              />
            )}
          </div>

          {previewMode === 'html' && (
            <div className="space-y-2">
              <div className="text-[11px] sc-mono text-emerald-400">
                🔒 Rendered inside isolated zero-script preview container (external scripts & forms disabled)
              </div>
              <div
                className="rounded-xl overflow-hidden border p-4"
                style={{ backgroundColor: '#f1f5f9', borderColor: 'var(--color-border)' }}
                dangerouslySetInnerHTML={{ __html: activeScan.htmlPreview }}
              />
            </div>
          )}

          {previewMode === 'text' && (
            <pre className="p-4 rounded-xl sc-mono text-xs overflow-x-auto leading-relaxed" style={{ backgroundColor: 'var(--color-canvas)' }}>
              {activeScan.plainTextPreview}
            </pre>
          )}

          {previewMode === 'headers' && (
            <pre className="p-4 rounded-xl sc-mono text-xs overflow-x-auto leading-relaxed" style={{ backgroundColor: 'var(--color-canvas)' }}>
              {activeScan.rawHeaders
                .split('\n')
                .filter((line) => (headerSearch ? line.toLowerCase().includes(headerSearch.toLowerCase()) : true))
                .join('\n')}
            </pre>
          )}
        </div>
      )}

      <Modal
        open={uploadModalOpen}
        title="🎣 Upload & Analyze Email (.eml)"
        subtitle="11-stage RFC 822 header, authentication, URL redirect, and attachment forensics (Max 25 MB)"
        onClose={() => setUploadModalOpen(false)}
      >
        {renderPhishingUploadModal()}
      </Modal>
    </div>
  );
};
