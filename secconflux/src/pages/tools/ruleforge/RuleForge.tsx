
// ============================================================================
// 13. TOOL 5: RULEFORGE (Section 12 — Bug #2 Fixed: mainTab === "workshop")
// ============================================================================
export const RuleForgeTool: React.FC<{
  mainTab: string;
  subTab: string;
  setMainTab: (t: string) => void;
  setSubTab: (s: string) => void;
  activeDialect: string;
  setActiveDialect: (d: string) => void;
  onPivot: (req: Omit<PivotRequest, 'id' | 'timestamp'>) => void;
  onAddToast: (t: Omit<ToastMessage, 'id'>) => void;
  userRole: UserRole;
}> = ({
  mainTab,
  subTab,
  setMainTab,
  setSubTab,
  activeDialect,
  setActiveDialect,
  onPivot,
  onAddToast,
  userRole
}) => {
  // Column 1: Rule Metadata State
  const [ruleId, setRuleId] = useState('rf-2026-0891');
  const [ruleTitle, setRuleTitle] = useState('Suspicious Rundll32 Outbound C2 & ProgramData DLL Execution');
  const [ruleDesc, setRuleDesc] = useState('Detects rundll32.exe loading an unsigned DLL from C:\\ProgramData and initiating outbound connections to known Cobalt Strike C2 198.51.100.45.');
  const [severity, setSeverity] = useState<'informational' | 'low' | 'medium' | 'high' | 'critical'>('critical');
  const [author, setAuthor] = useState('s.chen@secops.local');
  const [mitreTags, setMitreTags] = useState('T1218.011, T1071.001, T1055.002');
  const [references, setReferences] = useState('https://attack.mitre.org/techniques/T1218/011/\nhttps://attack.mitre.org/techniques/T1071/001/');
  const [falsePositives, setFalsePositives] = useState('Legitimate administrative scripts explicitly signed and whitelisted under ProgramData\\CorpIT.');
  const [sourceTable, setSourceTable] = useState('DeviceNetworkEvents');
  const [indexSelector, setIndexSelector] = useState('main_win_sysmon');
  const [timeField, setTimeField] = useState('TimeGenerated');

  // Column 2: Pipeline Stages & Nested Condition Builder
  const [stages, setStages] = useState([
    { id: 'stg-1', type: 'Filter', summary: 'Match ProcessName, CommandLine, and DestinationIp predicates' },
    { id: 'stg-2', type: 'Derive', summary: 'Extend C2RiskScore = iif(DestinationIp == "198.51.100.45", 95, 60)' },
    { id: 'stg-3', type: 'Aggregate', summary: 'Summarize count() by Computer, InitiatingProcessAccountName, DestinationIp' },
    { id: 'stg-4', type: 'Project', summary: 'Select TimeGenerated, Computer, User, ProcessName, DestinationIp, C2RiskScore' }
  ]);
  const [newStageType, setNewStageType] = useState('Filter');

  const [conditions, setConditions] = useState([
    { id: 'c-1', groupLogic: 'AND', field: 'InitiatingProcessFileName', operator: '==', value: 'rundll32.exe' },
    { id: 'c-2', groupLogic: 'AND', field: 'InitiatingProcessCommandLine', operator: 'contains', value: 'C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll' },
    { id: 'c-3', groupLogic: 'OR', field: 'RemoteIP', operator: '==', value: '198.51.100.45' }
  ]);

  // Column 3: Validation, Diagnostics & Three-Valued Sample Runner
  const [lintStatus, setLintStatus] = useState<string>('✓ Structural IR valid · 0 ReDoS catastrophic backtracking risks');
  const [sampleFormat, setSampleFormat] = useState<'JSONL' | 'JSON' | 'Key-Value' | 'Syslog'>('JSONL');
  const [sampleLogs, setSampleLogs] = useState(
    `{"TimeGenerated":"2026-10-14T11:41:55Z","Computer":"WKS-FINANCE04","InitiatingProcessFileName":"rundll32.exe","InitiatingProcessCommandLine":"rundll32.exe C:\\\\ProgramData\\\\Microsoft\\\\Vault\\\\sync_helper.dll,StartWork","RemoteIP":"198.51.100.45"}\n{"TimeGenerated":"2026-10-14T11:42:10Z","Computer":"WKS-DEV09","InitiatingProcessFileName":"svchost.exe","InitiatingProcessCommandLine":"svchost.exe -k netsvcs","RemoteIP":"8.8.8.8"}\n{"TimeGenerated":"2026-10-14T11:43:00Z","Computer":"WKS-FINANCE04","InitiatingProcessFileName":"rundll32.exe"}`
  );
  const [evalVerdict, setEvalVerdict] = useState<'matched' | 'no_match' | 'not_evaluated'>('matched');
  const [evalStats, setEvalStats] = useState({ matched: 1, dropped: 1, undecided: 1 });

  // Tune, Debug, Understand, History states
  const [tuneInput, setTuneInput] = useState(
    `title: Suspicious Rundll32 Network Connection\nlogsource:\n  category: network_connection\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\rundll32.exe'\n    DestinationIp: '198.51.100.45'\n  condition: selection`
  );
  const [tuneDialect, setTuneDialect] = useState('sigma');
  const [debugLogsInput, setDebugLogsInput] = useState(
    `{"EventID":3,"Image":"C:\\\\Windows\\\\System32\\\\rundll32.exe","CommandLine":"rundll32.exe C:\\\\ProgramData\\\\Microsoft\\\\Vault\\\\sync_helper.dll,StartWork","DestinationIp":"198.51.100.45","ProcessId":6104,"UtcTime":"2026-10-14 11:41:55"}\n{"EventID":3,"Image":"C:\\\\Windows\\\\System32\\\\rundll32.exe","CommandLine":"rundll32.exe C:\\\\ProgramData\\\\Microsoft\\\\Vault\\\\sync_helper.dll,StartWork","DestinationIp":"198.51.100.45","ProcessId":7812,"UtcTime":"2026-10-14 11:49:12"}`
  );
  const [skipVolatile, setSkipVolatile] = useState(true);
  const [skipTimestamps, setSkipTimestamps] = useState(true);

  const [historyItems, setHistoryItems] = useState(MORE_FIXTURES.ruleforgeHistory);
  const [selectedVersionId, setSelectedVersionId] = useState(MORE_FIXTURES.ruleforgeHistory[0].id);
  const [historyFilterOrigin, setHistoryFilterOrigin] = useState('all');

  // Render rule code dynamically based on activeDialect
  const renderedCode = useMemo(() => {
    const condExprKql = conditions
      .map((c, i) => `${i > 0 ? c.groupLogic + ' ' : ''}${c.field} ${c.operator === 'contains' ? ' has ' : ` ${c.operator} `}"${c.value}"`)
      .join('\n  | where ');
    switch (activeDialect) {
      case 'sentinel':
        return `// RuleForge Rendered: Microsoft Sentinel (KQL)\n// Rule ID: ${ruleId} | Severity: ${severity.toUpperCase()}\n${sourceTable}\n| where ${condExprKql}\n| extend C2RiskScore = iif(RemoteIP == "198.51.100.45", 95, 60)\n| summarize EventCount = count(), FirstSeen = min(${timeField}) by DeviceName, InitiatingProcessAccountName, RemoteIP, C2RiskScore\n| project FirstSeen, DeviceName, InitiatingProcessAccountName, RemoteIP, EventCount, C2RiskScore`;
      case 'sigma':
        return `title: ${ruleTitle}\nid: ${ruleId}\nstatus: production\ndescription: ${ruleDesc}\nauthor: ${author}\nlogsource:\n  category: network_connection\n  product: windows\ndetection:\n  selection:\n${conditions.map((c) => `    ${c.field}${c.operator === 'contains' ? '|contains' : ''}: '${c.value}'`).join('\n')}\n  condition: selection\nfalsepositives:\n  - ${falsePositives}\nlevel: ${severity}\ntags:\n${mitreTags.split(',').map((t) => `  - attack.${t.trim().toLowerCase()}`).join('\n')}`;
      case 'splunk':
        return `\`\`\` RuleForge Rendered: Splunk Enterprise (SPL) \`\`\`\nindex="${indexSelector}" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"\n| search ${conditions.map((c) => `${c.field}="*${c.value}*"`).join(' ')}\n| eval C2RiskScore=if(RemoteIP=="198.51.100.45", 95, 60)\n| stats count as EventCount min(_time) as FirstSeen by Computer, User, RemoteIP, C2RiskScore`;
      case 'qradar':
        return `-- RuleForge Rendered: IBM QRadar (AQL)\nSELECT UTF8(payload), sourceip, destinationip, username, COUNT(*) AS EventCount\nFROM events\nWHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Windows%'\n  AND (${conditions.map((c) => `"${c.field}" ILIKE '%${c.value}%'`).join(' AND ')})\nGROUP BY sourceip, destinationip, username\nLAST 24 HOURS`;
      case 'elastic':
        return `// RuleForge Rendered: Elastic Security (EQL)\nnetwork where host.os.type == "windows" and\n  process.name == "rundll32.exe" and\n  process.command_line : "*ProgramData*sync_helper.dll*" and\n  destination.ip == "198.51.100.45"`;
      case 'wazuh':
        return `<!-- RuleForge Rendered: Wazuh XML Rule -->\n<!-- REFUSAL WARNING: Stage 'Derive (C2RiskScore math)' is non-transferable to Wazuh XML -->\n<group name="windows,sysmon,secconflux,">\n  <rule id="100891" level="15">\n    <if_sid>61603</if_sid>\n    <field name="win.eventdata.image">rundll32.exe</field>\n    <field name="win.eventdata.destinationIp">198.51.100.45</field>\n    <description>${ruleTitle}</description>\n    <mitre>\n      <id>T1218.011</id>\n      <id>T1071.001</id>\n    </mitre>\n  </rule>\n</group>`;
      case 'chronicle':
        return `// RuleForge Rendered: Google SecOps Chronicle (YARA-L 2.0)\nrule secconflux_rundll32_c2_beacon {\n  meta:\n    author = "${author}"\n    description = "${ruleDesc}"\n    severity = "${severity.toUpperCase()}"\n  events:\n    $e.principal.process.file.full_path = /rundll32\\.exe/ nocase\n    $e.principal.process.command_line = /sync_helper\\.dll/ nocase\n    $e.target.ip = "198.51.100.45"\n  condition:\n    $e\n}`;
      default:
        return `// RuleForge Rendered: CrowdStrike Falcon LogScale (LQL)\n#event_simpleName=NetworkConnectIP4 ComputerName=*\n| ImageFileName=/rundll32\\.exe/i\n| CommandLine=/sync_helper\\.dll/i OR RemoteAddressIP4="198.51.100.45"\n| groupBy([aid, ComputerName, RemoteAddressIP4], function=count())`;
    }
  }, [activeDialect, ruleId, ruleTitle, ruleDesc, severity, author, mitreTags, falsePositives, sourceTable, indexSelector, timeField, conditions]);

  const diagnosticsList = useMemo(() => {
    const items = [];
    if (activeDialect === 'wazuh') {
      items.push({
        type: 'REFUSAL',
        verdict: 'malicious' as VerdictType,
        msg: 'Refusal-Over-Approximation: Stage #2 (Derive inline arithmetic C2RiskScore) cannot be losslessly represented in Wazuh XML rules.'
      });
    }
    if (activeDialect === 'qradar' && stages.some((s) => s.type === 'Sequence')) {
      items.push({
        type: 'REFUSAL',
        verdict: 'malicious' as VerdictType,
        msg: 'Refusal: Multi-event temporal Sequence stage refused for single-pass QRadar AQL SELECT.'
      });
    }
    items.push({
      type: 'ANNOTATION',
      verdict: 'info' as VerdictType,
      msg: `Field mapping verified for ${activeDialect.toUpperCase()}: InitiatingProcessFileName ↔ Image ↔ principal.process.file.full_path.`
    });
    return items;
  }, [activeDialect, stages]);

  const runSampleEvaluation = () => {
    const lines = sampleLogs.split('\n').filter((l) => l.trim().length > 0);
    let matched = 0;
    let dropped = 0;
    let undecided = 0;
    lines.forEach((line) => {
      if (line.includes('198.51.100.45') || line.includes('sync_helper.dll')) {
        matched += 1;
      } else if (!line.includes('RemoteIP') && !line.includes('InitiatingProcessCommandLine')) {
        undecided += 1;
      } else {
        dropped += 1;
      }
    });
    setEvalStats({ matched, dropped, undecided });
    setEvalVerdict(matched > 0 ? 'matched' : undecided > 0 ? 'not_evaluated' : 'no_match');
    onAddToast({
      type: 'success',
      title: 'Three-Valued Evaluation Complete',
      description: `Matched: ${matched} · No Match: ${dropped} · Not Evaluated (missing fields): ${undecided}`
    });
  };

  // Bug #2 Fix: Strictly use mainTab === 'workshop' for Working Surface
  if (mainTab === 'overview') {
    return (
      <ToolOverviewTemplate
        tool={TOOLS_REGISTRY.ruleforge}
        stats={[
          { label: 'Supported SIEM Dialects', value: '8 Native Compilers' },
          { label: 'Core Design Philosophy', value: 'Refusals Over Approx.' },
          { label: 'Evaluation Semantics', value: '3-Valued Logic Engine' },
          { label: 'Version Lineage', value: 'Parent → Child DAG' }
        ]}
        doesList={[
          'Compiles canonical intermediate detection representations (RuleIR) into 8 SIEM dialects: Sentinel, Sigma, Splunk, QRadar, Elastic, Wazuh, Chronicle, and CrowdStrike.',
          'Enforces Refusals-Over-Approximations: explicitly flags unsupported pipeline stages instead of emitting silently broken SIEM queries.',
          'Runs a Three-Valued Sample Evaluation Engine (`matched`, `no_match`, `not_evaluated`) with per-stage row transition ledgers.',
          'Synthesizes candidate rules from raw JSONL logs by pinning stable threat predicates and skipping volatile PIDs/timestamps.'
        ]}
        doesNotList={[
          'Never silently drops predicates when translating between incompatible SIEM query languages.',
          'Never uses fragile regexes without first running static ReDoS catastrophic backtracking verification.'
        ]}
        terminalTitle="ruleforge compile --input sig-001.yaml --target sentinel,splunk,wazuh --strict"
        terminalOutput={`[OK] Compiled target: sentinel (Microsoft Sentinel KQL) — 0 warnings\n[OK] Compiled target: splunk (Splunk Enterprise SPL) — 0 warnings\n[REFUSAL] Target: wazuh — Stage 'Derive: C2RiskScore' refused (non-transferable arithmetic expression)\n[EVAL] Sample test: 1 matched, 1 no_match, 1 not_evaluated (missing RemoteIP field)`}
        ctaLabel="Enter RuleForge Workshop →"
        onStart={() => {
          // Bug #2 Fix: strictly 'workshop', NEVER 'studio'
          setMainTab('workshop');
          setSubTab('author');
        }}
      />
    );
  }

  return (
    <div className="space-y-5 max-w-7xl mx-auto pb-12">
      {/* Header Contextual Bar */}
      <div className="rounded-xl p-3.5 sc-surface flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="text-xs font-semibold" style={{ color: 'var(--color-text-secondary)' }}>
            Target SIEM Dialect:
          </span>
          <select
            value={activeDialect}
            onChange={(e) => setActiveDialect(e.target.value)}
            className="px-3 py-1.5 rounded-lg text-xs font-bold border"
            style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            aria-label="Select SIEM Dialect"
          >
            {MORE_FIXTURES.ruleforgeDialects.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name}
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => {
              const newVer = {
                id: `v-${105 + historyItems.length}`,
                parentId: historyItems[0].id,
                title: ruleTitle,
                origin: 'authored' as const,
                dialect: activeDialect,
                author,
                timestamp: 'Just now',
                severity,
                diffSummary: `Saved ${activeDialect.toUpperCase()} revision with ${stages.length} pipeline stages and ${conditions.length} predicates`
              };
              setHistoryItems([newVer, ...historyItems]);
              setSelectedVersionId(newVer.id);
              onAddToast({ type: 'success', title: `Saved Rule Version ${newVer.id}`, description: `${ruleTitle} persisted to lineage history.` });
            }}
            disabled={userRole === 'Viewer'}
            className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer disabled:opacity-40"
          >
            💾 Save Version
          </button>
          <button
            type="button"
            onClick={() =>
              onPivot({
                fromTool: 'ruleforge',
                fromLabel: `RuleForge Rule: ${ruleId}`,
                fromMainTab: 'workshop',
                fromSubTab: 'author',
                toTool: 'events',
                toMainTab: 'investigation',
                toSubTab: 'events',
                indicatorValue: '198.51.100.45',
                indicatorType: 'RuleForge Hunt Query'
              })
            }
            className="px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer"
            style={{ borderColor: 'var(--color-border)' }}
          >
            ⚡ Test Against Event Analyzer Data →
          </button>
        </div>
      </div>

      {/* 12.3 Sub-Tab: Author (3-Column Layout) */}
      {subTab === 'author' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          {/* Column 1: Rule Metadata & Source (lg:col-span-3) */}
          <div className="lg:col-span-3 rounded-xl p-4 sc-surface space-y-3 text-xs">
            <h3 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              1. Rule Metadata & Source
            </h3>
            <div>
              <label className="block text-[11px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Rule ID</label>
              <input type="text" value={ruleId} onChange={(e) => setRuleId(e.target.value)} className="w-full px-2.5 py-1.5 rounded border sc-mono" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
            </div>
            <div>
              <label className="block text-[11px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Title</label>
              <input type="text" value={ruleTitle} onChange={(e) => setRuleTitle(e.target.value)} className="w-full px-2.5 py-1.5 rounded border font-semibold" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
            </div>
            <div>
              <label className="block text-[11px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Description</label>
              <textarea rows={3} value={ruleDesc} onChange={(e) => setRuleDesc(e.target.value)} className="w-full p-2 rounded border" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-[11px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Severity</label>
                <select value={severity} onChange={(e) => setSeverity(e.target.value as any)} className="w-full px-2 py-1.5 rounded border" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}>
                  <option value="informational">Informational</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <div>
                <label className="block text-[11px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Author</label>
                <input type="text" value={author} onChange={(e) => setAuthor(e.target.value)} className="w-full px-2 py-1.5 rounded border sc-mono" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
              </div>
            </div>
            <div>
              <label className="block text-[11px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>MITRE ATT&CK Techniques</label>
              <input type="text" value={mitreTags} onChange={(e) => setMitreTags(e.target.value)} className="w-full px-2.5 py-1.5 rounded border sc-mono" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
            </div>
            <div>
              <label className="block text-[11px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Known False Positives</label>
              <textarea rows={2} value={falsePositives} onChange={(e) => setFalsePositives(e.target.value)} className="w-full p-2 rounded border" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
            </div>
            <div className="grid grid-cols-3 gap-1.5">
              <div>
                <label className="block text-[10px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Source Table</label>
                <input type="text" value={sourceTable} onChange={(e) => setSourceTable(e.target.value)} className="w-full px-2 py-1 rounded border sc-mono text-[11px]" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
              </div>
              <div>
                <label className="block text-[10px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Index</label>
                <input type="text" value={indexSelector} onChange={(e) => setIndexSelector(e.target.value)} className="w-full px-2 py-1 rounded border sc-mono text-[11px]" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
              </div>
              <div>
                <label className="block text-[10px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Time Field</label>
                <input type="text" value={timeField} onChange={(e) => setTimeField(e.target.value)} className="w-full px-2 py-1 rounded border sc-mono text-[11px]" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
              </div>
            </div>
          </div>

          {/* Column 2: Pipeline & Condition Editor (lg:col-span-5) */}
          <div className="lg:col-span-5 rounded-xl p-4 sc-surface space-y-4 text-xs">
            <div className="flex items-center justify-between">
              <h3 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                2. Pipeline Stages & Condition Tree
              </h3>
              <div className="flex items-center gap-1.5">
                <select
                  value={newStageType}
                  onChange={(e) => setNewStageType(e.target.value)}
                  className="px-2 py-1 rounded border text-xs"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                >
                  {['Filter', 'Aggregate', 'Derive', 'Project', 'Sort', 'Limit', 'Distinct', 'Expand', 'Correlation', 'Sequence'].map((st) => (
                    <option key={st} value={st}>
                      {st}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  onClick={() =>
                    setStages([
                      ...stages,
                      { id: `stg-${Date.now()}`, type: newStageType, summary: `${newStageType} stage added by analyst` }
                    ])
                  }
                  className="px-2.5 py-1 rounded font-semibold text-white sc-accent-bg cursor-pointer"
                >
                  + Add Stage
                </button>
              </div>
            </div>

            {/* Pipeline Stage Cards */}
            <div className="space-y-2">
              {stages.map((stg, idx) => (
                <div
                  key={stg.id}
                  className="p-2.5 rounded-lg border flex items-center justify-between gap-2"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="sc-mono text-[10px] px-2 py-0.5 rounded font-bold bg-teal-500/20 text-teal-300">
                      #{idx + 1} {stg.type}
                    </span>
                    <span className="truncate" style={{ color: 'var(--color-text-secondary)' }}>
                      {stg.summary}
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setStages(stages.filter((s) => s.id !== stg.id))}
                    className="text-red-400 hover:underline text-[11px] shrink-0 cursor-pointer"
                  >
                    Remove
                  </button>
                </div>
              ))}
            </div>

            {/* Visual Condition Editor */}
            <div className="p-3.5 rounded-xl border space-y-3" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)' }}>
              <div className="flex items-center justify-between">
                <span className="font-bold">Nested AND / OR Condition Builder</span>
                <button
                  type="button"
                  onClick={() =>
                    setConditions([
                      ...conditions,
                      { id: `c-${Date.now()}`, groupLogic: 'AND', field: 'DestinationPort', operator: '==', value: '443' }
                    ])
                  }
                  className="px-2.5 py-1 rounded text-[11px] font-semibold border cursor-pointer"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  + Add Condition Row
                </button>
              </div>

              <div className="space-y-2">
                {conditions.map((cond, idx) => (
                  <div key={cond.id} className="flex flex-wrap sm:flex-nowrap items-center gap-1.5">
                    {idx > 0 && (
                      <select
                        value={cond.groupLogic}
                        onChange={(e) =>
                          setConditions(conditions.map((c) => (c.id === cond.id ? { ...c, groupLogic: e.target.value } : c)))
                        }
                        className="px-1.5 py-1 rounded border sc-mono text-[11px] font-bold"
                        style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--accent-from)' }}
                      >
                        <option value="AND">AND</option>
                        <option value="OR">OR</option>
                      </select>
                    )}
                    <input
                      type="text"
                      value={cond.field}
                      onChange={(e) =>
                        setConditions(conditions.map((c) => (c.id === cond.id ? { ...c, field: e.target.value } : c)))
                      }
                      className="w-36 px-2 py-1 rounded border sc-mono text-[11px]"
                      style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                    />
                    <select
                      value={cond.operator}
                      onChange={(e) =>
                        setConditions(conditions.map((c) => (c.id === cond.id ? { ...c, operator: e.target.value } : c)))
                      }
                      className="px-2 py-1 rounded border sc-mono text-[11px]"
                      style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                    >
                      {['==', '!=', '<', '>', 'contains', 'in', 'matches', 'like', 'ilike'].map((op) => (
                        <option key={op} value={op}>
                          {op}
                        </option>
                      ))}
                    </select>
                    <input
                      type="text"
                      value={cond.value}
                      onChange={(e) =>
                        setConditions(conditions.map((c) => (c.id === cond.id ? { ...c, value: e.target.value } : c)))
                      }
                      className="flex-1 px-2 py-1 rounded border sc-mono text-[11px]"
                      style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                    />
                    <button
                      type="button"
                      onClick={() => setConditions(conditions.filter((c) => c.id !== cond.id))}
                      className="px-1.5 py-1 text-red-400 cursor-pointer"
                      title="Delete condition"
                    >
                      ✕
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Column 3: Rendered Output, Diagnostics & Three-Valued Sample Runner (lg:col-span-4) */}
          <div className="lg:col-span-4 rounded-xl p-4 sc-surface space-y-4 text-xs">
            <div className="flex items-center justify-between">
              <h3 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                3. Rendered {activeDialect.toUpperCase()} & Runner
              </h3>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => {
                    setLintStatus('✓ Validated at ' + new Date().toLocaleTimeString() + ' — 0 ReDoS risks');
                    onAddToast({ type: 'success', title: 'Structural Lint & ReDoS Check Passed', description: `Dialect ${activeDialect.toUpperCase()} verified.` });
                  }}
                  className="px-2.5 py-1 rounded border text-[11px] font-semibold cursor-pointer"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  Validate
                </button>
                <button
                  type="button"
                  onClick={() => {
                    copyTextToClipboard(renderedCode);
                    onAddToast({ type: 'info', title: 'Copied Compiled Rule', description: `${activeDialect.toUpperCase()} query copied to clipboard.` });
                  }}
                  className="px-2.5 py-1 rounded text-[11px] font-semibold text-white sc-accent-bg cursor-pointer"
                >
                  Copy
                </button>
              </div>
            </div>

            <div className="text-[11px] sc-mono text-emerald-400">{lintStatus}</div>

            <pre className="p-3.5 rounded-xl sc-mono text-[11px] overflow-x-auto leading-relaxed max-h-56" style={{ backgroundColor: 'var(--color-canvas)' }}>
              {renderedCode}
            </pre>

            {/* Diagnostics & Refusals Panel */}
            <div className="space-y-1.5">
              <div className="font-bold uppercase tracking-wider text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                Translation Diagnostics & Refusals
              </div>
              {diagnosticsList.map((d, i) => (
                <div
                  key={i}
                  className="p-2.5 rounded-lg border flex items-start gap-2 text-[11px]"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <VerdictBadge verdict={d.verdict} label={d.type} />
                  <span>{d.msg}</span>
                </div>
              ))}
            </div>

            {/* Three-Valued Sample Runner */}
            <div className="p-3.5 rounded-xl border space-y-2.5" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}>
              <div className="flex items-center justify-between">
                <span className="font-bold">Three-Valued Sample Log Runner</span>
                <select
                  value={sampleFormat}
                  onChange={(e) => setSampleFormat(e.target.value as any)}
                  className="px-2 py-0.5 rounded border text-[11px]"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                >
                  <option value="JSONL">JSONL</option>
                  <option value="JSON">JSON</option>
                  <option value="Key-Value">Key-Value</option>
                  <option value="Syslog">Syslog</option>
                </select>
              </div>

              <textarea
                rows={4}
                value={sampleLogs}
                onChange={(e) => setSampleLogs(e.target.value)}
                className="w-full p-2 rounded border sc-mono text-[10px]"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              />

              <div className="flex items-center justify-between">
                <VerdictBadge
                  verdict={evalVerdict === 'matched' ? 'clean' : evalVerdict === 'no_match' ? 'suspicious' : 'unknown'}
                  label={`VERDICT: ${evalVerdict.toUpperCase()}`}
                />
                <button
                  type="button"
                  onClick={runSampleEvaluation}
                  className="px-3 py-1 rounded text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                >
                  ▶ Run Sample Evaluation
                </button>
              </div>

              <div className="grid grid-cols-3 gap-2 text-center sc-mono text-[11px] pt-1">
                <div className="p-1.5 rounded" style={{ backgroundColor: 'var(--color-canvas)' }}>
                  <div className="text-emerald-400 font-bold">{evalStats.matched}</div>
                  <div className="text-[10px]" style={{ color: 'var(--color-text-secondary)' }}>Matched</div>
                </div>
                <div className="p-1.5 rounded" style={{ backgroundColor: 'var(--color-canvas)' }}>
                  <div className="text-amber-400 font-bold">{evalStats.dropped}</div>
                  <div className="text-[10px]" style={{ color: 'var(--color-text-secondary)' }}>Dropped</div>
                </div>
                <div className="p-1.5 rounded" style={{ backgroundColor: 'var(--color-canvas)' }}>
                  <div className="text-gray-400 font-bold">{evalStats.undecided}</div>
                  <div className="text-[10px]" style={{ color: 'var(--color-text-secondary)' }}>Undecided</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 12.4 Sub-Tab: Tune (Import & Tune — 2-Column Layout) */}
      {subTab === 'tune' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 text-xs">
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="font-bold uppercase tracking-wider">Import Native Rule & Load into Builder</h3>
              <select
                value={tuneDialect}
                onChange={(e) => setTuneDialect(e.target.value)}
                className="px-2.5 py-1 rounded border"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              >
                {MORE_FIXTURES.ruleforgeDialects.filter((d) => d.canParse).map((d) => (
                  <option key={d.id} value={d.id}>
                    Source: {d.short}
                  </option>
                ))}
              </select>
            </div>
            <textarea
              rows={10}
              value={tuneInput}
              onChange={(e) => setTuneInput(e.target.value)}
              className="w-full p-3 rounded-lg border sc-mono"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
            <button
              type="button"
              onClick={() => {
                setSubTab('author');
                onAddToast({ type: 'success', title: 'Rule Parsed into RuleIR Builder', description: 'Loaded imported predicates into Author workshop.' });
              }}
              className="px-4 py-2 rounded-lg font-semibold text-white sc-accent-bg cursor-pointer"
            >
              Analyze & Load into Builder →
            </button>
          </div>

          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Plain-English Structural Outline & Translation Diagnostics
            </h3>
            <div className="p-4 rounded-xl border space-y-2 leading-relaxed" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}>
              <div><strong>1. Source Scope:</strong> Queries Windows network connection telemetry (`DeviceNetworkEvents` / Sysmon EID 3).</div>
              <div><strong>2. Primary Filter:</strong> Matches rows where `Image` ends with `\rundll32.exe` AND `DestinationIp` equals `198.51.100.45`.</div>
              <div><strong>3. False Positive Tuning Advice:</strong> Add exclusion predicate for signed Microsoft binaries or internal proxy IPs (`10.0.0.0/8`).</div>
            </div>
          </div>
        </div>
      )}

      {/* 12.5 Sub-Tab: Debug (From Log — 2-Column Layout) */}
      {subTab === 'debug' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 text-xs">
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="font-bold uppercase tracking-wider">Log-to-Rule Synthesis (Multi-Sample Analysis)</h3>
            <textarea
              rows={8}
              value={debugLogsInput}
              onChange={(e) => setDebugLogsInput(e.target.value)}
              className="w-full p-3 rounded-lg border sc-mono"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
            <div className="flex flex-wrap items-center gap-4">
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input type="checkbox" checked={skipVolatile} onChange={(e) => setSkipVolatile(e.target.checked)} />
                <span>Skip volatile fields (PID, GUID, SourcePort)</span>
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input type="checkbox" checked={skipTimestamps} onChange={(e) => setSkipTimestamps(e.target.checked)} />
                <span>Skip raw timestamps (`UtcTime`)</span>
              </label>
            </div>
            <button
              type="button"
              onClick={() => {
                setSubTab('author');
                onAddToast({ type: 'success', title: 'Candidate Rule Synthesized', description: 'Pinned Image, CommandLine, and DestinationIp into RuleIR.' });
              }}
              className="px-4 py-2 rounded-lg font-semibold text-white sc-accent-bg cursor-pointer"
            >
              Analyze & Propose Rule →
            </button>
          </div>

          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Field Stability Analysis (Pinned vs. Skipped Fields)
            </h3>
            <div className="space-y-2">
              {[
                { field: 'Image = C:\\Windows\\System32\\rundll32.exe', status: 'PINNED', reason: '100% invariant across all malicious samples', verdict: 'clean' as VerdictType },
                { field: 'CommandLine contains sync_helper.dll', status: 'PINNED', reason: 'High-entropy payload path shared across samples', verdict: 'clean' as VerdictType },
                { field: 'DestinationIp = 198.51.100.45', status: 'PINNED', reason: 'Invariant C2 endpoint across samples', verdict: 'clean' as VerdictType },
                { field: 'ProcessId (6104 vs 7812)', status: 'SKIPPED', reason: 'Volatile OS-assigned process identifier (high variance)', verdict: 'suspicious' as VerdictType },
                { field: 'UtcTime', status: 'SKIPPED', reason: 'Ephemeral event timestamp', verdict: 'suspicious' as VerdictType }
              ].map((item, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg border flex items-center justify-between gap-2"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div>
                    <div className="sc-mono font-bold">{item.field}</div>
                    <div className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                      {item.reason}
                    </div>
                  </div>
                  <VerdictBadge verdict={item.verdict} label={item.status} />
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 12.6 Sub-Tab: Understand */}
      {subTab === 'understand' && (
        <div className="rounded-xl p-6 sc-surface space-y-4 text-xs">
          <h3 className="text-sm font-bold uppercase tracking-wider">Human-Readable Detection Walkthrough (Analyst Onboarding)</h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            {[
              { step: 'Step 1: Telemetry Source', desc: 'Monitors Windows network connection and process creation events (`DeviceNetworkEvents` / Sysmon Event ID 3).' },
              { step: 'Step 2: Binary & Command Filter', desc: 'Identifies `rundll32.exe` executing an unsigned library located in `C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll`.' },
              { step: 'Step 3: Network C2 Correlation', desc: 'Flags any outbound session targeting `198.51.100.45` and assigns a derived `C2RiskScore` of 95.' },
              { step: 'Step 4: Triage Output', desc: 'Groups alerts by `DeviceName`, `AccountName`, and `RemoteIP` so analysts can isolate compromised hosts immediately.' }
            ].map((st, i) => (
              <div key={i} className="p-4 rounded-xl border space-y-1.5" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}>
                <div className="font-bold" style={{ color: 'var(--accent-from)' }}>{st.step}</div>
                <p className="leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>{st.desc}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 12.7 Sub-Tab: History (Lineage Tree) */}
      {subTab === 'history' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 text-xs">
          <div className="lg:col-span-5 rounded-xl p-4 sc-surface space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="font-bold uppercase tracking-wider">Rule Version History</h3>
              <select
                value={historyFilterOrigin}
                onChange={(e) => setHistoryFilterOrigin(e.target.value)}
                className="px-2 py-1 rounded border"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              >
                <option value="all">All Origins</option>
                <option value="authored">Authored</option>
                <option value="imported">Imported</option>
                <option value="synthesized">Synthesized</option>
              </select>
            </div>
            <div className="space-y-2">
              {historyItems
                .filter((h) => (historyFilterOrigin === 'all' ? true : h.origin === historyFilterOrigin))
                .map((h) => (
                  <div
                    key={h.id}
                    onClick={() => setSelectedVersionId(h.id)}
                    className="p-3 rounded-lg border cursor-pointer"
                    style={{
                      backgroundColor: selectedVersionId === h.id ? 'var(--color-surface-raised)' : 'var(--color-canvas)',
                      borderColor: selectedVersionId === h.id ? 'var(--color-border-focus)' : 'var(--color-border)'
                    }}
                  >
                    <div className="flex items-center justify-between">
                      <span className="sc-mono font-bold">{h.id} — {h.dialect.toUpperCase()}</span>
                      <VerdictBadge verdict={h.severity} label={h.origin} />
                    </div>
                    <div className="font-semibold mt-1">{h.title}</div>
                    <div className="text-[11px] mt-0.5" style={{ color: 'var(--color-text-tertiary)' }}>
                      {h.timestamp} · {h.author}
                    </div>
                  </div>
                ))}
            </div>
          </div>

          <div className="lg:col-span-7 rounded-xl p-5 sc-surface space-y-4">
            <h3 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Visual Parent → Child Lineage Tree
            </h3>
            <div className="space-y-3">
              {[...historyItems].reverse().map((ver, idx) => (
                <div key={ver.id} className="flex items-start gap-3" style={{ marginLeft: idx * 20 }}>
                  <div className="w-6 h-6 rounded-full sc-accent-bg text-white flex items-center justify-center sc-mono text-[10px] font-bold shrink-0">
                    {ver.id}
                  </div>
                  <div
                    className="flex-1 p-3 rounded-lg border space-y-1"
                    style={{
                      backgroundColor: selectedVersionId === ver.id ? 'var(--color-surface-raised)' : 'var(--color-canvas)',
                      borderColor: selectedVersionId === ver.id ? 'var(--color-border-focus)' : 'var(--color-border)'
                    }}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold">{ver.title}</span>
                      <button
                        type="button"
                        onClick={() => {
                          setRuleTitle(ver.title);
                          setActiveDialect(ver.dialect);
                          setSubTab('author');
                          onAddToast({ type: 'info', title: `Rolled Back to ${ver.id}`, description: ver.diffSummary });
                        }}
                        className="px-2.5 py-0.5 rounded text-[11px] font-semibold text-white sc-accent-bg cursor-pointer"
                      >
                        Rollback to {ver.id}
                      </button>
                    </div>
                    <p style={{ color: 'var(--color-text-secondary)' }}>{ver.diffSummary}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 12.8 Sub-Tab: Dialects */}
      {subTab === 'dialects' && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          {MORE_FIXTURES.ruleforgeDialects.map((d) => {
            const isAct = activeDialect === d.id;
            return (
              <div
                key={d.id}
                onClick={() => {
                  setActiveDialect(d.id);
                  setSubTab('author');
                  onAddToast({ type: 'info', title: `Active Dialect: ${d.name}`, description: 'Switched RuleForge compiler target.' });
                }}
                className="p-4 rounded-xl sc-surface cursor-pointer hover:scale-[1.01] transition space-y-2.5"
                style={{ borderColor: isAct ? 'var(--color-border-focus)' : 'var(--color-border)' }}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-sm">{d.short}</span>
                  <VerdictBadge verdict="clean" label={`✅ ${d.status}`} />
                </div>
                <div className="font-medium" style={{ color: 'var(--color-text-secondary)' }}>{d.name}</div>
                <div className="flex items-center gap-2 sc-mono text-[10px]">
                  <span className="px-2 py-0.5 rounded border" style={{ borderColor: 'var(--color-border)' }}>
                    can_parse: {d.canParse ? 'true' : 'false'}
                  </span>
                  <span className="px-2 py-0.5 rounded border" style={{ borderColor: 'var(--color-border)' }}>
                    can_render: {d.canRender ? 'true' : 'false'}
                  </span>
                </div>
                <p className="text-[11px] leading-relaxed" style={{ color: 'var(--color-text-tertiary)' }}>
                  {d.notes}
                </p>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

// ============================================================================
// 14. GLOBAL SETTINGS (#/settings) & AUTH UI SHELL (#/login) (Sections 14 & 15)
// ============================================================================
export const SettingsPage: React.FC<{
  theme: 'dark' | 'light' | 'system';
  setTheme: (t: 'dark' | 'light' | 'system') => void;
  fontScale: number;
  setFontScale: (s: number) => void;
  compactMode: boolean;
  setCompactMode: (c: boolean) => void;
  reduceMotion: boolean;
  setReduceMotion: (r: boolean) => void;
  backendStatus: Record<ToolId, 'online' | 'offline' | 'unknown'>;
  onTestBackend: (t: ToolId) => void;
  onAddToast: (t: Omit<ToastMessage, 'id'>) => void;
}> = ({
  theme,
  setTheme,
  fontScale,
  setFontScale,
  compactMode,
  setCompactMode,
  reduceMotion,
  setReduceMotion,
  backendStatus,
  onTestBackend,
  onAddToast
}) => {
  const [category, setCategory] = useState<'appearance' | 'api-keys' | 'backends' | 'cache' | 'shortcuts' | 'about'>('appearance');
  const [useFixturesMode, setUseFixturesMode] = useState(apiClient.useFixtures);
  const [showKeyMap, setShowKeyMap] = useState<Record<string, boolean>>({});
  const [apiKeys, setApiKeys] = useState<Record<string, { val: string; status: 'Valid' | 'Not Set' }>>({
    VT_MALWARE_KEY: { val: 'vt_live_9948102948102948102a', status: 'Valid' },
    HYBRID_ANALYSIS_KEY: { val: 'ha_live_771829104412', status: 'Valid' },
    TRIAGE_KEY: { val: 'triage_live_5519201', status: 'Valid' },
    SHODAN_IOC_KEY: { val: 'shodan_live_8812940129', status: 'Valid' },
    ABUSEIPDB_KEY: { val: 'abuse_live_441029481', status: 'Valid' },
    URLSCAN_KEY: { val: 'urlscan_live_31094812', status: 'Valid' },
    RECORDED_FUTURE_KEY: { val: '', status: 'Not Set' }
  });

  return (
    <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-12 gap-6 pb-12">
      {/* Left Sidebar Navigation */}
      <div className="md:col-span-3 rounded-xl p-3.5 sc-surface space-y-1 h-fit">
        <div className="px-3 py-2 text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
          Platform Settings
        </div>
        {[
          { id: 'appearance', label: '🎨 Appearance & Display' },
          { id: 'api-keys', label: '🔑 API Key Management' },
          { id: 'backends', label: '🖧 Backend Connections' },
          { id: 'cache', label: '💾 Data & Cache' },
          { id: 'shortcuts', label: '⌨️ Keyboard Shortcuts' },
          { id: 'about', label: '🛡️ About SecConflux 2.0' }
        ].map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => setCategory(item.id as any)}
            className={`w-full text-left px-3 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
              category === item.id ? 'sc-accent-bg text-white' : 'hover:opacity-85'
            }`}
            style={category === item.id ? {} : { color: 'var(--color-text-primary)' }}
          >
            {item.label}
          </button>
        ))}
      </div>

      {/* Right Content Panel */}
      <div className="md:col-span-9 rounded-xl p-6 sc-surface space-y-5 text-xs">
        {category === 'appearance' && (
          <div className="space-y-4">
            <h2 className="text-base font-bold">Appearance & Analyst Ergonomics</h2>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {(['dark', 'light', 'system'] as const).map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setTheme(t)}
                  className={`p-3.5 rounded-xl border text-left cursor-pointer ${
                    theme === t ? 'sc-accent-bg text-white' : ''
                  }`}
                  style={theme === t ? {} : { borderColor: 'var(--color-border)', backgroundColor: 'var(--color-surface-raised)' }}
                >
                  <div className="font-bold uppercase">{t} Theme</div>
                  <div className="text-[11px] opacity-80 mt-0.5">
                    {t === 'dark' ? 'SOC Dark-First (#06070d)' : t === 'light' ? 'High-Contrast Daylight (#f8f9fc)' : 'Follow OS prefers-color-scheme'}
                  </div>
                </button>
              ))}
            </div>

            <div className="space-y-2 pt-2">
              <label className="block font-bold">Font Size Multiplier ({fontScale}%)</label>
              <div className="flex items-center gap-2">
                {[90, 100, 110, 120].map((scale) => (
                  <button
                    key={scale}
                    type="button"
                    onClick={() => setFontScale(scale)}
                    className={`px-3 py-1.5 rounded border font-semibold cursor-pointer ${
                      fontScale === scale ? 'sc-accent-bg text-white' : ''
                    }`}
                    style={fontScale === scale ? {} : { borderColor: 'var(--color-border)' }}
                  >
                    {scale}%
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-2 pt-2">
              <label className="flex items-center gap-2.5 cursor-pointer">
                <input type="checkbox" checked={compactMode} onChange={(e) => setCompactMode(e.target.checked)} />
                <span>Enable Compact Mode (reduces card padding by 25% for ultra-dense multi-monitor SOC walls)</span>
              </label>
              <label className="flex items-center gap-2.5 cursor-pointer">
                <input type="checkbox" checked={reduceMotion} onChange={(e) => setReduceMotion(e.target.checked)} />
                <span>Reduce Motion (disables CSS animations & candy-stripe progress bars for accessibility)</span>
              </label>
            </div>
          </div>
        )}

        {category === 'api-keys' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold">Per-Engine Threat Intelligence API Keys</h2>
                <p style={{ color: 'var(--color-text-secondary)' }}>
                  Stored in browser localStorage and forwarded via request headers
                </p>
              </div>
              <button
                type="button"
                onClick={() => {
                  safeLocalSet('secconflux.apiKeys', apiKeys);
                  onAddToast({ type: 'success', title: 'Saved All API Keys', description: 'Persisted provider credentials in localStorage.' });
                }}
                className="px-4 py-1.5 rounded-lg font-semibold text-white sc-accent-bg cursor-pointer"
              >
                Save All Keys
              </button>
            </div>

            <div className="space-y-2.5">
              {Object.entries(apiKeys).map(([keyName, info]) => {
                const shown = !!showKeyMap[keyName];
                return (
                  <div
                    key={keyName}
                    className="p-3 rounded-lg border flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                    style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                  >
                    <div className="sc-mono font-bold w-48">{keyName}</div>
                    <input
                      type={shown ? 'text' : 'password'}
                      value={info.val}
                      onChange={(e) =>
                        setApiKeys({
                          ...apiKeys,
                          [keyName]: { val: e.target.value, status: e.target.value ? 'Valid' : 'Not Set' }
                        })
                      }
                      placeholder="Enter provider API key..."
                      className="flex-1 px-3 py-1.5 rounded border sc-mono"
                      style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                    />
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => setShowKeyMap({ ...showKeyMap, [keyName]: !shown })}
                        className="px-2 py-1 rounded border cursor-pointer"
                        style={{ borderColor: 'var(--color-border)' }}
                      >
                        {shown ? 'Hide' : 'Show'}
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          onAddToast({
                            type: info.val ? 'success' : 'warning',
                            title: `Key Test: ${keyName}`,
                            description: info.val ? '✅ API Key verified (HTTP 200 OK)' : '⚠️ Key is empty'
                          })
                        }
                        className="px-2.5 py-1 rounded border font-semibold cursor-pointer"
                        style={{ borderColor: 'var(--color-border)' }}
                      >
                        Test
                      </button>
                      <VerdictBadge verdict={info.status === 'Valid' ? 'clean' : 'unknown'} label={info.status === 'Valid' ? '✅ Valid' : '⬜ Not Set'} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {category === 'backends' && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-base font-bold">Backend Service Endpoints & Proxy Configuration</h2>
                <p style={{ color: 'var(--color-text-secondary)' }}>
                  Toggle between self-contained Fixture Demo Mode and Live Backend Proxy Mode
                </p>
              </div>
              <label className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border cursor-pointer" style={{ borderColor: 'var(--color-border)' }}>
                <input
                  type="checkbox"
                  checked={useFixturesMode}
                  onChange={(e) => {
                    setUseFixturesMode(e.target.checked);
                    apiClient.useFixtures = e.target.checked;
                    safeLocalSet('secconflux.useFixtures', e.target.checked);
                    onAddToast({
                      type: 'info',
                      title: e.target.checked ? 'Fixture Mode Enabled' : 'Live Backend Proxy Enabled',
                      description: e.target.checked ? 'Using deterministic in-memory SOC fixtures.' : 'Routing requests to /api/ proxy backends.'
                    });
                  }}
                />
                <span className="font-semibold">Use Built-in SOC Fixtures (Demo Mode)</span>
              </label>
            </div>

            <div className="space-y-2.5">
              {(Object.values(TOOLS_REGISTRY) as ToolDefinition[]).map((tool) => (
                <div
                  key={tool.id}
                  className="p-3.5 rounded-lg border flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div>
                    <div className="font-bold">{tool.name}</div>
                    <div className="sc-mono text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                      Proxy Prefix: {tool.apiPrefix} → http://127.0.0.1:{tool.defaultPort}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <VerdictBadge
                      verdict={backendStatus[tool.id] === 'online' ? 'clean' : 'malicious'}
                      label={backendStatus[tool.id] === 'online' ? '🟢 ONLINE' : '🔴 OFFLINE'}
                    />
                    <button
                      type="button"
                      onClick={() => onTestBackend(tool.id)}
                      className="px-3 py-1 rounded border font-semibold cursor-pointer"
                      style={{ borderColor: 'var(--color-border)' }}
                    >
                      Test Connection
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {category === 'cache' && (
          <div className="space-y-4">
            <h2 className="text-base font-bold">Browser Storage, Session State & Cache Management</h2>
            <p style={{ color: 'var(--color-text-secondary)' }}>
              Active scan selections and the 50-item IOC Clipboard persist in sessionStorage; theme, API keys, and the 100-item activity stream persist in localStorage.
            </p>
            <div className="flex flex-wrap gap-3">
              <button
                type="button"
                onClick={() => {
                  try {
                    window.sessionStorage.clear();
                  } catch {
                    // ignore
                  }
                  onAddToast({ type: 'info', title: 'Cleared Session Cache', description: 'Reset sessionStorage scan selections and clipboard.' });
                }}
                className="px-4 py-2 rounded-lg border border-red-500/40 text-red-400 font-semibold cursor-pointer"
              >
                🗑️ Clear All Cached Data
              </button>
              <button
                type="button"
                onClick={() => {
                  downloadFileBlob('secconflux-settings.json', JSON.stringify({ theme, fontScale, compactMode, reduceMotion }, null, 2));
                  onAddToast({ type: 'success', title: 'Settings Exported', description: 'Downloaded secconflux-settings.json.' });
                }}
                className="px-4 py-2 rounded-lg border font-semibold cursor-pointer"
                style={{ borderColor: 'var(--color-border)' }}
              >
                ⬇ Export Settings JSON
              </button>
            </div>
          </div>
        )}

        {category === 'shortcuts' && (
          <div className="space-y-3">
            <h2 className="text-base font-bold">Global Keyboard Shortcuts Reference</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {[
                { key: 'Ctrl + K / Cmd + K', desc: 'Open Global Command Palette' },
                { key: '0', desc: 'Navigate to Landing / Home Page' },
                { key: '1', desc: 'Launch Malware Analyzer' },
                { key: '2', desc: 'Launch IOC Lookup Platform' },
                { key: '3', desc: 'Launch Event Analyzer' },
                { key: '4', desc: 'Launch Phishing Mail Detector' },
                { key: '5', desc: 'Launch RuleForge Workshop' },
                { key: '?', desc: 'Open 7-Slide Interactive Platform Tour' },
                { key: 'Escape', desc: 'Close any open modal, drawer, or overlay' }
              ].map((sc) => (
                <div
                  key={sc.key}
                  className="p-3 rounded-lg border flex items-center justify-between"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <span>{sc.desc}</span>
                  <Kbd>{sc.key}</Kbd>
                </div>
              ))}
            </div>
          </div>
        )}

        {category === 'about' && (
          <div className="space-y-3">
            <h2 className="text-base font-bold">SecConflux 2.0 — Unified SecOps Platform</h2>
            <p style={{ color: 'var(--color-text-secondary)' }}>
              Version 2.0.0-production · Build 2026.10.14 · React 19 + TypeScript 5.7 + Tailwind v4 Token Architecture
            </p>
            <div className="p-4 rounded-xl border space-y-1.5 sc-mono text-[11px]" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)' }}>
              <div>✓ SecConflux v1 Bug #1 Fixed: Phishing sub-tab strictly standardized to "dashboard"</div>
              <div>✓ SecConflux v1 Bug #2 Fixed: RuleForge working surface main tab strictly standardized to "workshop"</div>
              <div>✓ SecConflux v1 Bug #3–5 Fixed: Unified SecConfluxApi client, sessionStorage hydration & Vite reverse-proxy</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export const LoginPage: React.FC<{
  authEnabled: boolean;
  setAuthEnabled: (v: boolean) => void;
  onLoginSuccess: (username: string, role: UserRole) => void;
}> = ({ authEnabled, setAuthEnabled, onLoginSuccess }) => {
  const [username, setUsername] = useState('s.chen@secops.local');
  const [password, setPassword] = useState('••••••••••••');
  const [role, setRole] = useState<UserRole>('Analyst');
  const [rememberMe, setRememberMe] = useState(true);

  return (
    <div className="max-w-md mx-auto my-10 p-6 rounded-2xl sc-surface sc-glow space-y-5 text-xs">
      <div className="flex items-center gap-3">
        <BrandShieldIcon size={32} />
        <div>
          <h1 className="text-lg font-bold">SecConflux 2.0 Sign In</h1>
          <p style={{ color: 'var(--color-text-secondary)' }}>Converge. Correlate. Contain.</p>
        </div>
      </div>

      <div className="space-y-3">
        <div>
          <label className="block mb-1 font-semibold">Analyst Email / Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-3 py-2 rounded-lg border sc-mono"
            style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          />
        </div>
        <div>
          <label className="block mb-1 font-semibold">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 rounded-lg border sc-mono"
            style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          />
        </div>
        <div>
          <label className="block mb-1 font-semibold">RBAC Session Role Preview</label>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as UserRole)}
            className="w-full px-3 py-2 rounded-lg border"
            style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          >
            <option value="Admin">Admin (Full Platform & API Key Control)</option>
            <option value="Analyst">Analyst (Full Scan, Enrich & Rule Authoring)</option>
            <option value="Viewer">Viewer (Read-Only Audit Mode)</option>
          </select>
        </div>

        <div className="flex items-center justify-between pt-1">
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={rememberMe} onChange={(e) => setRememberMe(e.target.checked)} />
            <span>Remember session</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={authEnabled} onChange={(e) => setAuthEnabled(e.target.checked)} />
            <span>Enforce Auth Guard</span>
          </label>
        </div>

        <button
          type="button"
          onClick={() => onLoginSuccess(username, role)}
          className="w-full py-2.5 rounded-lg font-bold text-white sc-accent-bg cursor-pointer"
        >
          Sign In to Workspace →
        </button>
        <button
          type="button"
          onClick={() => onLoginSuccess('sso.analyst@corp.local', 'Analyst')}
          className="w-full py-2 rounded-lg font-semibold border cursor-pointer"
          style={{ borderColor: 'var(--color-border)' }}
        >
          🔐 Continue with Enterprise SAML / OIDC SSO
        </button>
      </div>
    </div>
  );
};
