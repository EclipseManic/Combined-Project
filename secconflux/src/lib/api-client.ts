
// ============================================================================
// 4. SAFE STORAGE, CLIPBOARD & UNIFIED API CLIENT (Sections 19 & 20)
// ============================================================================
function safeLocalGet<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function safeLocalSet(key: string, value: unknown): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Ignore quota or sandboxed iframe storage blocks
  }
}

function safeSessionGet<T>(key: string, fallback: T): T {
  try {
    const raw = window.sessionStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function safeSessionSet(key: string, value: unknown): void {
  try {
    window.sessionStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Ignore quota or sandboxed iframe storage blocks
  }
}

function copyTextToClipboard(text: string, onDone?: () => void): void {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        if (onDone) onDone();
      }).catch(() => {
        fallbackCopy(text, onDone);
      });
      return;
    }
  } catch {
    // Fallback below
  }
  fallbackCopy(text, onDone);
}

function fallbackCopy(text: string, onDone?: () => void): void {
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  } catch {
    // Ignore if blocked
  }
  if (onDone) onDone();
}

function downloadFileBlob(filename: string, content: string, mimeType = 'application/json'): void {
  try {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch {
    // Fallback handled via toast
  }
}

// Unified API Client (Section 20) — Supports Live Proxy Mode & Fixture Mode
export class SecConfluxApiClient {
  public useFixtures: boolean = safeLocalGet('secconflux.useFixtures', true);
  public backends: Record<ToolId, { baseUrl: string; port: number; type: 'rest' | 'sse' | 'websocket' }> = safeLocalGet('secconflux.backends', {
    malware: { baseUrl: 'http://127.0.0.1:5000', port: 5000, type: 'websocket' },
    ioc: { baseUrl: 'http://127.0.0.1:8000', port: 8000, type: 'sse' },
    events: { baseUrl: 'http://127.0.0.1:5001', port: 5001, type: 'rest' },
    phishing: { baseUrl: 'http://127.0.0.1:5002', port: 5002, type: 'rest' },
    ruleforge: { baseUrl: 'http://127.0.0.1:8765', port: 8765, type: 'rest' }
  });

  async healthCheck(tool: ToolId): Promise<{ status: 'online' | 'offline'; latencyMs: number; mode: 'fixture' | 'live'; version: string }> {
    const versions: Record<ToolId, string> = {
      malware: '2.4.1-flask-yara',
      ioc: '3.1.0-fastapi-sse',
      events: '2.2.0-evtx-fts5',
      phishing: '2.0.8-rfc822-ml',
      ruleforge: '1.9.4-ir-3val'
    };
    if (this.useFixtures) {
      return { status: 'online', latencyMs: 12 + Math.floor(Math.random() * 18), mode: 'fixture', version: versions[tool] };
    }
    const start = performance.now();
    try {
      const endpoint = [this.backends[tool].baseUrl, '/api/health'].join('');
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2500);
      const res = await fetch(endpoint, { signal: controller.signal });
      clearTimeout(timer);
      if (res.ok) {
        return { status: 'online', latencyMs: Math.round(performance.now() - start), mode: 'live', version: versions[tool] };
      }
    } catch {
      // Fall back gracefully
    }
    return { status: 'offline', latencyMs: Math.round(performance.now() - start), mode: 'live', version: versions[tool] };
  }
}

export const apiClient = new SecConfluxApiClient();

// ============================================================================
// 5. CUSTOM INLINE SVG ICON SYSTEM (Section 1 & 2 — Zero External Icon Deps)
// ============================================================================
export const BrandShieldIcon: React.FC<{ className?: string; size?: number }> = ({ className = '', size = 24 }) => (
  <svg width={size} height={size} viewBox="0 0 32 32" fill="none" className={className} aria-hidden="true">
    <defs>
      <linearGradient id="scShieldGrad" x1="0" y1="0" x2="32" y2="32" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stopColor="var(--accent-from)" />
        <stop offset="100%" stopColor="var(--accent-to)" />
      </linearGradient>
    </defs>
    <path d="M16 2.5L4.5 7.2V15.8C4.5 23.1 9.4 29.4 16 31.5C22.6 29.4 27.5 23.1 27.5 15.8V7.2L16 2.5Z" stroke="url(#scShieldGrad)" strokeWidth="2.2" fill="rgba(99,102,241,0.10)" />
    {/* 5 converging streams into central nexus */}
    <path d="M8 10L16 16M24 10L16 16M7 18L16 16M25 18L16 16M16 26L16 16" stroke="url(#scShieldGrad)" strokeWidth="1.7" strokeLinecap="round" />
    <circle cx="16" cy="16" r="3.2" fill="url(#scShieldGrad)" />
  </svg>
);

export const ToolIcon: React.FC<{ tool: ToolId | 'home' | 'dashboard'; size?: number; className?: string }> = ({ tool, size = 18, className = '' }) => {
  switch (tool) {
    case 'malware':
      // Microscope / Binary Dissection Icon
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
          <path d="M6 18h8" />
          <path d="M3 21h18" />
          <path d="M14 21v-4a2 2 0 0 0-2-2H9" />
          <path d="M14 7l-3.5 3.5" />
          <rect x="12" y="2" width="6" height="6" rx="1" transform="rotate(45 15 5)" />
          <path d="M14 11a5 5 0 0 1 5 5v2" />
        </svg>
      );
    case 'ioc':
      // Magnifying Glass with Crosshair Icon
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
          <circle cx="10.5" cy="10.5" r="7.5" />
          <path d="M21 21l-5.2-5.2" />
          <path d="M10.5 6.5v8M6.5 10.5h8" />
          <circle cx="10.5" cy="10.5" r="2" />
        </svg>
      );
    case 'events':
      // Log / Timeline Scroll Icon
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
          <rect x="3" y="3" width="18" height="18" rx="2.5" />
          <path d="M7 8h3M13 8h4M7 12h2M12 12h5M7 16h4M14 16h3" />
        </svg>
      );
    case 'phishing':
      // Email Shield / Hook-Catch Icon
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
          <rect x="2" y="4" width="20" height="16" rx="2.5" />
          <path d="M22 7l-10 6L2 7" />
          <path d="M16 15a2.5 2.5 0 0 0 5 0v-3" />
        </svg>
      );
    case 'ruleforge':
      // Anvil / Hammer-on-Code Icon
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
          <path d="M14.5 4.5l5 5-9.5 9.5-5-5 9.5-9.5z" />
          <path d="M4 20h16" />
          <path d="M12 3L9 6" />
          <path d="M18 12l3-3" />
        </svg>
      );
    case 'dashboard':
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
          <rect x="3" y="3" width="7" height="9" rx="1.5" />
          <rect x="14" y="3" width="7" height="5" rx="1.5" />
          <rect x="14" y="12" width="7" height="9" rx="1.5" />
          <rect x="3" y="16" width="7" height="5" rx="1.5" />
        </svg>
      );
    default:
      return <BrandShieldIcon size={size} className={className} />;
  }
};

// ============================================================================
// 6. SHARED UI COMPONENT LIBRARY (Section 22 — src/ui/ components)
// ============================================================================
export const Kbd: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <kbd
    className="sc-mono inline-flex items-center justify-center px-1.5 py-0.5 text-[11px] font-medium rounded border"
    style={{
      backgroundColor: 'var(--color-surface-raised)',
      borderColor: 'var(--color-border)',
      color: 'var(--color-text-secondary)'
    }}
  >
    {children}
  </kbd>
);

export const VerdictBadge: React.FC<{ verdict: VerdictType | string; label?: string; size?: 'sm' | 'md' | 'lg' }> = ({
  verdict,
  label,
  size = 'sm'
}) => {
  const norm = verdict.toLowerCase();
  let color = 'var(--color-unknown)';
  let bg = 'var(--color-unknown-bg)';
  let text = label || verdict.toUpperCase();

  if (norm === 'malicious' || norm === 'critical' || norm === 'unsafe' || norm === 'fail') {
    color = 'var(--color-malicious)';
    bg = 'var(--color-malicious-bg)';
    if (!label && norm === 'malicious') text = 'MALICIOUS';
  } else if (norm === 'suspicious' || norm === 'medium' || norm === 'high' || norm === 'cautious' || norm === 'mismatch' || norm === 'no_match') {
    color = 'var(--color-suspicious)';
    bg = 'var(--color-suspicious-bg)';
  } else if (norm === 'clean' || norm === 'low' || norm === 'safe' || norm === 'pass' || norm === 'matched' || norm === 'match') {
    color = 'var(--color-clean)';
    bg = 'var(--color-clean-bg)';
  } else if (norm === 'info' || norm === 'informational') {
    color = 'var(--color-info)';
    bg = 'var(--color-info-bg)';
  }

  const padding = size === 'lg' ? 'px-3 py-1 text-xs' : size === 'md' ? 'px-2.5 py-0.5 text-xs' : 'px-2 py-0.5 text-[11px]';

  return (
    <span
      className={`sc-mono inline-flex items-center gap-1.5 font-semibold rounded-full uppercase tracking-wider ${padding}`}
      style={{ color, backgroundColor: bg, border: `1px solid ${color}` }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />
      {text}
    </span>
  );
};

export const ScoreRing: React.FC<{ score: number; max?: number; size?: number; label?: string }> = ({
  score,
  max = 100,
  size = 80,
  label
}) => {
  const ratio = Math.max(0, Math.min(1, score / max));
  const pct = Math.round(ratio * 100);
  const strokeWidth = size >= 100 ? 8 : 6;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - ratio * circumference;

  let strokeColor = 'var(--color-clean)';
  if (pct >= 70) strokeColor = 'var(--color-malicious)';
  else if (pct >= 20) strokeColor = 'var(--color-suspicious)';

  return (
    <div className="relative inline-flex items-center justify-center shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke="var(--color-border)"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke={strokeColor}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 350ms cubic-bezier(0.16, 1, 0.3, 1)' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className="sc-mono font-bold text-sm leading-none" style={{ color: strokeColor }}>
          {score}
          <span className="text-[10px] opacity-70">/{max}</span>
        </span>
        {label && (
          <span className="text-[9px] uppercase tracking-wider mt-0.5" style={{ color: 'var(--color-text-secondary)' }}>
            {label}
          </span>
        )}
      </div>
    </div>
  );
};

export const Sparkline: React.FC<{ values: number[]; color?: string }> = ({ values, color = 'var(--accent-from)' }) => {
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const range = Math.max(max - min, 1);
  const width = 104;
  const height = 30;
  const coords = values.map((v, idx) => {
    const x = (idx / Math.max(values.length - 1, 1)) * (width - 8) + 4;
    const y = height - 4 - ((v - min) / range) * (height - 8);
    return { x, y };
  });
  const pts = coords.map((c) => `${c.x.toFixed(1)},${c.y.toFixed(1)}`).join(' ');
  const areaPts = `4,${height - 2} ${pts} ${width - 4},${height - 2}`;
  const last = coords[coords.length - 1] || { x: width - 4, y: height / 2 };

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="overflow-visible" aria-hidden="true">
      <polygon fill={color} fillOpacity="0.16" points={areaPts} />
      <polyline fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" points={pts} />
      <circle cx={last.x} cy={last.y} r="3" fill={color} className="animate-pulse" />
    </svg>
  );
};

export const CopyKV: React.FC<{
  label: string;
  value: string;
  mono?: boolean;
  onCopy?: (val: string) => void;
  onPivot?: (val: string) => void;
  pivotLabel?: string;
}> = ({ label, value, mono = true, onCopy, onPivot, pivotLabel }) => (
  <div
    className="flex items-center justify-between gap-3 py-2 px-3 rounded-md border text-xs"
    style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
  >
    <span className="font-medium shrink-0" style={{ color: 'var(--color-text-secondary)' }}>
      {label}
    </span>
    <div className="flex items-center gap-2 min-w-0">
      <span className={`${mono ? 'sc-mono' : ''} truncate select-all`} style={{ color: 'var(--color-text-primary)' }} title={value}>
        {value}
      </span>
      {onCopy && (
        <button
          type="button"
          onClick={() => onCopy(value)}
          className="px-1.5 py-0.5 rounded text-[10px] font-medium border hover:opacity-90 shrink-0"
          style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}
          title="Copy value"
        >
          Copy
        </button>
      )}
      {onPivot && (
        <button
          type="button"
          onClick={() => onPivot(value)}
          className="px-1.5 py-0.5 rounded text-[10px] font-semibold shrink-0 sc-accent-bg"
          style={{ color: '#ffffff' }}
        >
          {pivotLabel || 'Pivot →'}
        </button>
      )}
    </div>
  </div>
);

export const Modal: React.FC<{
  open: boolean;
  title: string;
  subtitle?: string;
  onClose: () => void;
  maxWidth?: string;
  children: React.ReactNode;
}> = ({ open, title, subtitle, onClose, maxWidth = 'max-w-xl', children }) => {
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onClick={onClose}
    >
      <div
        className={`w-full ${maxWidth} rounded-xl sc-surface-raised sc-modal-enter shadow-2xl overflow-hidden`}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          className="flex items-center justify-between px-5 py-3.5 border-b"
          style={{ borderColor: 'var(--color-border)' }}
        >
          <div>
            <h3 className="text-base font-semibold" style={{ color: 'var(--color-text-primary)' }}>
              {title}
            </h3>
            {subtitle && (
              <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-secondary)' }}>
                {subtitle}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="w-7 h-7 rounded-lg flex items-center justify-center text-sm hover:opacity-80"
            style={{ backgroundColor: 'var(--color-surface)', color: 'var(--color-text-secondary)' }}
            aria-label="Close modal"
          >
            ✕
          </button>
        </div>
        <div className="p-5 max-h-[80vh] overflow-y-auto">{children}</div>
      </div>
    </div>
  );
};

export const ToolOverviewTemplate: React.FC<{
  tool: ToolDefinition;
  stats: { label: string; value: string }[];
  doesList: string[];
  doesNotList: string[];
  terminalTitle: string;
  terminalOutput: string;
  ctaLabel: string;
  onStart: () => void;
}> = ({ tool, stats, doesList, doesNotList, terminalTitle, terminalOutput, ctaLabel, onStart }) => (
  <div className="space-y-6 max-w-6xl mx-auto">
    <div className="rounded-xl p-6 sc-surface sc-glow relative overflow-hidden">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        <div className="space-y-2 max-w-2xl">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-semibold sc-accent-bg text-white">
            <ToolIcon tool={tool.id} size={14} />
            <span>{tool.name} Engine</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight">{tool.tagline}</h1>
          <p className="text-sm leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
            {tool.description}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={onStart}
            className="px-5 py-2.5 rounded-lg text-sm font-semibold text-white sc-accent-bg shadow-lg hover:opacity-95 transition cursor-pointer"
          >
            {ctaLabel}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6">
        {stats.map((st, i) => (
          <div
            key={i}
            className="p-3.5 rounded-lg border"
            style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
          >
            <div className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
              {st.label}
            </div>
            <div className="sc-mono text-lg font-bold mt-1">{st.value}</div>
          </div>
        ))}
      </div>
    </div>

    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
      <div className="rounded-xl p-5 sc-surface space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--color-clean)' }}>
          ✓ What {tool.shortName} Does
        </h2>
        <ul className="space-y-2 text-xs leading-relaxed" style={{ color: 'var(--color-text-primary)' }}>
          {doesList.map((item, idx) => (
            <li key={idx} className="flex items-start gap-2">
              <span style={{ color: 'var(--color-clean)' }}>●</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="rounded-xl p-5 sc-surface space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--color-suspicious)' }}>
          ⚠ Operational Scope & Guardrails (What It Does NOT Do)
        </h2>
        <ul className="space-y-2 text-xs leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
          {doesNotList.map((item, idx) => (
            <li key={idx} className="flex items-start gap-2">
              <span style={{ color: 'var(--color-suspicious)' }}>●</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>

    <div className="rounded-xl overflow-hidden sc-surface">
      <div
        className="flex items-center justify-between px-4 py-2.5 border-b text-xs sc-mono"
        style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
      >
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
          <span className="ml-2" style={{ color: 'var(--color-text-secondary)' }}>
            {terminalTitle}
          </span>
        </div>
        <span style={{ color: 'var(--color-text-tertiary)' }}>READ-ONLY SAMPLE TELEMETRY</span>
      </div>
      <pre
        className="p-4 text-xs sc-mono overflow-x-auto leading-relaxed"
        style={{ backgroundColor: 'var(--color-canvas)', color: 'var(--color-text-primary)' }}
      >
        {terminalOutput}
      </pre>
    </div>
  </div>
);
