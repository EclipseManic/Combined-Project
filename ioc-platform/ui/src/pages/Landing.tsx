import type { NavigateEvent, Page, Tool } from "../App";
import { DISPLAY_CLEAN, DISPLAY_SUSPICIOUS, DISPLAY_MALICIOUS } from "../lib/thresholds";

const STATS = [
  { value: "20+", label: "Threat Intel Sources" },
  { value: "10", label: "IOC Types" },
  { value: "812+", label: "YARA Rules" },
  { value: "3", label: "Verdict Tiers" },
  { value: "100", label: "Batch IOCs" },
];

const FEATURES = [
  {
    title: "Multi-Source Lookup",
    desc: "Query 20+ public threat-intel feeds in one pass — reputation, tags, and raw evidence per source, with a consensus verdict.",
    tags: ["IP", "Domain", "Hash", "URL", "Email", "CVE"],
    accent: "#facc15",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
        <circle cx="11" cy="11" r="7" />
        <path d="M21 21l-4.3-4.3" />
      </svg>
    ),
  },
  {
    title: "Deep Enrichment",
    desc: "WHOIS, SSL certificates, RDNS, GeoIP, ASN ownership, subdomains, and MITRE ATT&CK mapping layered on top of reputation.",
    tags: ["WHOIS", "GeoIP", "ASN", "ATT&CK"],
    accent: "#f97316",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
        <path d="M12 2L2 7l10 5 10-5-10-5z" />
        <path d="M2 17l10 5 10-5" />
        <path d="M2 12l10 5 10-5" />
      </svg>
    ),
  },
  {
    title: "Consensus Verdict",
    desc: "Independent engines vote per IOC type, and a weighted scoring model turns the votes into a confident 0-100 verdict.",
    tags: ["Scoring", "Voting", "0-100"],
    accent: "#22d3ee",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
        <path d="M12 2l3 6 6 .9-4.5 4.3 1 6.3-5.5-3-5.5 3 1-6.3L3 8.9 9 8z" />
      </svg>
    ),
  },
  {
    title: "Batch Processing",
    desc: "Analyze up to 100 IOCs at once — paste a list or upload CSV/JSON — with per-indicator results and one-click JSON export.",
    tags: ["CSV", "JSON", "Progress", "Export"],
    accent: "#22c55e",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
        <rect x="3" y="3" width="18" height="18" rx="3" />
        <path d="M8 12h8M12 8v8" />
      </svg>
    ),
  },
  {
    title: "Investigation Cases",
    desc: "Group related IOCs into persistent investigation cases, annotate each indicator with notes, and revisit them anytime.",
    tags: ["Cases", "Notes", "History"],
    accent: "#ec4899",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
        <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
      </svg>
    ),
  },
  {
    title: "Interlinked Graph",
    desc: "Co-occurring hashes, domains, and IPs form a relationship graph — follow the infrastructure, not just the indicator.",
    tags: ["Graph", "Infra", "D3"],
    accent: "#a855f7",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
        <circle cx="6" cy="6" r="3" />
        <circle cx="18" cy="7" r="3" />
        <circle cx="8" cy="18" r="3" />
        <path d="M8.8 7.8L15.2 6.4M7 8.9L8.5 15M14 9l1 4.5" />
      </svg>
    ),
  },
];

const TIERS = [
  { name: "Clean", range: `0-${DISPLAY_CLEAN - 1}`, desc: "No meaningful malicious signal across the evaluated sources.", color: "var(--color-verdict-clean)" },
  { name: "Suspicious", range: `${DISPLAY_CLEAN}-${DISPLAY_SUSPICIOUS - 1}`, desc: "Some signals present — verify context or corroborate with additional sources.", color: "var(--color-verdict-suspicious)" },
  { name: "Malicious", range: `${DISPLAY_SUSPICIOUS}-100`, desc: `Weighted consensus of independent engines flags this indicator; scores of ${DISPLAY_MALICIOUS}+ carry high confidence.`, color: "var(--color-verdict-malicious)" },
];

const WORKFLOW = [
  { step: "01", title: "Lookup", desc: "Enter any IOC — IP, domain, hash, URL, email, or CVE." },
  { step: "02", title: "Enrich", desc: "20+ sources run in parallel and are layered with deep enrichment." },
  { step: "03", title: "Investigate", desc: "Consensus verdict, evidence, relationships, and ATT&CK context." },
  { step: "04", title: "Export", desc: "Download JSON, save history, or group IOCs into investigation cases." },
];

function navigateTo(page: Page, tool?: Tool | null) {
  window.dispatchEvent(new CustomEvent<NavigateEvent>("navigate", { detail: { page, tool: tool ?? null } }));
}

export default function Landing() {
  return (
    <div className="page-enter">
      {/* â•â•â• HERO â•â•â• */}
      <section className="relative overflow-hidden rounded-xl border border-border bg-bg-secondary/40">
        <div className="hero-grid-bg" aria-hidden="true" />
        <div className="hero-radial" aria-hidden="true" />
        <div className="relative z-10 max-w-6xl mx-auto px-6 pt-20 pb-16 grid lg:grid-cols-2 gap-12 items-center">
          <div className="hero-fade-up">
            <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-border bg-bg-elevated/60 text-xs font-semibold uppercase tracking-wider text-accent">
              <span className="pulse-ring" aria-hidden="true" />
              Threat Intelligence Platform
            </span>
            <h1 className="mt-6 text-4xl md:text-6xl font-black tracking-tight leading-[1.02] text-text-primary">
              Dissect. Enrich.
              <br />
              <span className="bg-gradient-to-r from-accent to-accent-secondary bg-clip-text text-transparent">
                Defend.
              </span>
            </h1>
            <p className="mt-5 max-w-md text-text-secondary text-lg leading-relaxed">
              Query 20+ threat-intel sources in a single pass — then enrich, correlate, and export the full picture of any IOC.
            </p>
            <div className="mt-8 flex gap-3 flex-wrap">
              <button onClick={() => navigateTo("lookup")} className="glow-btn px-6 py-3 text-sm">
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="w-4 h-4" aria-hidden="true">
                  <circle cx="10" cy="10" r="7" />
                  <path d="M10 7v6M7 10h6" />
                </svg>
                Start Lookup
              </button>
              <button onClick={() => navigateTo("lookup", "history")} className="outline-btn px-6 py-3 text-sm">
                Past Lookups
              </button>
            </div>
          </div>

          {/* Floating terminal preview */}
          <div className="hero-fade-up hidden lg:block" style={{ animationDelay: "0.15s" }} aria-hidden="true">
            <div className="term-float">
              <div className="rounded-xl border border-border overflow-hidden bg-bg-card shadow-[0_24px_60px_rgba(0,0,0,0.45)] rotate-[1.5deg]">
                <div className="term-chrome">
                  <span className="term-dot r" />
                  <span className="term-dot y" />
                  <span className="term-dot g" />
                  <span className="term-title">lookup_result.json</span>
                  <span className="ml-auto text-xs font-bold tracking-wider text-green-400 border border-green-500/40 bg-green-500/10 px-2 py-0.5 rounded-full">
                    LIVE
                  </span>
                </div>
                <div className="p-5 font-mono text-sm leading-[1.9]">
                  <div className="text-text-secondary">{"{"}</div>
                  <div className="pl-4"><span className="text-accent">"input"</span>: <span className="text-green-400">"8.8.8.8"</span>,</div>
                  <div className="pl-4"><span className="text-accent">"verdict"</span>: <span className="text-green-400">"clean"</span>,</div>
                  <div className="pl-4"><span className="text-accent">"score"</span>: <span className="text-amber-300">0.05</span>,</div>
                  <div className="pl-4"><span className="text-accent">"sources"</span>: [</div>
                  <div className="pl-8"><span className="text-green-400">"greynoise"</span>,</div>
                  <div className="pl-8"><span className="text-green-400">"abuse_ipdb"</span>,</div>
                  <div className="pl-8"><span className="text-green-400">"team_cymru"</span></div>
                  <div className="pl-4">],</div>
                  <div className="pl-4"><span className="text-accent">"enrichment"</span>: {"{"} <span className="text-accent">"geoip"</span>: <span className="text-green-400">"US"</span>, <span className="text-accent">"asn"</span>: <span className="text-green-400">"AS15169"</span> {"}"}</div>
                  <div className="text-text-secondary">{"}"}</div>
                  <span className="term-cursor" aria-hidden="true" />
                </div>
                <div className="term-chrome text-xs text-text-secondary border-t border-border bg-bg-secondary">
                  <span className="font-mono">â± 2.4s · 6 engines · 812 YARA rules</span>
                  <span className="ml-auto flex items-center gap-2 font-mono text-green-400">
                    <span className="status-dot" />
                    live
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* â•â•â• STATS BAR â•â•â• */}
      <section className="mt-8 rounded-xl border border-border bg-bg-secondary/60">
        <div className="flex flex-wrap justify-center items-stretch divide-x divide-border">
          {STATS.map((stat, i) => (
            <div key={stat.label} className={`px-8 py-5 text-center ${i > 0 ? "border-l border-border" : ""}`}>
              <div className="stat-num">{stat.value}</div>
              <div className="mt-1 text-xs uppercase tracking-wider text-text-secondary">{stat.label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* â•â•â• CAPABILITIES â•â•â• */}
      <section className="mt-16">
        <div className="text-center mb-10">
          <span className="section-tag">Capabilities</span>
          <h2 className="mt-3 text-3xl md:text-4xl font-extrabold text-text-primary">Built for the analyst's workflow</h2>
          <p className="mt-2 text-text-secondary">From a single IOC to a full investigation — all in one platform.</p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {FEATURES.map((f) => (
            <article
              key={f.title}
              className="feature-card bg-bg-card border border-border rounded-xl p-6"
              style={{ ["--card-accent" as string]: f.accent }}
            >
              <div
                className="w-11 h-11 rounded-lg grid place-items-center mb-4"
                style={{ background: `${f.accent}1f`, color: f.accent }}
              >
                {f.icon}
              </div>
              <h3 className="text-sm font-bold text-text-primary">{f.title}</h3>
              <p className="mt-2 text-sm text-text-secondary leading-relaxed">{f.desc}</p>
              <div className="mt-4 flex flex-wrap gap-2">
                {f.tags.map((t) => (
                  <span
                    key={t}
                    className="text-xs px-2 py-0.5 rounded-full border border-border bg-bg-elevated text-text-secondary font-mono"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </article>
          ))}
        </div>
      </section>

      {/* â•â•â• VERDICT TIERS â•â•â• */}
      <section className="mt-16">
        <div className="text-center mb-10">
          <span className="section-tag">Risk Classification</span>
          <h2 className="mt-3 text-3xl md:text-4xl font-extrabold text-text-primary">Verdicts that mean something</h2>
          <p className="mt-2 text-text-secondary">A weighted 0-100 scale backed by independent engine votes.</p>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {TIERS.map((tier) => (
            <article
              key={tier.name}
              className="tier-card bg-bg-card border border-border rounded-xl p-6 text-center"
              style={{ ["--tier-color" as string]: tier.color }}
            >
              <div className="text-xs font-bold uppercase tracking-widest text-text-secondary">{tier.range}</div>
              <div className="mt-3 text-3xl font-black font-mono" style={{ color: tier.color }}>
                {tier.name}
              </div>
              <p className="mt-3 text-sm text-text-secondary leading-relaxed">{tier.desc}</p>
            </article>
          ))}
        </div>
      </section>

      {/* â•â•â• WORKFLOW â•â•â• */}
      <section className="mt-16 mb-8">
        <div className="text-center mb-10">
          <span className="section-tag">Workflow</span>
          <h2 className="mt-3 text-3xl md:text-4xl font-extrabold text-text-primary">From indicator to decision</h2>
        </div>
        <div className="flex items-start justify-center flex-wrap gap-y-6">
          {WORKFLOW.map((w, i) => (
            <div key={w.step} className="flex items-start">
              <div className="wf-step text-center px-4">
                <div className="wf-num mx-auto">{w.step}</div>
                <h4 className="text-lg font-bold text-text-primary">{w.title}</h4>
                <p className="mt-1.5 text-sm text-text-secondary leading-relaxed max-w-[190px] mx-auto">{w.desc}</p>
              </div>
              {i < WORKFLOW.length - 1 && <div className="wf-connector" aria-hidden="true" />}
            </div>
          ))}
        </div>
      </section>

      {/* â•â•â• CTA â•â•â• */}
      <section className="rounded-xl border border-border bg-bg-secondary/60 py-10 text-center relative overflow-hidden">
        <div className="hero-grid-bg" aria-hidden="true" />
        <div className="hero-radial" aria-hidden="true" />
        <div className="relative z-10">
          <h2 className="text-2xl font-bold text-text-primary">Ready to investigate?</h2>
          <p className="mt-2 text-text-secondary">Search any indicator across 20+ sources right now.</p>
          <button onClick={() => navigateTo("lookup")} className="glow-btn mt-6 px-6 py-3 text-sm">
            Open Lookup
          </button>
        </div>
      </section>
    </div>
  );
}