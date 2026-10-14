# 🛡️ SecConflux Suite (Combined Project)

> **Unified Cybersecurity Operations & Threat Intelligence Ecosystem**  
> Consolidating 5 enterprise-grade security tools and a cohesive React 19 / TypeScript / Tailwind CSS unified platform.

---

## 📂 Repository Architecture

```
Combined Project/
├── secconflux/               # 🌐 Unified SecOps Platform (SecConflux 2.0 SPA)
│   ├── src/App.tsx           # Full Command Center & 5-Tool Integrated Shell
│   ├── run (2).py            # Zero-dependency Reverse Proxy Gateway
│   └── package.json          # Vite + React 19 + TypeScript
│
├── Malware Analyzer/         # 🔬 Multi-Format Binary Triage & Threat Intel
│   ├── run.py                # Flask + Socket.IO Backend Server
│   ├── modules/              # PE, ELF, Mach-O, APK, Office, PDF, YARA Engine
│   └── ui/                   # Dark-themed Single Page Application
│
├── ioc-platform/             # 🔍 Threat Intelligence Aggregator & Enrichment
│   ├── app/backend/          # FastAPI Async Engine + 33 Intel Adapters
│   └── ui/                   # React 19 + Vite + D3 Relationship Graph
│
├── Event-Analyzer/           # 📋 Windows EVTX Log Viewer & Threat Hunter
│   ├── app/                  # Rust pyevtx Parser, FTS5 Indexer, Sigma Matcher
│   └── run.py                # Flask Application Server
│
├── Phishing-Mail-Detector/   # 🎣 RFC 822 Email Forensics & Triage
│   ├── core/                 # 11-Stage Pipeline, Auth Matrix, Attachment Scanner
│   └── run.py                # Flask Async Task Server
│
└── RuleForge/                # ⚒️ Cross-Dialect SIEM Detection Engineering
    ├── ruleforge/            # 8 SIEM Dialects (Sentinel, Splunk, Sigma, QRadar, etc.)
    └── ruleforge/__main__.py # Zero-dependency Python Engine & Web Workbench
```

---

## 🚀 The 5 Security Engines

| Engine | Technology | Primary Capability | Default Port |
| :--- | :--- | :--- | :--- |
| **🔬 Malware Analyzer** | Python, Flask, Socket.IO, YARA, pefile | In-memory binary dissection (PE, ELF, Mach-O, APK, Office) with 812+ YARA rules and cloud sandbox fusion | `5000` |
| **🔍 IOC Lookup Platform** | Python, FastAPI, React 19, D3.js | 33+ threat feeds, weighted consensus scoring, 31 IOC types, force-directed relationship graph | `8000` |
| **📋 Event Analyzer** | Python, Flask, Rust `pyevtx-rs`, SQLite FTS5 | Sub-second Windows EVTX indexing, full-text search, Sigma rule detection, MITRE ATT&CK mapping | `5001` |
| **🎣 Phishing Mail Detector** | Python, Flask, BeautifulSoup, oletools | 11-stage forensic email analysis, SPF/DKIM/DMARC alignment, MTA hop path, attachment sandboxing | `5002` |
| **⚒️ RuleForge** | Pure Python 3.10+ (Standard Library Only) | Vendor-neutral detection rules, lossless translation across 8 SIEM query languages, 3-valued evaluation | `8765` |

---

## 🌐 Unified SecConflux 2.0 Platform

The `secconflux` directory provides the single-pane-of-glass workspace uniting all 5 engines:
- **Unified Command Center Dashboard (`#/dashboard`)**: Real-time aggregated threat posture, active alerts, and recent activities.
- **Cross-Tool Pivoting**: Seamlessly pivot any indicator (IP, Domain, Hash) between Malware Analyzer, IOC Lookup, Event Analyzer, and Phishing Detector.
- **Shared IOC Clipboard**: Collect indicators across investigations and bulk-enrich with one click.
- **Dark/Light Mode & Dynamic Tool Accents**: Custom theme transitions per active security tool.

### Running SecConflux 2.0
```bash
# 1. Install dependencies and start Vite dev server
cd secconflux
npm install
npm run dev

# 2. Or start the production reverse-proxy gateway
python "run (2).py"
```

---

## 🔒 Security & Privacy Notice
All sensitive artifacts, environment credentials (`.env`), cache stores (`.cache`, `__pycache__`), raw sqlite databases, and temporary archives are strictly excluded via `.gitignore`.
