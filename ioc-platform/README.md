# IOC Lookup Platform

A self-hosted indicator-of-compromise lookup tool. Give it an IP, domain, URL,
email address, phone number, hash, CVE or wallet address and it queries the
threat-intelligence sources you have configured, scores what comes back, and
shows you which sources said what.

It is a single-user tool. It runs on your machine, stores its data in a local
SQLite file, and binds to loopback unless you explicitly change that.

**Status: alpha.** Version 0.2.0. It works and is tested, but it has not been
hardened for hostile networks. Read the limitations below before trusting a
verdict.

---

## Read this before you trust a verdict

These are the things a lookup tool can get wrong, and what this one does about
them.

**"Not found" does not mean "clean".** Most threat-intelligence sources only
know about things someone reported. If a source has never seen an indicator, it
returns nothing — and nothing is not evidence of safety. This tool keeps
*not-found*, *provider errored*, *rate limited* and *no key configured* as
separate states, none of which contribute to the malicious score. A result built
only from not-found responses is reported as `unknown`, not `clean`, and the
review reason says so.

**Absence of a risk flag is not a clean bill.** A residential IP with no VPN,
proxy or abuse flag is reported as `unknown`, not `clean`.

**Coverage is reported, not hidden.** Every result carries a coverage figure and
an expected-providers count. The **Sources** tab lists, per lookup, which
sources were queried, which were not, and why — including keys that are
configured but were never spent.

**Nineteen of the thirty-three sources need an API key.** Without keys you get
fourteen key-free sources and partial coverage. The Sources tab names the exact
environment variable for each source that is applicable and unconfigured, so a
missing key is visible rather than silent.

**Some indicator types have very little coverage.** `phone` is served by exactly
two providers, AbstractAPI Phone Intelligence and IPQualityScore Phone, and
**both need a key**. There is no key-free phone reputation service, so a fresh
clone gets nothing for phone numbers at all. The coverage test in
`tests/test_coverage.py` records this as a known gap rather than passing quietly.

**Free tiers are small.** AbstractAPI allows 100 requests per month, 1 per
second. Expect quota exhaustion, which the tool surfaces as
`monthly_quota_exhausted` and stops retrying rather than hammering.

**Wallet data is scraped, not licensed.** Bitcoin statistics come from
Blockchain.info and Ethereum context from Etherscan's public pages. No fiat
conversion is shown anywhere, because the platform does not fetch a price and a
fixed rate would be wrong within hours.

**Enrichment does not apply to every type.** The backend reports
`completeness: {module: skipped}` for modules that do not apply to an indicator
type. The Enrichment tab says which modules were skipped, unavailable, or ran
and found nothing, instead of rendering an empty panel.

**There is no authentication on the default configuration.** The service binds
to `127.0.0.1` and trusts anything that can reach it. If you need remote access,
see [Exposing it on a network](#exposing-it-on-a-network) — it requires keys and
TLS, and you should put a reverse proxy in front of it.

---

## Quick start

Requires Python 3.11 or newer. Node.js is only needed if you want to change the
frontend.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python run.py
```

The browser opens at <http://127.0.0.1:8000/>. Press `Ctrl+C` to stop.

That works with no API keys at all — you will simply get less coverage.

On macOS or Linux the activation line is `source .venv/bin/activate`.

### Migrations

Migrations run automatically at startup. To run them by hand, or against a
separate database:

```powershell
python -m alembic upgrade head
```

Startup refuses to adopt an unversioned SQLite file whose existing tables are
missing required columns. `alembic downgrade` refuses to run once batch records
exist, because that step drops batch history. Back up `data/ioc_platform.db`
before any downgrade.

---

## What it supports

**31 indicator types:** `ipv4` `ipv6` `domain` `url` `email` `phone` `asn`
`btc` `eth` `cve` `mitre_attack` `md5` `sha1` `sha256` `sha512` `ssdeep` `tlsh`
`mac` `ja3` `ja4` `user_agent` `username` `password` `password_sha1` `filename`
`windows_path` `linux_path` `mutex` `named_pipe` `registry_key` `service_name`

Refanged values are unwrapped automatically, so `hxxp://example[.]com` and
`1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`-style pastes are detected correctly. You
can also force a type with a prefix: `phone:+14152007986`, `msisdn:+44...`,
`tel:+1...`.

---

## Sources

33 registered sources: 14 work without a key, 19 need one. `GET /api/sources`
returns the live list, including which credential each source expects and
whether it is configured. Secret values are never returned.
### No key required

| Source | Covers |
|---|---|
| OpenPhish | URL |
| URLhaus | URL, domain, MD5, SHA-1, SHA-256 |
| Tor Exit | IPv4 |
| IPinfo (lite) | IPv4, IPv6 |
| GreyNoise (community) | IPv4 |
| Shodan InternetDB | IPv4 |
| urlscan.io search | URL, domain |
| StopForumSpam | Email |
| CIRCL HashLookup | MD5, SHA-1, SHA-256 |
| XposedOrNot | Email |
| RDAP, DNS, CRT.sh, Cloudflare DNS | IPs, domains, URLs, email domains |
| CISA KEV, EPSS, NVD | CVE |
| RIPEstat | ASN |
| MITRE ATT&CK | ATT&CK IDs |
| blockchain.info | Bitcoin |
| Etherscan (public pages) | Ethereum |
| Team Cymru | IP, ASN |

### Requires an API key

| Variable | Source | Covers |
|---|---|---|
| `VT_API_KEY` | VirusTotal | Most types |
| `IPQUALITY_API_KEY` | IPQualityScore | Phone, IPv4, IPv6, email |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | IPv4, IPv6 |
| `URL_SCAN_API_KEY` | urlscan.io | Active submissions |
| `MB_AUTH_KEY` | MalwareBazaar | Hashes |
| `THREATFOX_API_KEY` | ThreatFox | IPs, domains, URLs, hashes |
| `URLHAUS_API_KEY` | URLhaus | Higher quota |
| `TRIAGE_API_KEY` | Tria.ge | Host artifacts |
| `HA_API_KEY` | Hybrid Analysis | Host artifacts |
| `GREYNOISE_API_KEY` | GreyNoise | Higher quota |
| `OTX_API_KEY` | AlienVault OTX | Pulses, malware URLs |
| `SHODAN_API_KEY` | Shodan | Full host API |
| `CENSYS_API_KEY` | Censys (`ID:secret`) | Host certificates |
| `IPINFO_API_KEY` | IPinfo | Better geo |
| `NVD_API_KEY` | NVD | Higher CVE quota |
| `ABSTRACTAPI_EMAIL_KEY` | AbstractAPI Email Reputation | Email |
| `ABSTRACTAPI_IP_KEY` | AbstractAPI IP Intelligence | IPv4, IPv6 |
| `ABSTRACTAPI_No_KEY` | AbstractAPI Phone Intelligence | Phone |

> **AbstractAPI issues one key per product.** A key issued for one product is
> rejected by the others with `401 Invalid API key provided`. The three keys
> above are not interchangeable, and each unlocks exactly one adapter. The
> product hostnames are not derivable from the product names
> (`ip-intelligence`, `phoneintelligence`, `emailreputation`), which is why they
> are spelled out in `app/backend/adapters/abstract_api.py`.
>
> **IPQualityScore is the opposite:** one key serves all three of its products
> (phone, IP and email). Two details matter if you add your own adapter for it.
> It answers **HTTP 200 to every error, including a rejected API key**, so the
> `success` field and the `message` text must be inspected rather than the
> status code. And it reports plan limitations by returning `null` fields with a
> nested `"... required."` status string, which the adapter records as
> `ipqs:blocked:<field>` so an unavailable field is never read as "no risk
> found".

See `.env.example` for the complete list.

---

## Configuring keys

`.env` is the primary configuration source; process and system environment
variables are a fallback for anything `.env` does not set. `.env` is gitignored.
Never commit a real key.

A key can be written three ways:

```dotenv
VT_API_KEY=actual_key_here
VT_API_KEY=${MY_VT_KEY}      # explicit reference to another variable
VT_API_KEY=my_vt_key         # bare reference; resolved .env first, then env
```

References resolve through `.env` first, then the process environment. Set
`IOC_ENV_FILE` to load a different file, or to an empty value to disable file
loading entirely — the test suite does this so it never reads real credentials.

**A missing key never stops the app from starting.** The source is reported as
unconfigured, excluded from the score, and named in the Sources tab.

### Application settings

| Variable | Default | Purpose |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind address; keep on loopback |
| `PORT` | `8000` | Bind port |
| `RELOAD` | `false` | Auto-reload the backend on code changes |
| `DATABASE_URL` | SQLite in `data/` | Database location |
| `REDIS_URL` | unset | Shared cache and rate-limit backend |
| `FAIL_FAST_MISSING_KEYS` | `false` | Refuse to start if provider keys are missing or placeholders |
| `ALLOW_NETWORK_BIND` | `false` | Must be `true` to bind anywhere but loopback |
| `API_KEYS` | unset | Required when network binding; comma-separated |
| `BASE_URL` | unset | Required HTTPS base URL when network binding |
| `REQUIRE_NETWORK_TLS` | `true` | Keep TLS enforcement on |
| `TRUST_PROXY` | `false` | Trust forwarded headers, only behind a controlled proxy |
| `TRUSTED_PROXY_HOSTS` | unset | Required when `TRUST_PROXY=true` |
| `TRUSTED_HOSTS` | unset | Optional host allowlist |
| `WEBHOOKS_ENABLED` | `false` | Outbound result webhooks |
| `WEBHOOK_SECRET_KEY` | unset | Required when webhooks are on; encrypts stored secrets |
| `ENABLE_PUBLIC_URL_SUBMISSION` | `false` | Submit URLs to urlscan |
| `ENABLE_URL_CONTENT_FETCH` | `false` | Fetch remote URL content |

---

## Exposing it on a network

Do not skip this section if you bind anywhere but `127.0.0.1`.

1. Put a TLS reverse proxy (nginx, Caddy) in front of the service.
2. Set `ALLOW_NETWORK_BIND=true`, a strong random `API_KEYS`, and an HTTPS
   `BASE_URL`.
3. Leave `REQUIRE_NETWORK_TLS=true`.
4. Set `TRUST_PROXY=true` and `TRUSTED_PROXY_HOSTS` to your proxy's address.
5. Keep `ALLOW_GLOBAL_FEEDBACK=false` unless global analyst feedback is
   intentional.

Interactive API docs at `/docs` switch off automatically once `API_KEYS` is set.

---

## How a verdict is produced

Each source returns a verdict, a score and a confidence. Sources are grouped by
kind — identity and reputation sources carry more weight than context-only
sources such as geolocation — and combined into a weighted score with a stated
confidence. Disagreement between sources lowers confidence rather than averaging
away.

Every result records which sources contributed, which were excluded, and why.
False positives you mark feed back into scoring.

Exports are available as CSV, an HTML report, STIX 2.1, MISP, and SIEM formats
(Splunk, ECS, LEEF).

---

## API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/lookup` | Start a lookup |
| `GET` | `/api/tasks/{task_id}` | Progress |
| `GET` | `/api/tasks/{task_id}/result` | Completed result |
| `POST` | `/api/tasks/{task_id}/cancel` | Cancel a lookup |
| `GET` | `/api/sources` | Source inventory and credential state |
| `GET` | `/api/health` | Application health |
| `GET` | `/api/health/keys` | Credential health per source |
| `GET` | `/api/recent` | Lookup history |
| `GET` | `/api/investigations` | Investigation cases |
| `POST` | `/api/batch` | Batch analysis |
| `GET` | `/api/batches` | Batch list |
| `POST` | `/api/export/csv` | CSV export |
| `POST` | `/api/export/stix` | STIX 2.1 export |
| `POST` | `/api/export/misp` | MISP export |
| `POST` | `/api/export/siem` | Splunk, ECS, LEEF export |
| `POST` | `/api/export/report` | HTML report |
| `POST` | `/api/feedback` | Mark a false positive |

---

## Development

Backend:

```powershell
pip install -r requirements-dev.txt
python -m pytest -q          # 901 tests
pip-audit -r requirements.txt
```

This is the same set of checks CI runs on every push, so a green local run means
a green build. The `frontend` job additionally runs `npm run lint`, which has no
Python equivalent configured.

Frontend:

```powershell
cd ui
npm install
npm test                     # 154 tests
npm run lint
npm run build
```

The frontend build output (`ui/dist/`) is not tracked; `npm run build`
regenerates it. The server serves whatever is currently in that directory.

---

## Project layout

```
app/backend/       FastAPI service
  adapters/        one module per intelligence source
  classifier.py    indicator type detection and normalisation
  scorer.py        weighted verdict combination
  evidence.py      source provenance and evidence strength
  enrichment.py    DNS, WHOIS, TLS, geo, CVE and related context
alembic/           database migrations
ui/src/            React frontend
tests/             Backend tests
```

## License

MIT. See [LICENSE](LICENSE).
