import { useEffect, useState } from "react";

const EXAMPLES = [
  ["IP: 8.8.8.8", "8.8.8.8"],
  ["Domain: eclipsemanic.me", "eclipsemanic.me"],
  ["CVE: Log4j", "CVE-2021-44228"],
  ["Hash: WannaCry", "84c82835a5d21bbcf75a61706d8ab549"],
  ["BTC: WannaCry", "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94"],
  ["Pwned Password", "password"],
];
const MAX_IOC_LENGTH = 2048;
const CREDENTIAL_MARKERS = ["password", "passwd", "secret", "admin", "root", "qwerty", "letmein", "welcome", "login", "auth", "user"];

function looksLikeCredential(value: string): boolean {
  const input = value.trim().toLowerCase();
  if (!input) return false;
  if (/^(?:pass|password):/i.test(input)) return true;
  if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$/.test(input)) return false;
  if (/@|^[a-z0-9.-]+\.[a-z]{2,}$/.test(input)) {
    return CREDENTIAL_MARKERS.some((marker) => input.includes(marker));
  }
  return /^[^\s]{4,128}$/.test(input) && /[A-Z]/.test(input) && /[a-z]/.test(input) && /[\d!@#$%^&*(),.?":{}|<>]/.test(input);
}

function refangIOC(text: string): string {
  return text
    .replace(/\bhxxps?:\/\//gi, (m) => (m.toLowerCase().startsWith("hxxps") ? "https://" : "http://"))
    .replace(/\[\.\]/g, ".")
    .replace(/\(\.\)/g, ".")
    .replace(/\[dot\]/gi, ".")
    .replace(/\[at\]/gi, "@")
    .replace(/\(@\)/g, "@");
}

function detectType(value: string): string | null {
  const input = refangIOC(value.trim());
  if (!input) return null;
  if (/^CVE-\d{4}-\d{4,}$/i.test(input)) return "CVE Vulnerability";
  if (/^0x[a-f\d]{40}$/i.test(input)) return "Ethereum wallet";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(input)) return "IPv4";
  // Anchored IPv6 - must be standalone, not embedded in a URL/domain
  if (/^(?:[0-9a-f]{1,4}:){2,}[0-9a-f:]*$/i.test(input) || input === "::1") return "IPv6";
  if (/^[a-f\d]{32}$/i.test(input)) return "MD5 hash";
  if (/^[a-f\d]{40}$/i.test(input)) return "SHA-1 hash";
  if (/^[a-f\d]{64}$/i.test(input)) return "SHA-256 hash";
  if (/^[a-f\d]{128}$/i.test(input)) return "SHA-512 hash";
  if (/^[\w.+-]+@[\w-]+\.[\w.-]+$/.test(input)) return "Email address";
  if (/^https?:\/\//i.test(input)) return "URL";
  if (/^(?:[a-z\d-]+\.)+[a-z]{2,}$/i.test(input)) return "Domain";
  if (/^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z\d]{38,58})$/i.test(input)) return "Bitcoin wallet";
  if (/^AS\d+$/i.test(input)) return "Autonomous System (ASN)";
  if (/^(?:pass|password):/i.test(input)) return "Password / Credential";
  if (/^(?:user|username):/i.test(input)) return "Username";
  return "Custom / Search";
}

function validateIOC(value: string): string | null {
  if (!value) return "Enter an indicator, hash, wallet, or credential to analyze";
  if (value.length > MAX_IOC_LENGTH) return `Max length ${MAX_IOC_LENGTH} characters`;
  return null;
}

export default function SearchBar({
  onSearch,
  initialValue = "",
  initialType = "",
  disabled = false,
}: {
  onSearch: (value: string, iocType?: string) => void;
  initialValue?: string;
  initialType?: string;
  disabled?: boolean;
}) {
  const [value, setValue] = useState(initialValue);
  const [iocType, setIocType] = useState(initialType === "password_sha1" ? "password" : initialType || "auto");
  const [prehashed, setPrehashed] = useState(initialType === "password_sha1");
  const [showSecret, setShowSecret] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setValue(initialValue);
    setIocType(initialType === "password_sha1" ? "password" : initialType || "auto");
    setPrehashed(initialType === "password_sha1");
  }, [initialType, initialValue]);

  const detected = detectType(value);
  const isCredentialMode = iocType === "password" || detected === "Password / Credential";

  async function handleSubmit() {
    let v = value.trim();
    const err = validateIOC(v);
    if (err) {
      setError(err);
      return;
    }
    setError(null);

    // If explicit pass: or password: prefix, strip it and treat as password
    if (/^(?:pass|password):/i.test(v)) {
      v = v.replace(/^(?:pass|password):/i, "").trim();
    }

    // If explicit user: or username: prefix, strip it and treat as username
    if (/^(?:user|username):/i.test(v)) {
      v = v.replace(/^(?:user|username):/i, "").trim();
      onSearch(v, "username");
      return;
    }

    if (iocType === "auto" && !isCredentialMode && looksLikeCredential(v)) {
      setError("Select an IOC type or Password / Credential for ambiguous input");
      return;
    }

    if (iocType === "auto" && detected === "Custom / Search") {
      setError("Select an IOC type or Password / Credential for ambiguous input");
      return;
    }

    if (iocType === "password" || isCredentialMode) {
      if (prehashed) {
        if (!/^[a-f0-9]{40}$/i.test(v)) {
          setError("Prehashed password must be a 40-character SHA-1 digest");
          return;
        }
        onSearch(v.toLowerCase(), "password_sha1");
        return;
      }
      if (!window.crypto?.subtle) {
        setError("Secure password hashing is unavailable in this browser");
        return;
      }
      try {
        const encoder = new TextEncoder();
        const data = encoder.encode(v);
        const hashBuffer = await window.crypto.subtle.digest("SHA-1", data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const sha1 = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
        onSearch(sha1, "password_sha1");
        return;
      } catch {
        setError("Secure password hashing is unavailable in this browser");
      }
      return;
    }

    // Auto-refang defanged URLs, IPs, domains, and emails
    v = refangIOC(v);

    if (iocType === "auto") {
      onSearch(v);
    } else {
      onSearch(v, iocType);
    }
  }

  return (
    <div role="search" aria-label="IOC lookup" className="w-full">
      <div className="rounded-2xl border border-border bg-bg-card p-2.5 shadow-[0_18px_40px_rgba(0,0,0,0.24)]">
        {/* Detection context banner */}
        <div className="mb-2 flex items-center justify-between px-2 text-xs">
          <div className="flex items-center gap-2">
            <span className="font-semibold uppercase tracking-wider text-text-secondary">Indicator</span>
            {detected && (
              <span className="rounded-full border border-accent/40 bg-accent/10 px-2.5 py-0.5 font-medium text-accent">
                {detected}
              </span>
            )}
            {isCredentialMode && (
              <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-xs font-semibold text-amber-300">
                🔒 Zero-Knowledge HIBP Mode
              </span>
            )}
          </div>
          {isCredentialMode && (
            <button
              type="button"
              onClick={() => setShowSecret((prev) => !prev)}
              className="text-xs font-medium text-text-secondary hover:text-accent transition-colors"
            >
              {showSecret ? "Hide input 🙈" : "Show input ðŸ‘ï¸"}
            </button>
          )}
        </div>

        <div className="flex flex-col gap-2 sm:flex-row">
          <div className="relative min-w-0 flex-1">
            <input
              type={isCredentialMode && !showSecret ? "password" : "text"}
              value={value}
              onChange={(event) => {
                 setValue(event.target.value);
                 setPrehashed(false);
                 if (error) setError(null);
              }}
              onKeyDown={(event) => event.key === "Enter" && handleSubmit()}
              placeholder={
                isCredentialMode
                  ? "Enter password to check for public breach compromise..."
                  : "Paste IP, domain, URL, hash, email, wallet, CVE, or credential..."
              }
              aria-label="Search IOC"
              aria-invalid={!!error}
              aria-describedby={error ? "ioc-search-error" : undefined}
              disabled={disabled}
              maxLength={MAX_IOC_LENGTH}
              className="w-full rounded-xl border border-border bg-bg-secondary px-4 py-3.5 font-mono text-sm text-text-primary outline-none transition-all placeholder:text-text-secondary focus:border-accent focus:ring-1 focus:ring-accent disabled:opacity-50"
            />
          </div>

          <select
            aria-label="IOC type"
            value={iocType}
             onChange={(event) => { setIocType(event.target.value); setPrehashed(false); }}
            disabled={disabled}
            className="rounded-xl border border-border bg-bg-secondary px-3 py-3 text-xs font-medium text-text-secondary sm:w-44 disabled:opacity-50"
          >
            <option value="auto">Auto detect</option>
            <option value="username">👤 Username</option>
            <option value="password">🔑 Password / Credential</option>
            <option value="ipv4">IPv4 Address</option>
            <option value="ipv6">IPv6 Address</option>
            <option value="domain">Domain Name</option>
            <option value="url">Web URL</option>
            <option value="email">Email Address</option>
            <option value="phone">Phone Number</option>
            <option value="md5">MD5 Hash</option>
            <option value="sha1">SHA-1 Hash</option>
            <option value="sha256">SHA-256 Hash</option>
            <option value="btc">Bitcoin (BTC)</option>
            <option value="eth">Ethereum (ETH)</option>
            <option value="cve">CVE Vulnerability</option>
            <option value="asn">Autonomous System (ASN)</option>
          </select>

          <button
            onClick={handleSubmit}
            disabled={disabled}
            aria-label="Submit search"
            className="rounded-xl bg-accent px-5 py-3 text-sm font-bold text-[#06070d] hover:bg-accent/90 transition-colors disabled:opacity-40"
          >
            {disabled ? "Analyzing…" : "Analyze Indicator"}
          </button>
        </div>
      </div>

      {error && (
        <p id="ioc-search-error" className="mt-2 text-xs font-semibold text-verdict-malicious" role="alert">
          {error}
        </p>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-2" role="group" aria-label="Example IOCs">
        <span className="mr-1 text-xs font-semibold uppercase tracking-wider text-text-secondary">
          Examples
        </span>
        {EXAMPLES.map(([label, example]) => (
          <button
            key={example}
            onClick={() => {
               setValue(example);
               setPrehashed(false);
               setError(null);
              if (example === "password") {
                setIocType("password");
                // Don't call onSearch directly - let user click "Analyze Indicator"
                // so the client-side SHA-1 hashing flow runs correctly
              } else {
                onSearch(example);
              }
            }}
            disabled={disabled}
            className="rounded-full border border-border bg-bg-elevated px-3 py-1.5 font-mono text-xs text-text-secondary hover:border-accent/60 hover:text-accent transition-colors disabled:opacity-50"
          >
            {label}
          </button>
        ))}
      </div>
    </div>
  );
}
