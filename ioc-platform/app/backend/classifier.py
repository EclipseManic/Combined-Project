import hashlib
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


def refang(text: str) -> str:
    text = re.sub(r"hxxps\[?:\]?//", "https://", text, flags=re.IGNORECASE)
    text = re.sub(r"hxxp\[?:\]?//", "http://", text, flags=re.IGNORECASE)
    text = re.sub(r"\[\.\]", ".", text)
    text = re.sub(r"\[:\]", ":", text)
    text = re.sub(r"\\\.", ".", text)
    text = text.replace(r"\@", "@").replace(r"\_", "_")
    return text


def defang(text: str) -> str:
    text = text.replace("http://", "hxxp://")
    text = text.replace("https://", "hxxps://")
    text = text.replace(".", "[.]")
    return text


@dataclass(frozen=True)
class NormalizedIOC:
    value: str
    ioc_type: str
    candidate_types: tuple[str, ...]
    type_confidence: float
    valid: bool

    @property
    def identity_key(self) -> str:
        """Stable key used by deduplication, cache, and persistence."""
        return f"{self.ioc_type}:{self.value}"


COMMON_PASSWORDS = {
    "password", "pass", "admin", "administrator", "root", "toor", "guest", "qwerty",
    "123456", "12345678", "123456789", "12345", "111111", "welcome", "letmein",
    "monkey", "dragon", "master", "sunshine", "princess", "football", "shadow",
    "superman", "trustno1", "iloveyou", "secret", "default", "changeme",
}

KNOWN_SYSTEM_PROCESSES = {
    "svchost", "lsass", "csrss", "services", "explorer", "cmd", "powershell",
    "rundll32", "regsvr32", "vssadmin", "tasklist", "certutil", "bitsadmin",
    "whoami", "net", "net1", "wmic", "mshta", "cscript", "wscript", "conhost",
    "smss", "winlogon", "dwm", "spoolsv", "system", "taskhostw",
}


def password_digest(value: str, *, already_digest: bool = False) -> str:
    normalized = str(value or "").strip()
    if already_digest and re.fullmatch(r"[a-f0-9]{40}", normalized, re.IGNORECASE):
        return normalized.lower()
    return hashlib.sha1(normalized.encode("utf-8")).hexdigest()


def is_password_digest(value: str) -> bool:
    return bool(re.fullmatch(r"[a-f0-9]{40}", str(value or "").strip(), re.IGNORECASE))


def is_password_candidate(text: str) -> bool:
    if not text or len(text) < 4 or len(text) > 128:
        return False
    if any(c in text for c in (" ", "\t", "\r", "\n")):
        return False
    lower = text.lower()
    if lower in COMMON_PASSWORDS:
        return True
    if lower in KNOWN_SYSTEM_PROCESSES:
        return False
    if re.fullmatch(r"[a-f0-9]{16,}", text, re.IGNORECASE):
        return False
    # If it has standard password symbols
    has_symbol = any(c in text for c in "!@#$%^&*+~=?|")
    has_digit = any(c.isdigit() for c in text)
    has_lower = any(c.islower() for c in text)
    has_upper = any(c.isupper() for c in text)
    if has_symbol and (has_digit or has_lower or has_upper):
        return True
    # If mixed case + digits and length >= 6
    if has_upper and has_lower and has_digit and len(text) >= 6:
        return True
    # Common credential pattern like name123, admin2024
    if has_digit and (has_lower or has_upper) and len(text) >= 6 and len(text) <= 32 and not text.isdigit():
        return True
    return False


def normalize_phone(text: str) -> str | None:
    """Canonicalize a phone IOC, or return None when it is not a usable number.

    Formatting characters are dropped so ``+1 (415) 200-7986`` and
    ``+14152007986`` share one cache entry.  A leading ``+`` is preserved
    because it is what makes the country code explicit; bare national numbers
    stay bare rather than being given a ``+`` that was never supplied.
    """
    compact = re.sub(r"[\s().\-‐-―]", "", text)
    if not re.fullmatch(r"\+?\d{7,15}", compact):
        return None
    return compact


def normalize_ioc(value: str, expected_type: str | None = None) -> NormalizedIOC:
    """Deterministically normalize and validate an IOC before planning."""
    raw_str = str(value or "")

    # ── Typed-prefix detection ──────────────────────────────────────────
    # If the caller did not already supply an expected type, check whether
    # the raw value uses the ``type:value`` shorthand (e.g.
    # ``domain:eclipsemanic.me``, ``cve:CVE-2021-44228``).
    if expected_type is None:
        parsed_type, parsed_value = parse_typed_ioc(raw_str)
        if parsed_type is not None:
            expected_type = parsed_type
            raw_str = parsed_value

    if expected_type == "password_sha1":
        candidate = raw_str.strip()
        if re.fullmatch(r"[a-f0-9]{40}", candidate, re.IGNORECASE):
            return NormalizedIOC(candidate.lower(), "password", ("password",), 1.0, True)
        return NormalizedIOC(candidate, "password_sha1", (), 0.0, False)

    # Check for explicit password prefix like pass:secret or password:secret
    if expected_type == "password" or raw_str.lower().startswith(("pass:", "password:")):
        clean_pwd = re.sub(r"^(?:pass|password):", "", raw_str, flags=re.IGNORECASE).strip()
        if clean_pwd and len(clean_pwd) <= 256:
            return NormalizedIOC(clean_pwd, "password", ("password",), 1.0, True)

    # Check for explicit username prefix like user:admin or username:admin
    if expected_type == "username" or raw_str.lower().startswith(("user:", "username:")):
        clean_user = re.sub(r"^(?:user|username):", "", raw_str, flags=re.IGNORECASE).strip()
        if clean_user and len(clean_user) <= 64:
            return NormalizedIOC(clean_user, "username", ("username",), 1.0, True)

    text = refang(raw_str).strip().strip("`'\"<>()[],;")
    if not text:
        return NormalizedIOC("", "unknown", (), 0.0, False)
    if expected_type == "password" and len(text) <= 256:
        return NormalizedIOC(text, "password", ("password",), 1.0, True)
    # For any other explicit expected_type in SUPPORTED_IOC_TYPES, skip the
    # heuristic pattern matching and treat the value as the declared type.
    # The value still gets normalized (case-folding, IP compression, etc.)
    # via the type-specific block below.
    if expected_type and expected_type in SUPPORTED_IOC_TYPES and expected_type not in {"password", "username"}:
        # Apply type-specific normalization without pattern matching.
        if expected_type in {"ipv4", "ipv6"}:
            try:
                addr = ipaddress.ip_address(text)
            except ValueError:
                return NormalizedIOC(text, "unknown", (), 0.0, False)
            text = addr.compressed
            return NormalizedIOC(text, "ipv4" if addr.version == 4 else "ipv6",
                                 ("ipv4" if addr.version == 4 else "ipv6",), 1.0, True)
        elif expected_type == "domain":
            try:
                candidate = text.rstrip(".").encode("idna").decode("ascii").lower()
            except (UnicodeError, UnicodeDecodeError):
                return NormalizedIOC(text, "domain", (), 0.0, False)
            if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", candidate):
                return NormalizedIOC(text, "domain", (), 0.0, False)
            return NormalizedIOC(candidate, "domain", ("domain",), 1.0, True)
        elif expected_type in {"md5", "sha1", "sha256", "sha512"}:
            hash_lengths = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
            if not re.fullmatch(rf"[0-9a-f]{{{hash_lengths[expected_type]}}}", text, re.IGNORECASE):
                return NormalizedIOC(text, expected_type, (), 0.0, False)
            text = text.lower()
            return NormalizedIOC(text, expected_type, (expected_type,), 1.0, True)
        elif expected_type == "cve":
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE):
                return NormalizedIOC(text, "cve", (), 0.0, False)
            text = text.upper()
            return NormalizedIOC(text, "cve", ("cve",), 1.0, True)
        elif expected_type == "email":
            local, _, domain = text.rpartition("@")
            if not local or not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+", text, re.IGNORECASE):
                return NormalizedIOC(text, "email", (), 0.0, False)
            text = f"{local}@{domain.lower().rstrip('.')}"
            return NormalizedIOC(text, "email", ("email",), 1.0, True)
        elif expected_type == "url":
            try:
                parsed = urlsplit(text)
                _ = parsed.port
            except ValueError:
                return NormalizedIOC(text, "url", (), 0.0, False)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None or any(char.isspace() for char in text):
                return NormalizedIOC(text, "url", (), 0.0, False)
            return NormalizedIOC(text, "url", ("url",), 1.0, True)
        elif expected_type == "asn":
            if not re.fullmatch(r"(?:AS)?\d+", text, re.IGNORECASE):
                return NormalizedIOC(text, "asn", (), 0.0, False)
            text = "AS" + re.sub(r"^AS", "", text, flags=re.IGNORECASE)
            return NormalizedIOC(text, "asn", ("asn",), 1.0, True)
        elif expected_type == "phone":
            compact = normalize_phone(text)
            if compact is None:
                return NormalizedIOC(text, "phone", (), 0.0, False)
            return NormalizedIOC(compact, "phone", ("phone",), 1.0, True)
        else:
            # For btc, eth, mac, filename, mutex, etc. — accept as-is
            return NormalizedIOC(text, expected_type, (expected_type,), 1.0, True)
    if re.fullmatch(r"\d+(?:\.\d+){3}", text) and any(int(part) > 255 for part in text.split(".")):
        return NormalizedIOC(text, "unknown", (), 0.0, False)
    if text.lower().startswith("http."):
        return NormalizedIOC(text, "unknown", (), 0.0, False)
    # DNS treats a terminal dot as equivalent to the absolute hostname form.
    # Normalize it before pattern selection so batch deduplication and cache
    # identity do not split ``Example.COM`` from ``Example.COM.``.
    if "/" not in text and "@" not in text and re.fullmatch(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\.?", text):
        text = text.rstrip(".")
    candidates = []
    for type_name, pattern, *flags in PATTERNS:
        if re.match(pattern, text, flags[0] if flags else 0):
            if type_name == "domain" and text.lower().startswith("http"):
                continue
            if type_name == "filename" and re.fullmatch(r"[a-f0-9]{16,}", text, re.IGNORECASE):
                continue
            if type_name in {"mutex", "service_name"}:
                if is_password_candidate(text):
                    continue
                if len(text) < 6 or text.isdigit() or re.fullmatch(r"[a-f0-9]{16,}", text, re.I):
                    continue
                if text.isalpha() and text.islower() and len(text) < 12:
                    continue
                if type_name == "service_name" and ("\\" in text or "-" in text):
                    continue
            candidates.append(type_name)

    if not candidates:
        if text.lower() in KNOWN_SYSTEM_PROCESSES:
            candidates.append("filename")
        elif is_password_candidate(text):
            candidates.append("password")

    try:
        address = ipaddress.ip_address(text)
        text = address.compressed
        candidates = ["ipv4" if address.version == 4 else "ipv6"]
    except ValueError:
        pass
    primary = candidates[0] if candidates else "unknown"
    if primary == "url":
        parsed = urlsplit(text)
        if parsed.username is not None or parsed.password is not None:
            return NormalizedIOC("", "unknown", (), 0.0, False)
        if parsed.hostname:
            host = parsed.hostname.rstrip(".").lower()
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError:
                pass
            port_number = parsed.port
            default_port = (parsed.scheme.lower() == "http" and port_number == 80) or (parsed.scheme.lower() == "https" and port_number == 443)
            host_for_url = f"[{host}]" if ":" in host else host
            port = f":{port_number}" if port_number and not default_port else ""
            # Keep meaningful path/query content while normalizing percent
            # escapes for unreserved characters and hex casing.
            path = re.sub(r"%([0-9a-fA-F]{2})", lambda m: "%" + m.group(1).upper(), parsed.path or "")
            path = re.sub(r"%([0-9A-F]{2})", lambda m: chr(int(m.group(1), 16)) if chr(int(m.group(1), 16)).isalnum() else m.group(0), path)
            text = urlunsplit((parsed.scheme.lower(), f"{host_for_url}{port}", path, parsed.query, parsed.fragment))
    elif primary == "domain":
        text = text.encode("idna").decode("ascii").lower().rstrip(".")
    elif primary in {"md5", "sha1", "sha256", "sha512", "ja3", "ja4", "tlsh"}:
        text = text.lower()
    elif primary == "email":
        local, _, domain = text.rpartition("@")
        text = f"{local}@{domain.lower().rstrip('.') }"
    elif primary == "cve":
        text = text.upper()
    elif primary == "asn":
        text = "AS" + re.sub(r"^AS", "", text, flags=re.IGNORECASE)
    elif primary == "phone":
        compact = normalize_phone(text)
        if compact is None:
            return NormalizedIOC(text, "unknown", tuple(candidates), 0.0, False)
        text = compact
    elif primary == "windows_path":
        text = text.replace("/", "\\")
    elif primary == "linux_path":
        text = re.sub(r"/{2,}", "/", text)
    if re.fullmatch(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", text, re.I):
        text = ":".join(re.findall(r"[0-9a-f]{2}", text, re.I)).lower()
        candidates = ["mac"]
        primary = "mac"
    candidates = list(dict.fromkeys(candidates))
    if primary == "unknown":
        return NormalizedIOC(text, primary, tuple(candidates), 0.0, False)
    return NormalizedIOC(text, primary, tuple(candidates), 1.0 if len(candidates) == 1 else 0.7, True)


PATTERNS: list[tuple[str, str]] = [
    ("cve", r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
    ("url", r"^https?://[^\s]+$", re.IGNORECASE),
    ("email", r"^[\w.+-]+@[\w-]+\.[\w.-]+$"),
    ("md5", r"^[a-f0-9]{32}$", re.IGNORECASE),
    ("sha1", r"^[a-f0-9]{40}$", re.IGNORECASE),
    ("sha256", r"^[a-f0-9]{64}$", re.IGNORECASE),
    ("sha512", r"^[a-f0-9]{128}$", re.IGNORECASE),
    # Ethereum externally-owned account address.
    ("eth", r"^0x[a-fA-F0-9]{40}$"),
    # JA4 fingerprints are structured tokens, not service names. JA3 is
    # commonly submitted with an explicit prefix because a bare 32-char
    # fingerprint is indistinguishable from an MD5 hash.
    ("ja4", r"^[tq]\d{2}d\d{4}h\d(?:_[a-z0-9]*)?$", re.IGNORECASE),
    ("ja3", r"^ja3:[a-f0-9]{32}$", re.IGNORECASE),
    ("tlsh", r"^T1[0-9A-Z]{68,70}$", re.IGNORECASE),
    ("mac", r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.IGNORECASE),
    ("ssdeep", r"^\d+:[a-zA-Z0-9/+:=]+:[a-zA-Z0-9/+:=]+$"),
    ("btc", r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$"),
    ("btc", r"^bc1[a-zA-Z0-9]{38,58}$"),
    ("mitre_attack", r"^(TA\d{4}|T\d{4}(\.\d{3})?)$"),
    ("asn", r"^AS\d+$", re.IGNORECASE),
    # Phone numbers.  An explicit leading '+' is unambiguous and may carry
    # formatting; bare digits are only accepted in the E.164 7-15 digit range
    # with no formatting, so short numeric secrets still classify as passwords
    # and service names are never swallowed.  ``normalize_phone`` does the
    # strict validation once the pattern has picked the type.
    ("phone", r"(?:\+\s?[\d\s().\-]{6,}|\d{7,15})"),
    ("user_agent", r"^(?:Mozilla|curl|wget|python-requests|Go-http-client|Java)/[^\s]+$", re.IGNORECASE),
    ("named_pipe", r"^\\\\[^\\]+\\pipe\\"),
    # Registry keys must start with a known hive to avoid swallowing mutexes like Global\MyMutex
    ("registry_key", r"^(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[A-Za-z0-9_\\]+$", re.IGNORECASE),
    ("windows_path", r"^(?:[A-Za-z]:[\\/].+|\\\\[^\\/]+[\\/].+)$"),
    ("linux_path", r"^/(?:[^\x00\r\n]+)$"),
    # Filenames must have a valid extension
    ("filename", r"^[a-zA-Z0-9_\-. ]+\.(?:exe|dll|sys|scr|bat|cmd|ps1|vbs|js|jar|msi|docm|xlsm|pptm|hta|apk|sh|bin|txt|pdf|docx?|xlsx?|pptx?|dat|log|tmp|iso|img|vhd|zip|rar|7z|tar|gz|elf|so|dylib|py|pl|php|asp|aspx|jsp|cfg|ini|conf|yaml|yml|json|xml|csv)$", re.IGNORECASE),
    ("domain", r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"),
    # Host artifacts last — service_name before mutex so My_Service123 is not swallowed
    ("service_name", r"^[A-Za-z0-9_]{6,}$"),
    ("mutex", r"^[A-Za-z0-9_\\-]{6,}$"),
]

_SEARCH_BASED_TYPES = {"mutex", "registry_key", "named_pipe", "service_name"}
SUPPORTED_IOC_TYPES = {
    "cve", "ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "sha512",
    "ssdeep", "tlsh", "btc", "eth", "mitre_attack", "asn", "mac", "ja3", "ja4", "user_agent", "filename", "windows_path", "linux_path",
    "mutex", "named_pipe", "registry_key", "service_name", "password", "password_sha1", "username", "phone",
}

# Aliases that map user-friendly short prefixes to canonical type names.
# ``pass:`` and ``password:`` are already handled inside ``normalize_ioc``.
_TYPE_PREFIX_ALIASES: dict[str, str] = {
    "ip": "ipv4",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "domain": "domain",
    "dom": "domain",
    "url": "url",
    "email": "email",
    "mail": "email",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
    "hash": "sha256",  # default hash alias
    "cve": "cve",
    "password": "password",
    "password_sha1": "password_sha1",
    "pass": "password",
    "username": "username",
    "user": "username",
    "btc": "btc",
    "eth": "eth",
    "asn": "asn",
    "mac": "mac",
    "ssdeep": "ssdeep",
    "tlsh": "tlsh",
    "ja3": "ja3",
    "ja4": "ja4",
    "filename": "filename",
    "file": "filename",
    "mitre": "mitre_attack",
    "mitre_attack": "mitre_attack",
    "mutex": "mutex",
    "service_name": "service_name",
    "named_pipe": "named_pipe",
    "registry_key": "registry_key",
    "windows_path": "windows_path",
    "linux_path": "linux_path",
    "user_agent": "user_agent",
    "phone": "phone",
    "tel": "phone",
    "msisdn": "phone",
}


def parse_typed_ioc(text: str) -> tuple[str | None, str]:
    """Detect an explicit ``type:value`` prefix and return ``(canonical_type, value)``.

    Returns ``(None, original_text)`` when no recognized prefix is found or
    when the colon belongs to a URL scheme, IPv6 address, Windows drive path,
    or other non-prefix context.
    """
    if not text or ":" not in text:
        return None, text

    # URLs, defanged URLs, and IPv6 should never be treated as typed prefixes.
    lower = text.lower().lstrip()
    if lower.startswith(("http://", "https://", "hxxp://", "hxxps://", "ftp://", "ftps://")):
        return None, text

    # Windows drive paths like C:\Users\...
    if len(text) >= 3 and text[1] == ":" and text[0].isalpha() and text[2] in ("\\/"):
        return None, text

    # Bare IPv6 addresses (e.g. 2001:db8::1) — if the prefix before the first
    # colon looks like a hex group rather than a type alias, skip.
    colon_idx = text.index(":")
    prefix_candidate = text[:colon_idx].strip().lower()
    value_candidate = text[colon_idx + 1:].strip()

    if not prefix_candidate or not value_candidate:
        return None, text

    # Reject if prefix looks like an IPv6 hex nibble group (1-4 hex chars)
    if re.fullmatch(r"[0-9a-f]{1,4}", prefix_candidate):
        return None, text

    # JA3 fingerprints use ``ja3:`` as a structural prefix already recognized
    # by the pattern table — let them flow through normally.
    if prefix_candidate == "ja3" and re.fullmatch(r"[a-f0-9]{32}", value_candidate, re.I):
        return None, text

    canonical = _TYPE_PREFIX_ALIASES.get(prefix_candidate)
    if canonical is None:
        return None, text

    return canonical, value_candidate


def classify_ioc(value: str) -> str:
    return normalize_ioc(value).ioc_type


def is_search_based(ioc_type: str) -> bool:
    return ioc_type in _SEARCH_BASED_TYPES
