import ipaddress
import os
import re
from pathlib import Path

from dotenv import dotenv_values
from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.backend.thresholds import (
    MALICIOUS_OVERRIDE_COUNT_HIGH,
    MALICIOUS_OVERRIDE_COUNT_MEDIUM,
    OVERRIDE_MIN_MALICIOUS_WEIGHT,
)

PROJECT_ENV_FILE = Path(__file__).resolve().parent.parent.parent / ".env"


def _default_env_file() -> str | None:
    """The repo ``.env`` is the primary configuration source.

    ``IOC_ENV_FILE`` points at a different file; an empty value disables file
    loading entirely (the test suite uses this to stay off real credentials).
    """
    override = os.environ.get("IOC_ENV_FILE")
    if override is not None:
        return override.strip() or None
    return str(PROJECT_ENV_FILE)


_DEFAULT_ENV_FILE = _default_env_file()

_ENV_VAR_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REFERENCE_RE = re.compile(r"^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$")
_PLACEHOLDER_VALUES = frozenset({"null", "none", "placeholder", "undefined", "true", "false", "1", "0"})

CREDENTIAL_ORIGIN_DOTENV = ".env"
CREDENTIAL_ORIGIN_ENVIRONMENT = "environment"
CREDENTIAL_ORIGIN_EXPLICIT = "explicit"


def _dotenv_map(env_file) -> dict[str, str]:
    """Read raw .env values without touching the process environment."""
    if not env_file:
        return {}
    if isinstance(env_file, (list, tuple)):
        merged: dict[str, str] = {}
        for path in env_file:
            merged.update(dotenv_values(path, interpolate=False) or {})
        return merged
    return dotenv_values(env_file, interpolate=False) or {}


def _clean_credential(value: object) -> str:
    text = str(value or "").strip()
    return "" if text.lower() in _PLACEHOLDER_VALUES else text


def resolve_credential_with_origin(
    names, *, env_file=_DEFAULT_ENV_FILE, environ: dict | None = None,
) -> tuple[str, str | None, str | None]:
    """Resolve the first configured alias, ``.env`` before the process environment.

    Every alias is tried against ``.env`` before any alias is tried against the
    process environment, so a key in ``.env`` can never be shadowed by a stale
    system variable under a different alias.  A ``.env`` value may be a literal,
    ``${NAME}``/``$NAME``, or a bare variable name; references resolve through
    ``.env`` first and then the process environment.

    Returns ``(value, alias_name, origin)``; ``("", None, None)`` when unset.
    """
    env = os.environ if environ is None else environ
    dotenv = _dotenv_map(env_file)
    if isinstance(names, str):
        names = [names]

    def _from_dotenv(name: str, seen: set[str]) -> str:
        if name in seen:
            return ""
        seen.add(name)
        raw = _clean_credential(dotenv.get(name))
        if not raw:
            return ""
        m = _REFERENCE_RE.match(raw)
        if m:
            target = m.group(1) or m.group(2)
        elif _ENV_VAR_NAME_RE.match(raw) and (raw in env or raw in dotenv):
            target = raw
        else:
            return raw
        return _from_dotenv(target, seen) or _clean_credential(env.get(target))

    for name in names:
        value = _from_dotenv(name, set())
        if value:
            return value, name, CREDENTIAL_ORIGIN_DOTENV
    for name in names:
        value = _clean_credential(env.get(name))
        if value:
            return value, name, CREDENTIAL_ORIGIN_ENVIRONMENT
    return "", None, None


def resolve_credential(alias: str, *, env_file=_DEFAULT_ENV_FILE, environ: dict | None = None) -> str:
    """Resolve one API key name: ``.env`` first, process environment as fallback."""
    return resolve_credential_with_origin([alias], env_file=env_file, environ=environ)[0]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_DEFAULT_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    @classmethod
    def settings_customise_sources(
        cls, settings_cls, init_settings, env_settings, dotenv_settings, file_secret_settings,
    ):
        # .env is the primary configuration source; the process environment is
        # only a fallback for values the file does not set.
        return init_settings, dotenv_settings, env_settings, file_secret_settings

    database_url: str = Field(
        "sqlite+aiosqlite:///./data/ioc_platform.db",
        validation_alias=AliasChoices("DATABASE_URL", "database_url"),
    )

    redis_url: str = Field("", alias="REDIS_URL")

    virustotal_api_key: str = Field("", alias="VT_API_KEY")
    vt_rate_per_minute: int = Field(4, alias="VT_RATE_PER_MINUTE")
    abuseipdb_api_key: str = Field("", validation_alias=AliasChoices("ABUSEIPDB_API_KEY", "AbuseDB_API_KEY", "ABUSE_IPDB_API_KEY"))
    urlscanio_api_key: str = Field("", alias="URL_SCAN_API_KEY")
    malwarebazaar_api_key: str = Field("", validation_alias=AliasChoices("MB_AUTH_KEY", "ABUSH_CH_AUTH_KEY", "ABUSE_CH_AUTH_KEY", "ABUSE_CH_API_KEY", "ABUSECH_API_KEY"))
    threatfox_api_key: str = Field("", validation_alias=AliasChoices("THREATFOX_API_KEY", "MB_AUTH_KEY", "ABUSH_CH_AUTH_KEY", "ABUSE_CH_AUTH_KEY", "ABUSE_CH_API_KEY", "ABUSECH_API_KEY"))
    urlhaus_api_key: str = Field("", validation_alias=AliasChoices("URLHAUS_API_KEY", "MB_AUTH_KEY", "ABUSH_CH_AUTH_KEY", "ABUSE_CH_AUTH_KEY", "ABUSE_CH_API_KEY", "ABUSECH_API_KEY"))

    nvd_api_key: str = Field("", alias="NVD_API_KEY")
    hashlookup_enabled: bool = Field(True, alias="HASHLOOKUP_ENABLED")
    triage_api_key: str = Field("", validation_alias=AliasChoices("TRIAGE_API_KEY", "TRIA_GE_API_KEY"))
    hybridanalysis_api_key: str = Field("", alias="HA_API_KEY")

    greynoise_api_key: str = Field("", alias="GREYNOISE_API_KEY")
    # One IPQualityScore key unlocks all three of its products (phone, IP, email).
    ipquality_api_key: str = Field(
        "", validation_alias=AliasChoices("IPQUALITY_API_KEY", "IPQUALITYSCORE_API_KEY")
    )
    abstractapi_api_key: str = Field("", validation_alias=AliasChoices("ABSTRACTAPI_API_KEY", "ABSTRACT_API_KEY"))
    # AbstractAPI issues one key per product, and a key for one product is
    # rejected by the others.  Each field below is scoped to a single endpoint.
    abstractapi_email_api_key: str = Field("", alias="ABSTRACTAPI_EMAIL_KEY")
    abstractapi_ip_api_key: str = Field("", alias="ABSTRACTAPI_IP_KEY")
    abstractapi_phone_api_key: str = Field(
        "", validation_alias=AliasChoices("ABSTRACTAPI_No_KEY", "ABSTRACTAPI_PHONE_KEY")
    )
    hunterio_api_key: str = Field("", validation_alias=AliasChoices("HUNTERIO_API_KEY", "HUNTER_IO_API_KEY", "HUNTER_API_KEY"))
    alienvault_otx_api_key: str = Field("", validation_alias=AliasChoices("OTX_API_KEY", "ALIENVAULT_OTX_KEY"))
    shodan_api_key: str = Field("", alias="SHODAN_API_KEY")
    censys_api_key: str = Field("", alias="CENSYS_API_KEY")
    censys_organization_id: str = Field("", alias="CENSYS_ORGANIZATION_ID")
    ipinfo_api_key: str = Field("", validation_alias=AliasChoices("IPINFO_API_KEY", "IPINFO_ACCESS_TOKEN"))
    etherscan_api_key: str = Field("", alias="ETHERSCAN_API_KEY")
    # Scrape the public etherscan.io address page for labels, valuation,
    # holdings, multichain portfolio and funding source (no key needed).
    etherscan_page_enrichment: bool = Field(True, alias="ETHERSCAN_PAGE_ENRICHMENT")
    chainabuse_api_key: str = Field("", validation_alias=AliasChoices("CHAIN_BUSE_API", "CHAINABUSE_API_KEY", "CHAINABUSE_API"))
    filescan_api_key: str = Field("", alias="FILESCAN_API_KEY")
    hudson_api_key: str = Field("", validation_alias=AliasChoices("HUDSON_API_KEY", "HUDSON_ROCK_API_KEY", "HUDSONROCK_API_KEY"))

    log_level: str = Field("INFO", alias="LOG_LEVEL")
    api_keys: str = Field("", alias="API_KEYS")
    fail_fast_missing_keys: bool = Field(False, alias="FAIL_FAST_MISSING_KEYS")
    reload: bool = Field(False, alias="RELOAD")
    host: str = Field("127.0.0.1", alias="HOST")
    port: int = Field(8000, alias="PORT")
    allow_network_bind: bool = Field(False, alias="ALLOW_NETWORK_BIND")
    disable_auto_open: bool = Field(False, alias="DISABLE_AUTO_OPEN")

    scoring_override_min_weight: float = Field(OVERRIDE_MIN_MALICIOUS_WEIGHT, alias="SCORING_OVERRIDE_MIN_WEIGHT")
    scoring_override_count_high: int = Field(MALICIOUS_OVERRIDE_COUNT_HIGH, alias="SCORING_OVERRIDE_COUNT_HIGH")
    scoring_override_count_medium: int = Field(MALICIOUS_OVERRIDE_COUNT_MEDIUM, alias="SCORING_OVERRIDE_COUNT_MEDIUM")
    cors_origins: str = Field("http://localhost:8000,http://127.0.0.1:8000,http://localhost:5173", alias="CORS_ORIGINS")
    trusted_hosts: str = Field("", alias="TRUSTED_HOSTS")
    base_url: str = Field("", alias="BASE_URL")
    require_network_tls: bool = Field(True, alias="REQUIRE_NETWORK_TLS")
    allow_global_feedback: bool = Field(False, alias="ALLOW_GLOBAL_FEEDBACK")
    cache_dir: str = Field("", alias="CACHE_DIR")
    app_name: str = "IOC Lookup Platform"
    debug: bool = False
    ioc_timeout: int = Field(60, alias="IOC_TIMEOUT")
    batch_deadline_seconds: int = Field(300, alias="BATCH_DEADLINE_SECONDS")
    ioc_deadline_seconds: float = Field(60.0, alias="IOC_DEADLINE_SECONDS")
    provider_timeout_seconds: float = Field(20.0, alias="PROVIDER_TIMEOUT_SECONDS")
    queue_wait_timeout_seconds: float = Field(10.0, alias="QUEUE_WAIT_TIMEOUT_SECONDS")
    network_timeout_seconds: float = Field(15.0, alias="NETWORK_TIMEOUT_SECONDS")
    batch_semaphore_limit: int = Field(10, alias="BATCH_SEMAPHORE_LIMIT")
    # Batch progress-persistence debounce: how often the drive loop flushes
    # partial progress to the DB while a batch is running.  Terminal states
    # always force one final complete persist regardless of these.
    batch_progress_persist_every: int = Field(5, alias="BATCH_PROGRESS_PERSIST_EVERY")
    batch_progress_persist_interval: float = Field(2.0, alias="BATCH_PROGRESS_PERSIST_INTERVAL")
    # Shared provider fan-out budget: clamps batch IOC concurrency so
    # concurrency * per-IOC-fanout stays under the budget, capping the
    # worst-case simultaneous provider burst (API-key protection).  Budget 0
    # disables the clamp.
    batch_provider_fanout_budget: int = Field(90, alias="BATCH_PROVIDER_FANOUT_BUDGET")
    batch_provider_fanout_per_ioc: int = Field(18, alias="BATCH_PROVIDER_FANOUT_PER_IOC")
    max_batch_iocs: int = Field(100, alias="MAX_BATCH_IOCS")
    max_concurrent_lookups: int = Field(4, alias="MAX_CONCURRENT_LOOKUPS")
    max_pending_lookups: int = Field(32, alias="MAX_PENDING_LOOKUPS")
    enable_active_port_scan: bool = Field(False, alias="ENABLE_ACTIVE_PORT_SCAN")
    enable_url_content_fetch: bool = Field(False, alias="ENABLE_URL_CONTENT_FETCH")
    enable_public_url_submission: bool = Field(False, alias="ENABLE_PUBLIC_URL_SUBMISSION")
    webhooks_enabled: bool = Field(False, alias="WEBHOOKS_ENABLED")
    webhook_secret_key: str = Field("", alias="WEBHOOK_SECRET_KEY")
    enabled_sources: str = Field("", alias="ENABLED_SOURCES")
    history_retention_days: int = Field(30, alias="HISTORY_RETENTION_DAYS")
    lookup_rate_limit_per_minute: int = Field(30, alias="LOOKUP_RATE_LIMIT_PER_MINUTE")
    lookup_rate_window: int = Field(60, alias="LOOKUP_RATE_WINDOW")
    lookup_global_rate_limit_per_minute: int = Field(300, alias="LOOKUP_GLOBAL_RATE_LIMIT_PER_MINUTE")
    trust_proxy: bool = Field(False, alias="TRUST_PROXY")
    trusted_proxy_hosts: str = Field("", alias="TRUSTED_PROXY_HOSTS")

    def __init__(self, **values):
        if "database_url" in values:
            values["DATABASE_URL"] = values.pop("database_url")
        explicit = {name for name in values if not name.startswith("_")}
        super().__init__(**values)
        self._active_env_file = values.get("_env_file", _DEFAULT_ENV_FILE)
        self._credential_origins: dict[str, tuple[str | None, str | None]] = {}
        self._resolve_api_keys(explicit)
        self._validate_required()

    def credential_origin(self, field_name: str) -> tuple[str | None, str | None]:
        """``(alias_name, origin)`` that supplied a credential field; never the value."""
        return self._credential_origins.get(field_name, (None, None))

    def is_source_enabled(self, source_name: str) -> bool:
        allowed = {name.strip().lower() for name in self.enabled_sources.split(",") if name.strip()}
        return not allowed or source_name.lower() in allowed

    @field_validator("debug", mode="before")
    @classmethod
    def _parse_debug_mode(cls, value):
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"release", "production", "prod"}:
                return False
            if normalized in {"development", "develop", "dev"}:
                return True
        return value

    @field_validator("history_retention_days")
    @classmethod
    def _validate_retention_days(cls, value: int) -> int:
        if value < 1:
            raise ValueError("HISTORY_RETENTION_DAYS must be >= 1")
        return value

    def _resolve_api_keys(self, explicit: set[str]):
        for field_name, info in type(self).model_fields.items():
            if not (field_name.endswith("_api_key") or field_name in _EXTRA_CREDENTIAL_FIELDS):
                continue
            alias = info.validation_alias
            if alias is None:
                continue
            choices = list(alias.choices) if isinstance(alias, AliasChoices) else [str(alias)]
            if field_name in explicit or explicit.intersection(choices):
                value = _clean_credential(getattr(self, field_name, ""))
                setattr(self, field_name, value)
                self._credential_origins[field_name] = (None, CREDENTIAL_ORIGIN_EXPLICIT if value else None)
                continue
            resolved, name, origin = resolve_credential_with_origin(choices, env_file=self._active_env_file)
            setattr(self, field_name, resolved)
            self._credential_origins[field_name] = (name, origin)

    def _validate_required(self):
        if not self.database_url:
            raise ValueError("DATABASE_URL is required — set it in .env or environment")
        if self.max_concurrent_lookups < 1 or self.max_pending_lookups < 1:
            raise ValueError("Lookup concurrency and pending limits must be positive")
        if self.batch_semaphore_limit < 1 or self.max_batch_iocs < 1:
            raise ValueError("Batch limits must be positive")
        if self.fail_fast_missing_keys:
            from app.backend.adapters.base import is_valid_api_key

            missing = []
            for name in _API_KEY_FIELDS:
                value = getattr(self, name)
                if not is_valid_api_key(value or ""):
                    missing.append(name)
            if missing:
                raise ValueError(
                    "FAIL_FAST_MISSING_KEYS is enabled but the following API keys are "
                    f"missing or placeholders: {', '.join(missing)}"
                )
        if not _is_loopback_host(self.host) and not self.allow_network_bind:
            raise ValueError("ALLOW_NETWORK_BIND=true is required for non-loopback binding")
        if self.allow_network_bind:
            api_keys = [key.strip() for key in self.api_keys.split(",") if key.strip()]
            if not api_keys:
                raise ValueError("API_KEYS is required when ALLOW_NETWORK_BIND=true")
            if any(len(key) < 16 for key in api_keys):
                raise ValueError("Network API keys must be at least 16 characters")
            if self.require_network_tls and not self.base_url.lower().startswith("https://"):
                raise ValueError("BASE_URL must use HTTPS when network binding is enabled")
        if self.webhooks_enabled and not self.webhook_secret_key.strip():
            raise ValueError("WEBHOOK_SECRET_KEY is required when webhooks are enabled")
        if self.trust_proxy and not self.trusted_proxy_hosts.strip():
            raise ValueError("TRUSTED_PROXY_HOSTS is required when TRUST_PROXY is enabled")
        return self


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


_EXTRA_CREDENTIAL_FIELDS = frozenset({"censys_organization_id"})

_API_KEY_FIELDS = (
    "virustotal_api_key",
    "abuseipdb_api_key",
    "urlscanio_api_key",
    "malwarebazaar_api_key",
    "threatfox_api_key",
    "urlhaus_api_key",
    "nvd_api_key",
    "triage_api_key",
    "hybridanalysis_api_key",
    "greynoise_api_key",
    "alienvault_otx_api_key",
    "shodan_api_key",
    "censys_api_key",
    "ipinfo_api_key",
    "ipquality_api_key",
    "abstractapi_api_key",
    "abstractapi_email_api_key",
    "abstractapi_ip_api_key",
    "abstractapi_phone_api_key",
    "hunterio_api_key",
)


settings = Settings()
