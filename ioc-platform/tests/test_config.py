import sys

sys.path.insert(0, ".")

import pytest

from app.backend.config import Settings, resolve_credential, resolve_credential_with_origin

VALID_KEYS = {
    "virustotal_api_key": "a" * 40,
    "abuseipdb_api_key": "a" * 40,
    "urlscanio_api_key": "a" * 40,
    "malwarebazaar_api_key": "a" * 40,
    "threatfox_api_key": "a" * 40,
    "urlhaus_api_key": "a" * 40,
    "nvd_api_key": "a" * 40,
    "triage_api_key": "a" * 40,
    "hybridanalysis_api_key": "a" * 40,
    "greynoise_api_key": "a" * 40,
    "alienvault_otx_api_key": "a" * 40,
    "shodan_api_key": "a" * 40,
    "censys_api_key": "a" * 40,
    "ipinfo_api_key": "a" * 40,
    "ipquality_api_key": "a" * 32,
    "abstractapi_api_key": "a" * 32,
    "abstractapi_email_api_key": "a" * 32,
    "abstractapi_ip_api_key": "a" * 32,
    "abstractapi_phone_api_key": "a" * 32,
    "hunterio_api_key": "a" * 40,
}

ALIAS_KEYS = {
    "virustotal_api_key": "VT_API_KEY",
    "abuseipdb_api_key": "ABUSEIPDB_API_KEY",
    "urlscanio_api_key": "URL_SCAN_API_KEY",
    "malwarebazaar_api_key": "MB_AUTH_KEY",
    "threatfox_api_key": "THREATFOX_API_KEY",
    "urlhaus_api_key": "URLHAUS_API_KEY",
    "nvd_api_key": "NVD_API_KEY",
    "triage_api_key": "TRIAGE_API_KEY",
    "hybridanalysis_api_key": "HA_API_KEY",
    "greynoise_api_key": "GREYNOISE_API_KEY",
    "alienvault_otx_api_key": "OTX_API_KEY",
    "shodan_api_key": "SHODAN_API_KEY",
    "censys_api_key": "CENSYS_API_KEY",
    "ipinfo_api_key": "IPINFO_API_KEY",
    "ipquality_api_key": "IPQUALITY_API_KEY",
    "abstractapi_api_key": "ABSTRACTAPI_API_KEY",
    "abstractapi_email_api_key": "ABSTRACTAPI_EMAIL_KEY",
    "abstractapi_ip_api_key": "ABSTRACTAPI_IP_KEY",
    "abstractapi_phone_api_key": "ABSTRACTAPI_No_KEY",
    "hunterio_api_key": "HUNTERIO_API_KEY",
}


def _settings(**kwargs):
    base = {"database_url": "sqlite+aiosqlite:///./test.db", "_env_file": None}
    base.update(kwargs)
    return Settings(**base)


def test_defaults_applied():
    s = _settings()
    assert s.port == 8000
    assert s.host == "127.0.0.1"
    assert s.app_name == "IOC Lookup Platform"
    assert s.enable_active_port_scan is False
    assert s.enable_url_content_fetch is False
    assert s.webhooks_enabled is False
    assert s.history_retention_days == 30


def test_history_retention_days_alias(monkeypatch):
    monkeypatch.delenv("HISTORY_RETENTION_DAYS", raising=False)
    s = _settings(HISTORY_RETENTION_DAYS="90")
    assert s.history_retention_days == 90


def test_history_retention_days_must_be_positive():
    with pytest.raises(ValueError, match="HISTORY_RETENTION_DAYS must be >= 1"):
        _settings(HISTORY_RETENTION_DAYS="0")


def test_aliases(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    s = _settings(VT_API_KEY="key12345")
    assert s.virustotal_api_key == "key12345"


def test_empty_database_url_raises():
    with pytest.raises(ValueError, match="DATABASE_URL is required"):
        Settings(database_url="", _env_file=None)


def test_non_loopback_host_requires_explicit_opt_in():
    with pytest.raises(ValueError, match="ALLOW_NETWORK_BIND"):
        _settings(host="0.0.0.0", api_keys="test-key-123")


def test_non_loopback_opt_in_still_requires_api_keys():
    with pytest.raises(ValueError, match="API_KEYS is required"):
        _settings(host="0.0.0.0", allow_network_bind=True)


def test_non_loopback_host_with_explicit_opt_in_and_api_keys_is_allowed():
    settings = _settings(
        host="0.0.0.0",
        api_keys="test-key-1234567890",
        allow_network_bind=True,
        base_url="https://ioc.example.com",
    )
    assert settings.host == "0.0.0.0"


def test_network_opt_in_requires_api_keys_on_loopback_host():
    with pytest.raises(ValueError, match="API_KEYS is required"):
        _settings(allow_network_bind=True, base_url="https://ioc.example.com")


def test_network_opt_in_requires_https_base_url():
    with pytest.raises(ValueError, match="BASE_URL must use HTTPS"):
        _settings(allow_network_bind=True, api_keys="test-key-1234567890")


def test_proxy_headers_require_explicit_peer_allowlist():
    with pytest.raises(ValueError, match="TRUSTED_PROXY_HOSTS"):
        _settings(trust_proxy=True)
    settings = _settings(trust_proxy=True, trusted_proxy_hosts="127.0.0.1")
    assert settings.trusted_proxy_hosts == "127.0.0.1"


def test_source_allowlist_is_case_insensitive():
    s = _settings(enabled_sources="OpenPhish, URLhaus")
    assert s.is_source_enabled("openphish")
    assert s.is_source_enabled("URLhaus")
    assert not s.is_source_enabled("VirusTotal")


def test_fail_fast_with_all_keys_passes():
    aliased = {ALIAS_KEYS[k]: v for k, v in VALID_KEYS.items()}
    s = _settings(fail_fast_missing_keys=True, **aliased)
    assert s.fail_fast_missing_keys is True


def test_fail_fast_missing_key_raises(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    aliased = {ALIAS_KEYS[k]: v for k, v in VALID_KEYS.items()}
    aliased["VT_API_KEY"] = ""
    with pytest.raises(ValueError, match="FAIL_FAST_MISSING_KEYS"):
        _settings(fail_fast_missing_keys=True, **aliased)


def test_alias_choices(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("AbuseDB_API_KEY", raising=False)
    monkeypatch.delenv("ABUSH_CH_AUTH_KEY", raising=False)
    s = Settings(
        _env_file=None,
        database_url="sqlite+aiosqlite:///./test.db",
        ABUSEIPDB_API_KEY="x" * 10,
    )
    assert s.abuseipdb_api_key == "x" * 10


@pytest.mark.parametrize(
    ("value", "expected"),
    [("release", False), ("production", False), ("dev", True), ("development", True)],
)
def test_debug_accepts_common_environment_modes(value, expected):
    s = _settings(debug=value)
    assert s.debug is expected

# ------------------------------------------------------------
# Credential resolution: .env (literal or reference) > system env
# ------------------------------------------------------------

def _write_env(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_resolve_env_file_wins_over_system_env_literal(tmp_path):
    env_file = _write_env(tmp_path, "a.env", "VT_API_KEY=file-key\n")
    assert resolve_credential("VT_API_KEY", env_file=env_file, environ={"VT_API_KEY": "sys-key"}) == "file-key"


def test_resolve_system_env_is_fallback_when_env_file_lacks_key(tmp_path):
    env_file = _write_env(tmp_path, "a2.env", "SHODAN_API_KEY=x\n")
    assert resolve_credential("VT_API_KEY", env_file=env_file, environ={"VT_API_KEY": "sys-key"}) == "sys-key"


def test_resolve_env_file_reference_wins_over_system_env(tmp_path):
    env_file = _write_env(tmp_path, "b.env", "VT_API_KEY=${MY_VT_KEY}\n")
    assert resolve_credential(
        "VT_API_KEY", env_file=env_file, environ={"VT_API_KEY": "sys-key", "MY_VT_KEY": "other-key"}
    ) == "other-key"


def test_env_file_alias_beats_system_env_under_other_alias(tmp_path):
    env_file = _write_env(tmp_path, "b2.env", "AbuseDB_API_KEY=file-key\n")
    value, name, origin = resolve_credential_with_origin(
        ["ABUSEIPDB_API_KEY", "AbuseDB_API_KEY"], env_file=env_file, environ={"ABUSEIPDB_API_KEY": "sys-key"},
    )
    assert (value, name, origin) == ("file-key", "AbuseDB_API_KEY", ".env")


def test_resolve_env_file_literal_when_no_system_var(tmp_path):
    env_file = _write_env(tmp_path, "c.env", "VT_API_KEY=file-key\n")
    assert resolve_credential("VT_API_KEY", env_file=env_file, environ={}) == "file-key"


def test_resolve_explicit_reference_from_system_env(tmp_path):
    env_file = _write_env(tmp_path, "d.env", "VT_API_KEY=${MY_VT_KEY}\n")
    assert resolve_credential("VT_API_KEY", env_file=env_file, environ={"MY_VT_KEY": "real-key-123"}) == "real-key-123"


def test_resolve_dollar_name_reference_from_system_env(tmp_path):
    env_file = _write_env(tmp_path, "e.env", "VT_API_KEY=$MY_VT_KEY\n")
    assert resolve_credential("VT_API_KEY", env_file=env_file, environ={"MY_VT_KEY": "real-key-123"}) == "real-key-123"


def test_resolve_bare_name_reference_to_system_env_var(tmp_path):
    env_file = _write_env(tmp_path, "f.env", "VT_API_KEY=vt_ai_key\n")
    assert resolve_credential("VT_API_KEY", env_file=env_file, environ={"vt_ai_key": "real-key-123"}) == "real-key-123"


def test_resolve_reference_chained_within_env_file(tmp_path):
    env_file = _write_env(tmp_path, "g.env", "VT_API_KEY=${MY_VT_KEY}\nMY_VT_KEY=chained-key\n")
    assert resolve_credential("VT_API_KEY", env_file=env_file, environ={}) == "chained-key"


def test_resolve_bare_reference_chains_into_env_file(tmp_path):
    env_file = _write_env(tmp_path, "h.env", "VT_API_KEY=vt_ai_key\nvt_ai_key=chain-key\n")
    assert resolve_credential("VT_API_KEY", env_file=env_file, environ={}) == "chain-key"


def test_resolve_unresolved_reference_returns_empty(tmp_path):
    env_file = _write_env(tmp_path, "i.env", "VT_API_KEY=${DOES_NOT_EXIST}\n")
    assert resolve_credential("VT_API_KEY", env_file=env_file, environ={}) == ""


def test_resolve_literal_with_special_chars_stays_literal(tmp_path):
    env_file = _write_env(tmp_path, "j.env", "VT_API_KEY=abc-def:123xyz\n")
    assert resolve_credential("VT_API_KEY", env_file=env_file, environ={"abc-def:123xyz": "nope"}) == "abc-def:123xyz"


def test_resolve_missing_alias_returns_empty(tmp_path):
    env_file = _write_env(tmp_path, "k.env", "SHODAN_API_KEY=x\n")
    assert resolve_credential("VT_API_KEY", env_file=env_file, environ={}) == ""


def test_resolve_ignores_empty_env_file(tmp_path):
    env_file = _write_env(tmp_path, "l.env", "VT_API_KEY=\n")
    assert resolve_credential("VT_API_KEY", env_file=env_file, environ={}) == ""


def test_resolve_self_reference_does_not_loop(tmp_path):
    env_file = _write_env(tmp_path, "m.env", "VT_API_KEY=${VT_API_KEY}\n")
    assert resolve_credential("VT_API_KEY", env_file=env_file, environ={}) == ""


def test_settings_resolves_env_file_reference(tmp_path, monkeypatch):
    env_file = _write_env(tmp_path, "n.env", "VT_API_KEY=vt_ai_key\nMB_AUTH_KEY=mb-key\n")
    monkeypatch.setenv("vt_ai_key", "system-vt-key")
    monkeypatch.delenv("VT_API_KEY", raising=False)
    s = Settings(_env_file=env_file, database_url="sqlite+aiosqlite:///./test.db")
    assert s.virustotal_api_key == "system-vt-key"
    assert s.malwarebazaar_api_key == "mb-key"


def test_settings_kwarg_wins_over_system_env(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "system-key")
    s = _settings(VT_API_KEY="kwarg-key")
    assert s.virustotal_api_key == "kwarg-key"


def test_settings_env_file_wins_over_system_env_and_reports_origin(tmp_path, monkeypatch):
    env_file = _write_env(tmp_path, "o.env", "VT_API_KEY=file-key\nPORT=9123\n")
    monkeypatch.setenv("VT_API_KEY", "system-key")
    monkeypatch.setenv("PORT", "8111")
    s = Settings(_env_file=env_file, database_url="sqlite+aiosqlite:///./test.db")
    assert s.virustotal_api_key == "file-key"
    assert s.credential_origin("virustotal_api_key") == ("VT_API_KEY", ".env")
    assert s.port == 9123
