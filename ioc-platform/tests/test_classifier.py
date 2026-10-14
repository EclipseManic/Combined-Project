import sys
sys.path.insert(0, ".")

from app.backend.classifier import classify_ioc, normalize_ioc, refang, defang


def test_refang_hxxp():
    assert refang("hxxp://evil.com") == "http://evil.com"


def test_refang_hxxps():
    assert refang("hxxps://evil.com") == "https://evil.com"


def test_refang_bracket_dot():
    assert refang("evil[.]com") == "evil.com"


def test_refang_bracket_colon():
    assert refang("http[:]//evil.com") == "http://evil.com"


def test_refang_backslash_dot():
    assert refang(r"evil\.com") == "evil.com"


def test_classify_ipv4():
    assert classify_ioc("8.8.8.8") == "ipv4"


def test_classify_domain():
    assert classify_ioc("google.com") == "domain"


def test_classify_domain_with_http_prefix_skips_domain():
    assert classify_ioc("http.example.com") == "unknown"


def test_classify_invalid_ipv4_octets():
    assert classify_ioc("999.1.1.1") == "unknown"
    assert classify_ioc("256.256.256.256") == "unknown"


def test_classify_url():
    assert classify_ioc("https://evil.com/path") == "url"


def test_url_userinfo_is_rejected():
    assert classify_ioc("https://user:password@evil.com/path") == "unknown"
    assert normalize_ioc("https://user:password@evil.com/path", expected_type="url").valid is False


def test_classify_md5():
    assert classify_ioc("d41d8cd98f00b204e9800998ecf8427e") == "md5"


def test_classify_sha1():
    h = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert classify_ioc(h) == "sha1"


def test_classify_sha256():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert classify_ioc(h) == "sha256"


def test_classify_email():
    assert classify_ioc("user@evil.com") == "email"


def test_classify_cve():
    assert classify_ioc("CVE-2024-1234") == "cve"


def test_classify_ipv6():
    assert classify_ioc("fe80:0000:0000:0000:0000:0000:0000:0001") == "ipv6"


def test_classify_compressed_ipv6():
    assert classify_ioc("2606:4700:4700::1111") == "ipv6"


def test_classify_ssdeep_not_ipv6():
    assert classify_ioc("3:abc:def") == "ssdeep"


def test_classify_named_pipe_before_mutex():
    assert classify_ioc(r"\\host\pipe\mypipe") == "named_pipe"


def test_classify_registry_key_before_mutex():
    assert classify_ioc(r"HKLM\Software\Test") == "registry_key"


def test_classify_unknown():
    assert classify_ioc("not an ioc at all!") == "unknown"


def test_defang():
    assert defang("http://evil.com") == "hxxp://evil[.]com"


def test_defang_https():
    assert defang("https://evil.com") == "hxxps://evil[.]com"


def test_refang_and_classify():
    v = refang("hxxps://evil[.]com/path")
    assert v == "https://evil.com/path"
    assert classify_ioc(v) == "url"


def test_empty_input():
    assert classify_ioc("") == "unknown"


def test_md5_vs_sha1_length():
    assert classify_ioc("a" * 32) == "md5"
    assert classify_ioc("a" * 40) == "sha1"
    assert classify_ioc("a" * 64) == "sha256"


def test_asn():
    assert classify_ioc("AS12345") == "asn"


def test_classify_sample_artifacts_without_domain_or_ssdeep_collisions():
    assert classify_ioc("payload.exe") == "filename"
    assert classify_ioc(r"C:\Users\Public\payload.exe") == "windows_path"
    assert classify_ioc("/tmp/payload") == "linux_path"
    assert classify_ioc("00:1A:2B:3C:4D:5E") == "mac"
    assert classify_ioc("t13d1516h2") == "ja4"
    assert classify_ioc("Mozilla/5.0") == "user_agent"
    assert classify_ioc("e7d705a328a1e57f") == "unknown"


def test_password_digest_requires_explicit_prehashed_input():
    import hashlib
    from app.backend.classifier import password_digest

    value = "a" * 40
    assert password_digest(value) == hashlib.sha1(value.encode()).hexdigest()
    assert password_digest(value, already_digest=True) == value


def test_password_classification():
    from app.backend.classifier import normalize_ioc, SUPPORTED_IOC_TYPES
    assert "password" in SUPPORTED_IOC_TYPES
    # Explicit type passed
    res = normalize_ioc("P@ssw0rd123!", expected_type="password")
    assert res.ioc_type == "password"
    assert res.valid is True
    assert "password" in res.candidate_types

    # Prefix auto-detect
    res_prefix = normalize_ioc("pass:Admin@2024")
    assert res_prefix.ioc_type == "password"
    assert res_prefix.value == "Admin@2024"
    assert res_prefix.valid is True

    res_long_prefix = normalize_ioc("password:SecretVaultKey#1")
    assert res_long_prefix.ioc_type == "password"
    assert res_long_prefix.value == "SecretVaultKey#1"
    assert res_long_prefix.valid is True

    # Bare password auto-detection (credential heuristics)
    assert classify_ioc("Tr0ub4dor&39X9!Qz") == "password"
    assert classify_ioc("Summer2024!") == "password"
    assert classify_ioc("P@ssw0rd123") == "password"
    assert classify_ioc("password123") == "password"
    assert classify_ioc("123456") == "password"
    assert classify_ioc("qwerty") == "password"


def test_explicit_type_rejects_invalid_values():
    assert normalize_ioc("not a domain", expected_type="domain").valid is False
    assert normalize_ioc("bad", expected_type="md5").valid is False
    assert normalize_ioc("999.1.1.1", expected_type="ipv4").valid is False
    assert normalize_ioc("not a url", expected_type="url").valid is False
    assert normalize_ioc("CVE-nope", expected_type="cve").valid is False


def test_password_sha1_requires_a_digest():
    for value in ("a" * 39, "a" * 41, "z" * 40, ""):
        assert normalize_ioc(value, expected_type="password_sha1").valid is False


def test_password_sha1_prefix_canonicalizes_to_password():
    result = normalize_ioc(f"password_sha1:{'A' * 40}")
    assert result.valid is True
    assert result.value == "a" * 40
    assert result.ioc_type == "password"


def test_password_digest_detector():
    from app.backend.classifier import is_password_digest

    assert is_password_digest("a" * 40) is True
    assert is_password_digest("A" * 40) is True
    assert is_password_digest("a" * 39) is False
    assert is_password_digest("S3cret!") is False
    assert is_password_digest("") is False


def test_classify_phone_international():
    assert classify_ioc("+14152007986") == "phone"
    assert classify_ioc("+447700900123") == "phone"


def test_classify_phone_bare_digits():
    # 7-15 digits is the E.164 digit-count range and collides with no hash.
    assert classify_ioc("14152007986") == "phone"


def test_phone_formatting_is_normalized_to_one_cache_identity():
    assert normalize_ioc("+1 (415) 200-7986").value == "+14152007986"
    assert normalize_ioc("+1-415-200-7986").value == "+14152007986"
    assert normalize_ioc("+1.415.200.7986").value == "+14152007986"
    # A bare national number is never given a '+' that was not supplied.
    assert normalize_ioc("14152007986").value == "14152007986"


def test_phone_typed_prefixes():
    for value in ("tel:+14152007986", "phone:+14152007986", "msisdn:+447700900123"):
        result = normalize_ioc(value)
        assert result.ioc_type == "phone"
        assert result.value.startswith("+")


def test_short_numeric_secret_is_still_a_password_not_a_phone():
    # A 6-digit PIN must not become a phone number now that phone exists.
    assert classify_ioc("123456") == "password"
    # More digits than E.164 allows is not a phone number either.
    assert normalize_ioc("+1234567890123456").valid is False


def test_explicit_phone_type_validates_and_normalizes():
    assert normalize_ioc("+1 (415) 200-7986", expected_type="phone").value == "+14152007986"
    assert normalize_ioc("415.200.7986", expected_type="phone").value == "4152007986"
    for bad in ("not-a-phone", "12345", "+", ""):
        assert normalize_ioc(bad, expected_type="phone").valid is False
