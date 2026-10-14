import re

import httpx

from app.backend.adapters._http import MalformedResponse, describe_exception, exception_result, failure, http_failure, malformed, read_json
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter
from app.backend.logger import get_logger

logger = get_logger("adapter.hashlookup")
_HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
_TYPE_MAP = {"md5": "md5", "sha1": "sha1", "sha256": "sha256"}
_EXPECTED_LENGTH = {"md5": 32, "sha1": 40, "sha256": 64}
_DETAIL_FIELDS = ("FileName", "mimetype", "filetype", "trust", "ssdeep", "tlsh", "imphash", "FileSize", "Product")


class HashlookupAdapter(SourceAdapter):
    name = "Hashlookup"
    supported_types = ["md5", "sha1", "sha256"]
    public_without_key = True
    rate_limit = RateLimitConfig(requests_per_minute=30)

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if ioc_type not in self.supported_types:
            return failure(
                self.name, ioc_value, ioc_type, "invalid_request", ["unsupported_type"],
                f"Hashlookup does not support {ioc_type} lookups", request_made=False,
            )
        if not _HASH_RE.match(ioc_value):
            return failure(
                self.name, ioc_value, ioc_type, "invalid_request", ["invalid_hash_format"],
                "Not a valid hash", request_made=False,
            )
        if len(ioc_value) != _EXPECTED_LENGTH.get(ioc_type, 0):
            return failure(
                self.name, ioc_value, ioc_type, "invalid_request", ["invalid_hash_length"],
                f"Hash length does not match {ioc_type}", request_made=False,
            )
        hash_type = _TYPE_MAP[ioc_type]
        url = f"https://hashlookup.circl.lu/lookup/{hash_type}/{ioc_value}"
        client = self._get_client()
        try:
            resp = await client.get(url, timeout=10)
        except httpx.HTTPError as exc:
            self._record_failure()
            logger.warning("Hashlookup request failed: %s", describe_exception(exc))
            return exception_result(self.name, ioc_value, ioc_type, exc)

        failed = http_failure(self.name, ioc_value, ioc_type, resp, key_sent=False, not_found_summary="Hash is not in the CIRCL reference corpus")
        if failed is not None:
            if failed.execution_state in {"error", "rate_limited"}:
                self._record_failure()
            return failed
        try:
            data = read_json(resp)
        except MalformedResponse as exc:
            self._record_failure()
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        if not isinstance(data, dict):
            self._record_failure()
            return malformed(self.name, ioc_value, ioc_type, http_status=resp.status_code)

        # File metadata is structured data, not tags.
        details = {
            key: str(data[key])[:120]
            for key in _DETAIL_FIELDS
            if data.get(key) is not None and str(data[key]).strip()
        }
        parents = data.get("Parents") or data.get("Parent")
        if isinstance(parents, list):
            details["parents"] = [str(item)[:80] for item in parents[:3] if item]
        elif parents:
            details["parents"] = [str(parents)[:80]]
        other_hashes = {
            key: data[key] for key in ("md5", "sha1", "sha256")
            if data.get(key) and str(data[key]).lower() != ioc_value.lower()
        }
        if other_hashes:
            details["other_hashes"] = other_hashes
        source_link = f"https://hashlookup.circl.lu/lookup/{hash_type}/{ioc_value}"
        self._record_success()
        # CIRCL Hashlookup is a known-FILE reference corpus (NSRL + known
        # software + some malware). A hit means "this file is known", NOT
        # "this file is safe" -- known-malware samples are present here too.
        # Emit a neutral/informational signal so the per-source badge is honest
        # and never contributes a false "clean" verdict. The reputation scorer
        # already excludes Hashlookup from clean/negative evidence.
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", provider_verdict="known_file",
            raw_score=0.0, confidence="low",
            tags=["known_file", "present_in_reference_corpus"],
            source_link=source_link, status="found", raw_data=details,
            provider_summary="Hash is present in the CIRCL known-file corpus (not a safety verdict)",
        )
