from unittest.mock import AsyncMock, MagicMock

import pytest

from app.backend.adapters.nvd import NvdAdapter


def _make_client(status_code: int = 200, payload: dict | None = None) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload or {}
    client = AsyncMock()
    client.get.return_value = response
    return client


def _record(cvss_score: float | None = None) -> dict:
    metrics = {}
    if cvss_score is not None:
        metrics["cvssMetricV31"] = [{"cvssData": {"baseScore": cvss_score, "baseSeverity": "HIGH"}}]
    return {
        "resultsPerPage": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "published": "2024-01-01T00:00:00.000",
                    "lastModified": "2024-06-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "A test vulnerability"}],
                    "metrics": metrics,
                    "weaknesses": [{"description": [{"value": "CWE-79 Improper Neutralization"}]}],
                    "references": [{"url": "https://example.com/advisory"}],
                }
            }
        ],
    }


@pytest.mark.asyncio
async def test_nvd_critical_cvss_is_typed_vulnerability_data():
    adapter = NvdAdapter()
    adapter.set_client(_make_client(200, _record(cvss_score=9.8)))
    result = await adapter.lookup("CVE-2024-0001", "cve")
    assert result.verdict == "unknown"
    assert result.raw_score is None
    assert result.assessment_domain == "vulnerability"
    assert result.cvss_score == 9.8
    assert result.source == "NVD"
    # CVSS is typed data (cvss_score, raw_data), not a tag.
    assert result.raw_data["cvss_score"] == 9.8
    assert result.raw_data["severity"] == "high"
    assert "cvss:9.8" not in result.tags
    assert result.ioc == "CVE-2024-0001"


@pytest.mark.asyncio
async def test_nvd_no_cvss_is_unknown():
    adapter = NvdAdapter()
    adapter.set_client(_make_client(200, _record()))
    result = await adapter.lookup("CVE-2024-0001", "cve")
    assert result.verdict == "unknown"
    assert result.status == "found"


@pytest.mark.parametrize(
    "score,expected_score,expected_verdict",
    [
        (7.5, None, "unknown"),
        (5.0, None, "unknown"),
        (2.0, None, "unknown"),
    ],
)
@pytest.mark.asyncio
async def test_nvd_cvss_thresholds(score, expected_score, expected_verdict):
    adapter = NvdAdapter()
    adapter.set_client(_make_client(200, _record(cvss_score=score)))
    result = await adapter.lookup("CVE-2024-0001", "cve")
    assert result.verdict == expected_verdict
    assert result.raw_score == expected_score
    assert result.assessment_domain == "vulnerability"


@pytest.mark.asyncio
async def test_nvd_rejected_status_is_tagged():
    record = _record()
    record["vulnerabilities"][0]["cve"]["vulnStatus"] = "Rejected"
    adapter = NvdAdapter()
    adapter.set_client(_make_client(200, record))
    result = await adapter.lookup("CVE-2024-0001", "cve")
    assert "rejected" in result.tags


@pytest.mark.asyncio
async def test_nvd_malformed_body_is_error():
    client = AsyncMock()
    response = MagicMock()
    response.status_code = 200
    response.json.side_effect = ValueError("not json")
    client.get.return_value = response
    adapter = NvdAdapter()
    adapter.set_client(client)
    result = await adapter.lookup("CVE-2024-0001", "cve")
    assert result.verdict == "unknown"
    assert result.execution_state == "error"
    assert "malformed_response" in result.tags


@pytest.mark.asyncio
async def test_nvd_not_found_empty_vulnerabilities():
    payload = {"resultsPerPage": 0, "vulnerabilities": []}
    adapter = NvdAdapter()
    adapter.set_client(_make_client(200, payload))
    result = await adapter.lookup("CVE-2024-9999", "cve")
    assert result.verdict == "unknown"
    assert result.status == "not_found"


@pytest.mark.asyncio
async def test_nvd_rate_limited_429_or_503():
    for status in (429, 503):
        adapter = NvdAdapter()
        adapter.set_client(_make_client(status))
        result = await adapter.lookup("CVE-2024-0001", "cve")
        assert result.verdict == "unknown"
        assert result.execution_state == "rate_limited"
        assert "rate_limited" in result.tags


@pytest.mark.asyncio
async def test_nvd_http_error():
    adapter = NvdAdapter()
    adapter.set_client(_make_client(500))
    result = await adapter.lookup("CVE-2024-0001", "cve")
    assert result.verdict == "unknown"
    assert result.execution_state == "error"
    assert "http_500" in result.tags
