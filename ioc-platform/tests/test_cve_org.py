from unittest.mock import AsyncMock, MagicMock

import pytest

from app.backend.adapters.cve_org import CveOrgAdapter


def _make_client(status_code=200, payload=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload or {}
    client = AsyncMock()
    client.get.return_value = response
    return client


def _record(cvss_score=None):
    metrics = []
    if cvss_score is not None:
        metrics.append({"cvssV3_1": {"baseScore": cvss_score, "baseSeverity": "HIGH"}})
    return {
        "cveMetadata": {
            "cveId": "CVE-2024-0001",
            "state": "PUBLISHED",
            "assignerShortName": "mitre",
        },
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "A test vulnerability"}],
                "metrics": metrics,
                "problemTypes": [{"descriptions": [{"lang": "en", "value": "CWE-79 Improper Neutralization"}]}],
                "references": [{"url": "https://example.com/advisory"}],
                "affected": [{"vendor": "ACME", "product": "Widget"}],
            }
        },
    }


@pytest.mark.asyncio
async def test_cve_org_critical_cvss_is_typed_vulnerability_data():
    adapter = CveOrgAdapter()
    adapter.set_client(_make_client(200, _record(cvss_score=9.8)))
    result = await adapter.lookup("CVE-2024-0001", "cve")
    assert result.verdict == "unknown"
    assert result.raw_score is None
    assert result.assessment_domain == "vulnerability"
    assert result.cvss_score == 9.8
    assert result.source == "cve.org"
    # CVSS is typed data (cvss_score, raw_data), not a tag.
    assert result.raw_data["cvss_score"] == 9.8
    assert "cvss:9.8" not in result.tags
    assert result.ioc == "CVE-2024-0001"


@pytest.mark.asyncio
async def test_cve_org_no_cvss_is_unknown():
    adapter = CveOrgAdapter()
    adapter.set_client(_make_client(200, _record()))
    result = await adapter.lookup("CVE-2024-0001", "cve")
    assert result.verdict == "unknown"
    assert result.status == "found"


@pytest.mark.asyncio
async def test_cve_org_rejected_state_is_unknown():
    record = _record()
    record["cveMetadata"]["state"] = "REJECTED"
    adapter = CveOrgAdapter()
    adapter.set_client(_make_client(200, record))
    result = await adapter.lookup("CVE-2024-0001", "cve")
    assert result.verdict == "unknown"
    assert "rejected" in result.tags


@pytest.mark.asyncio
async def test_cve_org_not_found():
    adapter = CveOrgAdapter()
    adapter.set_client(_make_client(404))
    result = await adapter.lookup("CVE-2024-9999", "cve")
    assert result.verdict == "unknown"
    assert result.status == "not_found"


@pytest.mark.asyncio
async def test_cve_org_http_error():
    adapter = CveOrgAdapter()
    adapter.set_client(_make_client(500))
    result = await adapter.lookup("CVE-2024-0001", "cve")
    assert result.verdict == "unknown"
    assert result.execution_state == "error"
    assert "http_500" in result.tags
