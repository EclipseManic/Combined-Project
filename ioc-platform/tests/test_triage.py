"""Tests for Tria.ge sandbox adapter."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.backend.adapters.base import SourceAdapter
from app.backend.adapters.triage import TriageAdapter


def _mock_client(status_code=200, json_data=None):
    mock_resp = AsyncMock(spec=httpx.Response)
    mock_resp.status_code = status_code
    mock_resp.json.return_value = json_data or {}
    mock_resp.text = json.dumps(json_data or {})

    mock_instance = AsyncMock()
    mock_instance.get.return_value = mock_resp
    mock_instance.__aenter__.return_value = mock_instance
    mock_instance.__aexit__.return_value = None
    return MagicMock(return_value=mock_instance)


class TestTriageAdapter:
    def test_is_adapter(self):
        assert issubclass(TriageAdapter, SourceAdapter)

    def test_supported_types(self):
        a = TriageAdapter()
        assert "md5" in a.supported_types
        assert "sha1" in a.supported_types
        assert "sha256" in a.supported_types

    @pytest.mark.asyncio
    async def test_no_key(self):
        a = TriageAdapter()
        a.api_key = ""
        r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "unknown"
        assert "no_api_key_configured" in r.tags

    @pytest.mark.asyncio
    async def test_404_not_found(self):
        a = TriageAdapter()
        a.api_key = "valid_key"
        mock = _mock_client(status_code=404)
        with patch("httpx.AsyncClient", mock):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_401_unauthorized(self):
        a = TriageAdapter()
        a.api_key = "bad_key"
        mock = _mock_client(status_code=401)
        with patch("httpx.AsyncClient", mock):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "unknown"
        assert r.execution_state == "unavailable"
        assert "invalid_api_key" in r.tags

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        sample = {
            "status": "complete",
            "verdict": "malicious",
            "score": 9,
            "tags": ["emotet", "trojan"],
            "signatures": ["emotet"],
            "mitre_attck": ["T1055"],
            "target": {
                "file": {"name": "malware.exe", "md5": "d41d8cd98f00b204e9800998ecf8427e"}
            },
            "network": {
                "dns": [{"domain": "evil.com", "ip": "1.2.3.4"}],
                "tcp": [{"ip": "5.6.7.8", "port": 443}],
            },
            "process": "parent.exe -> child.exe",
            "extracted": {
                "files": [{"name": "dropped.dll"}, {"name": "config.bin"}],
                "registry": ["HKLM\\Software\\Malware"],
                "tlsh": "T1A2B3C4D5E6F7G8H9I0",
            },
        }
        a = TriageAdapter()
        a.api_key = "valid_key"
        mock = _mock_client(status_code=200, json_data=sample)
        with patch("httpx.AsyncClient", mock):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "malicious"
        assert r.confidence == "high"
        assert r.raw_score >= 0.9
        assert "emotet" in r.tags
        assert r.malware_family == "emotet"
        assert len(r.dropped_files) == 2
        assert "dropped.dll" in r.dropped_files
        assert len(r.registry_keys) == 1
        assert "HKLM\\Software\\Malware" in r.registry_keys
        assert len(r.network_iocs) >= 2
        assert r.process_tree == "parent.exe -> child.exe"
        assert r.tlsh == "T1A2B3C4D5E6F7G8H9I0"

    @pytest.mark.asyncio
    async def test_suspicious_response(self):
        sample = {
            "status": "complete",
            "verdict": "suspicious",
            "score": 5,
            "tags": ["generic"],
            "signatures": [],
            "target": {"file": {"name": "unknown.exe"}},
            "network": {},
            "extracted": {},
        }
        a = TriageAdapter()
        a.api_key = "valid_key"
        mock = _mock_client(status_code=200, json_data=sample)
        with patch("httpx.AsyncClient", mock):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "suspicious"
        assert r.confidence == "medium"
        assert r.raw_score == 0.5

    @pytest.mark.asyncio
    async def test_not_complete_response(self):
        sample = {"status": "running", "verdict": "unknown", "score": 0}
        a = TriageAdapter()
        a.api_key = "valid_key"
        mock = _mock_client(status_code=200, json_data=sample)
        with patch("httpx.AsyncClient", mock):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "unknown"
        assert "status_running" in r.tags

    @pytest.mark.asyncio
    async def test_overview_block_no_nameerror(self):
        """P0-5: overview enrichment must not raise NameError (tags/mitre initialized first)."""
        sample = {
            "status": "complete",
            "verdict": "malicious",
            "score": 9,
            "tags": ["emotet"],
            "signatures": [],
            "mitre_attck": [],
            "target": {"file": {"name": "malware.exe"}},
            "network": {},
            "extracted": {},
        }
        overview = {
            "signatures": ["agenttesla"],
            "mitre_attck": ["T1055", "T1047"],
        }
        sample_resp = AsyncMock(spec=httpx.Response)
        sample_resp.status_code = 200
        sample_resp.json.return_value = sample
        sample_resp.text = json.dumps(sample)
        overview_resp = AsyncMock(spec=httpx.Response)
        overview_resp.status_code = 200
        overview_resp.json.return_value = overview
        overview_resp.text = json.dumps(overview)

        mock_instance = AsyncMock()
        mock_instance.get.side_effect = [sample_resp, overview_resp]
        mock_instance.__aenter__.return_value = mock_instance
        mock_instance.__aexit__.return_value = None

        a = TriageAdapter()
        a.api_key = "valid_key"
        with patch("httpx.AsyncClient", MagicMock(return_value=mock_instance)):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "malicious"
        assert "sig:agenttesla" in r.tags
        assert "T1055" in r.mitre_attck
        assert "T1047" in r.mitre_attck

    @pytest.mark.asyncio
    async def test_adapter_name(self):
        a = TriageAdapter()
        assert a.name == "Tria.ge"
