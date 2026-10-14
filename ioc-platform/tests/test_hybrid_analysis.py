"""Tests for Hybrid Analysis sandbox adapter."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.backend.adapters.base import SourceAdapter
from app.backend.adapters.hybrid_analysis import HybridAnalysisAdapter


def _mock_client(status_code=200, json_data=None):
    mock_resp = AsyncMock(spec=httpx.Response)
    mock_resp.status_code = status_code
    mock_resp.json.return_value = json_data or {}
    mock_resp.text = json.dumps(json_data or {})

    mock_instance = AsyncMock()
    mock_instance.get.return_value = mock_resp
    mock_instance.post.return_value = mock_resp
    mock_instance.__aenter__.return_value = mock_instance
    mock_instance.__aexit__.return_value = None
    return MagicMock(return_value=mock_instance)


class TestHybridAnalysisAdapter:
    def test_is_adapter(self):
        assert issubclass(HybridAnalysisAdapter, SourceAdapter)

    def test_supported_types(self):
        a = HybridAnalysisAdapter()
        assert "md5" in a.supported_types
        assert "sha1" in a.supported_types
        assert "sha256" in a.supported_types

    @pytest.mark.asyncio
    async def test_no_key(self):
        a = HybridAnalysisAdapter()
        a.api_key = ""
        r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "unknown"
        assert "no_api_key_configured" in r.tags

    @pytest.mark.asyncio
    async def test_404_not_found(self):
        a = HybridAnalysisAdapter()
        a.api_key = "valid_key"
        mock = _mock_client(status_code=404)
        with patch("httpx.AsyncClient", mock):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_401_unauthorized(self):
        a = HybridAnalysisAdapter()
        a.api_key = "bad_key"
        mock = _mock_client(status_code=401)
        with patch("httpx.AsyncClient", mock):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "unknown"
        assert r.execution_state == "unavailable"
        assert "invalid_api_key" in r.tags

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        report = {
            "threat_score": 100,
            "verdict": "malicious",
            "submit_name": "malware.exe",
            "environment_description": "Windows 10 64bit",
            "analysis_start_time": "2024-01-15T10:30:00",
            "vx_family": "emotet",
            "classification_tags": ["trojan", "emotet"],
            "domains": ["evil.com"],
            "hosts": ["1.2.3.4", "5.6.7.8"],
            "process_list": [{"name": "loader.exe"}, {"name": "payload.dll"}],
            "extracted_files": [
                {"name": "dropped_1.dll", "file_path": "C:\\temp\\dropped_1.dll"},
                {"name": "config.ini"},
            ],
            "registry_keys": ["HKLM\\SOFTWARE\\Microsoft\\Malware"],
            "ssdeep": "384:abcdef:123456",
        }
        a = HybridAnalysisAdapter()
        a.api_key = "valid_key"
        mock = _mock_client(status_code=200, json_data=[report])
        with patch("httpx.AsyncClient", mock):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "malicious"
        assert r.confidence == "high"
        assert r.raw_score == 1.0
        assert r.malware_family == "emotet"
        assert "trojan" in r.tags
        assert len(r.dropped_files) == 2
        assert "dropped_1.dll" in r.dropped_files
        assert len(r.registry_keys) == 1
        assert len(r.network_iocs) >= 2
        assert r.process_tree == "loader.exe -> payload.dll"
        assert r.ssdeep == "384:abcdef:123456"

    @pytest.mark.asyncio
    async def test_suspicious_response(self):
        report = {
            "threat_score": 50,
            "verdict": "suspicious",
            "submit_name": "unknown.exe",
            "classification_tags": ["suspicious"],
            "vx_family": "",
            "domains": [],
            "hosts": [],
            "process_list": [],
            "extracted_files": [],
            "registry_keys": [],
        }
        a = HybridAnalysisAdapter()
        a.api_key = "valid_key"
        mock = _mock_client(status_code=200, json_data=[report])
        with patch("httpx.AsyncClient", mock):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "suspicious"
        assert r.confidence == "medium"
        assert r.raw_score == 0.5

    @pytest.mark.asyncio
    async def test_clean_response(self):
        report = {
            "threat_score": 0,
            "verdict": "clean",
            "submit_name": "clean.exe",
            "classification_tags": [],
            "vx_family": "",
            "domains": [],
            "hosts": [],
            "process_list": [],
            "extracted_files": [],
            "registry_keys": [],
        }
        a = HybridAnalysisAdapter()
        a.api_key = "valid_key"
        mock = _mock_client(status_code=200, json_data=[report])
        with patch("httpx.AsyncClient", mock):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "clean"
        assert r.raw_score == 0.0

    @pytest.mark.asyncio
    async def test_empty_results(self):
        a = HybridAnalysisAdapter()
        a.api_key = "valid_key"
        mock = _mock_client(status_code=200, json_data=[])
        with patch("httpx.AsyncClient", mock):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_report_for_a_different_hash_is_not_a_match(self):
        report = {"threat_score": 100, "verdict": "malicious", "sha256": "f" * 64, "md5": "a" * 32}
        a = HybridAnalysisAdapter()
        a.api_key = "valid_key"
        mock = _mock_client(status_code=200, json_data=[report])
        with patch("httpx.AsyncClient", mock):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"

    @pytest.mark.asyncio
    async def test_no_specific_threat_is_not_clean(self):
        report = {"threat_score": 0, "verdict": "no specific threat", "md5": "d41d8cd98f00b204e9800998ecf8427e"}
        a = HybridAnalysisAdapter()
        a.api_key = "valid_key"
        mock = _mock_client(status_code=200, json_data=[report])
        with patch("httpx.AsyncClient", mock):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "undetected"
        assert r.raw_data["match_type"] == "exact"

    @pytest.mark.asyncio
    async def test_adapter_name(self):
        a = HybridAnalysisAdapter()
        assert a.name == "Hybrid Analysis"
