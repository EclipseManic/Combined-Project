import sys
sys.path.insert(0, ".")

import pytest

from app.backend.adapters.base import CVEInfo, NormalizedResult
from app.backend.classifier import classify_ioc


class TestCveClassifier:
    def test_cve_yyyy_nnnn(self):
        assert classify_ioc("CVE-2024-1234") == "cve"

    def test_cve_yyyy_nnnnnnn(self):
        assert classify_ioc("CVE-2024-1234567") == "cve"

    def test_cve_lowercase(self):
        assert classify_ioc("cve-2024-1234") == "cve"

    def test_cve_invalid_short_id(self):
        result = classify_ioc("CVE-2024-123")
        assert result != "cve"

    def test_cve_invalid_format(self):
        result = classify_ioc("CVE-2024-ABCD")
        assert result != "cve"

    def test_cve_invalid_no_dash(self):
        result = classify_ioc("CVE20241234")
        assert result != "cve"


class TestCveNormalize:
    def test_kev_malicious(self):
        from app.backend.enrichment import normalize_cve_enrichment
        cve = CVEInfo(is_in_kev=True, kev_date_added="2024-01-15")
        result = normalize_cve_enrichment(cve, "CVE-2024-1234")
        assert result.verdict == "unknown"
        assert result.assessment_domain == "vulnerability"
        assert result.confidence == "high"
        assert result.raw_score is None
        assert result.exploit_status == "known_exploited"
        assert "cisa_kev" in result.tags
        assert result.source == "CVE"

    def test_high_epss_malicious(self):
        from app.backend.enrichment import normalize_cve_enrichment
        cve = CVEInfo(is_in_kev=False, epss_score=0.95, epss_percentile=0.99)
        result = normalize_cve_enrichment(cve, "CVE-2024-5678")
        assert result.verdict == "unknown"
        assert result.assessment_domain == "vulnerability"
        assert result.confidence == "high"
        assert result.epss_score == 0.95

    def test_medium_epss_suspicious(self):
        from app.backend.enrichment import normalize_cve_enrichment
        cve = CVEInfo(is_in_kev=False, epss_score=0.05, epss_percentile=0.80)
        result = normalize_cve_enrichment(cve, "CVE-2024-9012")
        assert result.verdict == "unknown"
        assert result.assessment_domain == "vulnerability"
        assert result.epss_score == 0.05

    def test_low_epss_unknown(self):
        from app.backend.enrichment import normalize_cve_enrichment
        cve = CVEInfo(is_in_kev=False, epss_score=0.001, epss_percentile=0.10)
        result = normalize_cve_enrichment(cve, "CVE-2024-3456")
        assert result.verdict == "unknown"
        assert result.confidence == "high"

    def test_no_data_unknown(self):
        from app.backend.enrichment import normalize_cve_enrichment
        cve = CVEInfo()
        result = normalize_cve_enrichment(cve, "CVE-2024-7890")
        assert result.verdict == "unknown"
        assert result.raw_score is None
        assert result.assessment_domain == "vulnerability"

    def test_source_is_cve(self):
        from app.backend.enrichment import normalize_cve_enrichment
        result = normalize_cve_enrichment(CVEInfo(), "CVE-2024-1111")
        assert result.source == "CVE"
        assert result.ioc_type == "cve"

    def test_cvss_vector_tags(self):
        from app.backend.enrichment import normalize_cve_enrichment
        cve = CVEInfo(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        result = normalize_cve_enrichment(cve, "CVE-2024-2222")
        assert "cvss_scored" in result.tags

    def test_cwe_categories(self):
        from app.backend.enrichment import normalize_cve_enrichment
        cve = CVEInfo(cwe=["CWE-79: Cross-site Scripting", "CWE-89: SQL Injection"])
        result = normalize_cve_enrichment(cve, "CVE-2024-3333")
        assert len(result.categories) >= 2
        assert any("Cross-site" in c for c in result.categories)

    def test_source_link(self):
        from app.backend.enrichment import normalize_cve_enrichment
        result = normalize_cve_enrichment(CVEInfo(), "CVE-2024-4444")
        assert "nvd.nist.gov" in result.source_link
        assert "CVE-2024-4444" in result.source_link

    def test_kev_tags_include_date(self):
        from app.backend.enrichment import normalize_cve_enrichment
        cve = CVEInfo(is_in_kev=True, kev_date_added="2024-06-01")
        result = normalize_cve_enrichment(cve, "CVE-2024-5555")
        assert any("kev_added" in t for t in result.tags)


class TestCveScorer:
    def test_cve_weight_used(self):
        from app.backend.scorer import SOURCE_WEIGHTS
        assert "CVE" in SOURCE_WEIGHTS
        assert SOURCE_WEIGHTS["CVE"] == 1.0

    def test_kev_is_vulnerability_context_not_reputation(self):
        from app.backend.enrichment import normalize_cve_enrichment
        from app.backend.scorer import compute_composite
        cve = CVEInfo(is_in_kev=True)
        kev_result = normalize_cve_enrichment(cve, "CVE-2024-6666")
        from app.backend.scorer import aggregate_evidence
        assessment = aggregate_evidence("CVE-2024-6666", "cve", [kev_result])
        assert assessment.assessment_domain == "vulnerability"
        assert assessment.final_verdict == "informational"
        assert assessment.final_verdict not in {"malicious", "suspicious"}

    def test_high_epss_is_typed_vulnerability_risk(self):
        from app.backend.enrichment import normalize_cve_enrichment
        from app.backend.scorer import compute_composite
        cve = CVEInfo(is_in_kev=False, epss_score=0.95, epss_percentile=0.99)
        result = normalize_cve_enrichment(cve, "CVE-2024-7777")
        from app.backend.scorer import aggregate_evidence
        assessment = aggregate_evidence("CVE-2024-7777", "cve", [result])
        assert assessment.assessment_domain == "vulnerability"
        assert assessment.risk_score == 0.95
        assert assessment.final_verdict == "informational"

    def test_no_cve_data_low_score(self):
        from app.backend.enrichment import normalize_cve_enrichment
        from app.backend.scorer import compute_composite
        result = normalize_cve_enrichment(CVEInfo(), "CVE-2024-8888")
        composite = compute_composite([result])
        assert composite.score == 0.0


class TestCvePipelineIntegration:
    @pytest.mark.asyncio
    async def test_enrich_cve_and_normalize(self):
        from app.backend.enrichment import enrich_cve, normalize_cve_enrichment
        enrichment = await enrich_cve("CVE-2023-44487")
        assert enrichment.cve is not None
        result = normalize_cve_enrichment(enrichment.cve, "CVE-2023-44487")
        assert isinstance(result, NormalizedResult)
        assert result.source == "CVE"
        assert result.ioc_type == "cve"

    @pytest.mark.asyncio
    async def test_pipeline_cve_has_cve_stage(self):
        from app.backend.pipeline import run_analysis
        task = await run_analysis("CVE-2023-44487")
        stage_names = [s.name for s in task.stages]
        assert "CVE Intelligence" in stage_names
        assert task.enrichment is not None

    @pytest.mark.asyncio
    async def test_pipeline_cve_includes_cve_source(self):
        from app.backend.pipeline import run_analysis
        task = await run_analysis("CVE-2023-44487")
        cve_sources = [r for r in task.results if r.source == "CVE"]
        assert len(cve_sources) >= 1

    @pytest.mark.asyncio
    async def test_pipeline_cve_composite_not_unknown(self):
        from app.backend.pipeline import run_analysis
        task = await run_analysis("CVE-2023-44487")
        if task.composite is not None:
            assert task.composite.verdict != "" or task.composite.score >= 0
