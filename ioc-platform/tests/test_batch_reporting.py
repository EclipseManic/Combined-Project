"""Two reporting bugs in batch results.

1. A `breached` verdict was counted as `malicious` in the batch summary, so the
   History page reported breached credentials as malicious detections. Exposure
   to a breach corpus is not proof that whoever holds the credential is an
   attacker; it gets its own bucket.

2. Every completed batch subtask is written to LookupResult (tagged with its
   batch_id) so the batch survives a restart. `/api/recent` read that table
   unfiltered, so a 100-IOC batch injected 100 entries into the single-scan
   history. Batch IOCs belong to the batch.
"""

import sys

sys.path.insert(0, ".")

import pytest

from app.backend.adapters.base import CompositeScore, IOCAssessment
from app.backend.batch import BatchTask, consolidate_batch_results
from app.backend.pipeline import AnalysisTask


def _subtask(
    ioc: str,
    verdict: str,
    *,
    ioc_type: str = "email",
    domain: str = "ioc_reputation",
) -> AnalysisTask:
    task = AnalysisTask(task_id=f"t-{ioc}", ioc_value=ioc, normalized=ioc, ioc_type=ioc_type, status="done")
    task.composite = CompositeScore(verdict=verdict, score=50.0, confidence="medium")
    task.final_assessment = IOCAssessment(
        ioc=ioc,
        normalized_ioc=ioc,
        ioc_type=ioc_type,
        assessment_domain=domain,
        final_verdict=verdict,
        confidence="medium",
        normalized_score=50.0,
    )
    return task


def _batch(*tasks: AnalysisTask) -> BatchTask:
    batch = BatchTask("b1", [t.ioc_value for t in tasks])
    batch.subtasks = list(tasks)
    batch.status = "done"
    batch.completed = len(tasks)
    return batch


# --------------------------------------------------------------- breached


def test_breached_is_not_counted_as_malicious():
    payload = consolidate_batch_results(_batch(_subtask("a@example.com", "breached")))
    assert payload["summary"]["breached"] == 1
    assert payload["summary"]["malicious"] == 0, (
        "a breached credential is exposure, not a proven malicious detection"
    )


def test_compromised_still_counts_as_malicious():
    # An active takeover is a different claim from appearing in a breach list.
    payload = consolidate_batch_results(_batch(_subtask("host.example.com", "compromised", ioc_type="domain")))
    assert payload["summary"]["malicious"] == 1
    assert payload["summary"]["breached"] == 0


def test_pwned_is_treated_as_breached():
    payload = consolidate_batch_results(_batch(_subtask("b@example.com", "pwned")))
    assert payload["summary"]["breached"] == 1
    assert payload["summary"]["malicious"] == 0


def test_breached_and_malicious_are_counted_separately():
    payload = consolidate_batch_results(_batch(
        _subtask("a@example.com", "breached"),
        _subtask("b@example.com", "breached"),
        _subtask("c.evil.com", "malicious", ioc_type="domain"),
        _subtask("d.example.org", "suspicious", ioc_type="domain"),
        _subtask("e@example.net", "clean"),
    ))
    summary = payload["summary"]
    assert summary["breached"] == 2
    assert summary["malicious"] == 1
    assert summary["suspicious"] == 1
    assert summary["clean"] == 1
    # The buckets partition the batch rather than overlapping.
    assert sum(summary[k] for k in ("malicious", "breached", "suspicious", "clean")) == 5


def test_summary_always_exposes_the_breached_key():
    payload = consolidate_batch_results(_batch(_subtask("a@example.com", "malicious")))
    assert "breached" in payload["summary"]
    assert payload["summary"]["breached"] == 0


def test_assessment_distribution_tracks_breached():
    payload = consolidate_batch_results(_batch(_subtask("a@example.com", "breached")))
    assert payload["assessment_distribution"]["breached"] == 1


def test_critical_severity_is_still_malicious():
    # A CVE at critical/high severity is a real detection and must not be
    # demoted by the new breached bucket.
    for verdict in ("critical", "high"):
        payload = consolidate_batch_results(
            _batch(_subtask("CVE-2024-0001", verdict, ioc_type="cve", domain="vulnerability"))
        )
        assert payload["summary"]["malicious"] == 1, verdict
        assert payload["summary"]["breached"] == 0, verdict