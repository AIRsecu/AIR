"""RiskScoring 포팅 검증 — 앱과 점수/등급이 동일해야 한다."""
from __future__ import annotations

import pytest

from ir.analyzer.risk import assess, score, severity
from ir.models.incident import Incident, Severity


@pytest.mark.parametrize("atype,expected", [
    ("SQLI_ATTEMPT", 95),
    ("RANSOM_MASSDELETE", 95),
    ("ORDER_NEGATIVE_QTY", 85),
    ("IDOR_ATTEMPT", 80),
    ("XSS_ATTEMPT", 75),
    ("DDOS_FLOOD", 70),
    ("ANOMALY_SCAN", 50),
    ("SOMETHING_NEW", 30),  # 미지 유형
])
def test_score_matches_app(atype, expected):
    assert score(atype) == expected


@pytest.mark.parametrize("atype,expected", [
    ("SQLI_ATTEMPT", Severity.CRITICAL),
    ("XSS_ATTEMPT", Severity.HIGH),
    ("ANOMALY_SCAN", Severity.MEDIUM),
    ("SOMETHING_NEW", Severity.LOW),
])
def test_severity_bands(atype, expected):
    assert severity(atype) == expected


def test_assess_duration_by_severity(settings):
    crit = assess(Incident.model_validate({"type": "SQLI_ATTEMPT"}), settings)
    assert crit.base_score == crit.score == 95
    assert crit.base_severity is crit.severity is Severity.CRITICAL
    assert crit.block_seconds == 120  # critical_block_duration
    assert crit.should_block

    high = assess(Incident.model_validate({"type": "XSS_ATTEMPT"}), settings)
    assert high.base_severity is Severity.HIGH
    assert high.block_seconds == 60   # default_block_duration (base HIGH)
    assert high.should_block


def test_low_severity_not_blocked(settings):
    a = assess(Incident.model_validate({"type": "SOMETHING_NEW"}), settings)
    assert a.severity is Severity.LOW
    assert not a.should_block
