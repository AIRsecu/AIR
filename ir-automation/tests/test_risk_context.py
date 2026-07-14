"""컨텍스트 스코어링 검증 — endpoint/payload/재범/시간대 가중치 + 하위 호환."""
from __future__ import annotations

import pytest

from ir.analyzer import rules
from ir.analyzer.context import RecidivismTracker, RiskContext
from ir.analyzer.risk import RiskAnalyzer, assess, assess_with_context, score
from ir.models.incident import Incident, Severity


def _incident(**kwargs) -> Incident:
    base = {
        "type": "XSS_ATTEMPT",
        "endpoint": "/api/v1/products/search",
        "clientIp": "203.0.113.9",
        "payload": "hello",
        "createdAt": "2026-07-03T10:00:00",
    }
    base.update(kwargs)
    return Incident.model_validate(base)


# ── 하위 호환 ───────────────────────────────────────────────

def test_assess_without_context_unchanged(settings):
    """ctx=None / 기존 assess() 는 base score 만 — test_risk.py 계약 유지."""
    inc = _incident(type="SQLI_ATTEMPT")
    a = assess(inc, settings)
    b = assess_with_context(inc, None, settings=settings)
    assert a.score == b.score == 95
    assert a.severity is Severity.CRITICAL


def test_risk_analyzer_without_context_delegates(settings):
    analyzer = RiskAnalyzer(settings=settings)
    inc = _incident(type="SQLI_ATTEMPT")
    a = analyzer.assess(inc, ctx=None)
    assert a.score == score("SQLI_ATTEMPT") == 95


# ── endpoint ────────────────────────────────────────────────

@pytest.mark.parametrize("endpoint,expected", [
    ("/admin/users", 15),
    ("/api/v1/admin/settings", 15),
    ("/api/v1/tenants/acme/delete", 15),
    ("/api/v1/auth/login", 10),
    ("/login", 10),
    ("/api/v1/products/search", 0),
    (None, 0),
])
def test_endpoint_weights(endpoint, expected):
    assert rules.match_endpoint_weight(endpoint) == expected


def test_endpoint_weight_raises_score(settings):
    """XSS(75) + admin(+15) → 90 CRITICAL."""
    inc = _incident(type="XSS_ATTEMPT", endpoint="/admin/dashboard", payload="ok")
    ctx = RiskContext.from_incident(inc)
    a = assess_with_context(inc, ctx, settings=settings)
    assert a.score == 90
    assert a.severity is Severity.CRITICAL


# ── payload ─────────────────────────────────────────────────

@pytest.mark.parametrize("payload,min_weight,name_substr", [
    ("UNION SELECT * FROM users", 20, "union"),
    ("DROP TABLE accounts", 20, "drop"),
    ("' OR 1=1--", 10, "or"),
    ("<script>alert(1)</script>", 10, "script"),
    ("../../etc/passwd", 15, "path"),
    ("normal text", 0, None),
])
def test_payload_signatures(payload, min_weight, name_substr):
    w, matched = rules.match_payload_weight(payload)
    assert w >= min_weight
    if name_substr:
        assert any(name_substr in m for m in matched)
    else:
        assert matched == []


def test_payload_weight_capped_at_20():
    """여러 시그니처 동시 히트해도 상한 20."""
    w, matched = rules.match_payload_weight(
        "DROP TABLE x; UNION SELECT 1; ../../etc/passwd"
    )
    assert len(matched) >= 2
    assert w == rules.PAYLOAD_WEIGHT_CAP == 20


def test_payload_raises_score(settings):
    """ANOMALY_SCAN(50) + path(+15) → 65 MEDIUM."""
    inc = _incident(
        type="ANOMALY_SCAN",
        endpoint="/files",
        payload="../../etc/passwd",
    )
    a = assess_with_context(inc, RiskContext.from_incident(inc), settings=settings)
    assert a.score == 65
    assert a.severity is Severity.MEDIUM


# ── clamp ───────────────────────────────────────────────────

def test_final_score_clamped_to_100(settings):
    """SQLI(95) + admin(+15) + union(+20) → 130 → 100."""
    inc = _incident(
        type="SQLI_ATTEMPT",
        endpoint="/admin/query",
        payload="UNION SELECT password FROM users",
        createdAt="2026-07-03T10:00:00",  # 주간
    )
    a = assess_with_context(inc, RiskContext.from_incident(inc), settings=settings)
    assert a.score == 100


# ── 시간대 ──────────────────────────────────────────────────

def test_night_weight_seoul(settings):
    """Asia/Seoul 02시 → +5."""
    # settings fixture 는 service_timezone 기본(Asia/Seoul) 사용
    inc = _incident(
        type="ANOMALY_SCAN",  # 50
        payload="ok",
        endpoint="/x",
        createdAt="2026-07-03T02:00:00",
    )
    a = assess_with_context(inc, RiskContext.from_incident(inc), settings=settings)
    assert a.score == 55  # 50 + 5


def test_daytime_no_night_weight(settings):
    inc = _incident(
        type="ANOMALY_SCAN",
        payload="ok",
        endpoint="/x",
        createdAt="2026-07-03T14:00:00",
    )
    a = assess_with_context(inc, RiskContext.from_incident(inc), settings=settings)
    assert a.score == 50


# ── 재범 트래커 ─────────────────────────────────────────────

def test_recidivism_tracker_lru_and_maxlen():
    t = RecidivismTracker(max_hits_per_ip=3, max_tracked_ips=2)
    t.record("1.1.1.1", now=1.0)
    t.record("1.1.1.1", now=2.0)
    t.record("1.1.1.1", now=3.0)
    t.record("1.1.1.1", now=4.0)  # maxlen=3 → 1.0 eviction
    assert t.count("1.1.1.1", window_seconds=100, now=4.0) == 3

    t.record("2.2.2.2", now=5.0)
    t.record("3.3.3.3", now=6.0)  # max_tracked_ips=2 → 1.1.1.1 LRU eviction
    assert len(t) == 2
    assert t.count("1.1.1.1", window_seconds=100, now=6.0) == 0


def test_risk_analyzer_recidivism_weight(settings):
    """윈도우 내 3번째 이벤트(recent≥2) 에서 +10."""
    analyzer = RiskAnalyzer(settings=settings)
    inc = _incident(
        type="ANOMALY_SCAN",  # 50
        payload="ok",
        endpoint="/x",
        clientIp="203.0.113.77",
        createdAt="2026-07-03T14:00:00",
    )
    ctx = RiskContext.from_incident(inc)

    s1 = analyzer.assess(inc, ctx).score
    s2 = analyzer.assess(inc, ctx).score
    s3 = analyzer.assess(inc, ctx).score
    assert s1 == 50
    assert s2 == 50          # recent=1 < 2
    assert s3 == 60          # recent=2 → +10


def test_rules_constants_immutable():
    """MappingProxyType — 런타임 덮어쓰기 불가."""
    with pytest.raises(TypeError):
        rules.ENDPOINT_WEIGHTS["/admin/*"] = 99  # type: ignore[index]


def test_pipeline_uses_context_scoring(settings):
    """파이프라인 경로에서도 payload 가중이 반영되는지 스모크."""
    from ir.notifier.discord import DiscordNotifier
    from ir.pipeline import IRPipeline
    from ir.responder.ip_blocker import IpBlocker
    from ir.store.incident_store import IncidentStore

    p = IRPipeline(
        settings,
        blocker=IpBlocker(settings),
        store=IncidentStore(settings.incident_storage_path),
        notifier=DiscordNotifier(settings),
    )
    # XSS(75) + OR inject(+10) = 85, 주간, 비민감 endpoint
    out = p.handle({
        "id": "ctx-001",
        "type": "XSS_ATTEMPT",
        "endpoint": "/api/v1/products/search",
        "clientIp": "203.0.113.50",
        "payload": "' OR 1=1--",
        "createdAt": "2026-07-03T10:00:00",
    })
    assert out["risk"]["score"] == 85
    assert out["risk"]["severity"] == "HIGH"
