"""재범(hits) 기반 TTL escalation 검증.

시맨틱: 재무장(rearm) — expires_at = now + escalated_ttl (남은 TTL 가산 아님).
"""
from __future__ import annotations

import pytest

from ir.analyzer.risk import assess
from ir.models.incident import Incident
from ir.responder.ip_blocker import (
    BlockAction,
    IpBlocker,
    _escalated_ttl,
)


def _incident(atype: str = "XSS_ATTEMPT", ip: str = "203.0.113.80") -> Incident:
    # XSS → HIGH → default_block_duration(60) — base TTL 계산이 단순
    return Incident.model_validate({"type": atype, "clientIp": ip})


def _blocker(settings) -> IpBlocker:
    return IpBlocker(settings)


# ── 헬퍼 단위 테스트 ─────────────────────────────────────────

@pytest.mark.parametrize("hits,mult", [
    (1, 1),
    (2, 1),
    (3, 2),
    (4, 2),
    (5, 4),
    (9, 4),
    (10, 24),
    (50, 24),  # 상한 캡
])
def test_escalated_ttl_multipliers(hits, mult):
    base = 60
    assert _escalated_ttl(base, hits) == base * mult


def test_ttl_x1_when_hits_below_threshold():
    assert _escalated_ttl(120, 1) == 120
    assert _escalated_ttl(120, 2) == 120


def test_ttl_x2_at_hits_3():
    assert _escalated_ttl(60, 3) == 120


def test_ttl_x4_at_hits_5():
    assert _escalated_ttl(60, 5) == 240


def test_ttl_x24_at_hits_10():
    assert _escalated_ttl(60, 10) == 1440


def test_ttl_capped_at_x24():
    assert _escalated_ttl(60, 50) == _escalated_ttl(60, 10) == 1440


# ── E2E: 누적 / 재무장 / 만료 리셋 ───────────────────────────

def test_hits_accumulate_within_active_window(settings):
    """활성 중 연속 재차단 → hits 증가 + TTL 배수 전환 + 재무장(rearm).

    hits=2(남은 시간 있음) → 재차단 hits=3 → expires_at = now + base×2
    (남은 20초를 이어 붙이지 않고 덮어쓰기).
    """
    b = _blocker(settings)
    inc = _incident()
    a = assess(inc, settings)
    base = a.block_seconds  # XSS → 60
    assert base == 60

    # hits=1
    r1 = b.block(inc, a, now=1000.0)
    assert r1.action is BlockAction.BLOCKED and r1.hits == 1
    e1 = b.store.get("203.0.113.80")
    assert e1 is not None and e1.expires_at == pytest.approx(1000.0 + base)

    # hits=2 (아직 ×1) — 1030 시점에 남은 TTL ≈ 30초
    r2 = b.block(inc, a, now=1030.0)
    assert r2.action is BlockAction.EXTENDED and r2.hits == 2
    e2 = b.store.get("203.0.113.80")
    assert e2 is not None
    assert e2.expires_at == pytest.approx(1030.0 + base)  # 재무장 base
    remaining_before = e2.remaining(1040.0)
    assert remaining_before == 50  # 1030+60 - 1040 = 50 (> 0, 아직 활성)

    # hits=3 → ×2 재무장: 남은 50초를 버리고 now+120
    r3 = b.block(inc, a, now=1040.0)
    assert r3.action is BlockAction.EXTENDED and r3.hits == 3
    e3 = b.store.get("203.0.113.80")
    assert e3 is not None
    expected_ttl = base * 2  # 120
    assert e3.expires_at == pytest.approx(1040.0 + expected_ttl)
    assert e3.remaining(1040.0) == expected_ttl
    # 누적 연장(50+120)이 아님을 명시
    assert e3.expires_at != pytest.approx(1040.0 + remaining_before + expected_ttl)


def test_hits_reset_after_ttl_expiry(settings):
    """TTL 만료(prune) 후 재차단 → hits=1, TTL=base (escalation 리셋)."""
    b = _blocker(settings)
    inc = _incident()
    a = assess(inc, settings)
    base = a.block_seconds

    b.block(inc, a, now=1000.0)
    b.block(inc, a, now=1010.0)
    b.block(inc, a, now=1020.0)  # hits=3, TTL=base×2
    assert b.store.get("203.0.113.80").hits == 3

    # 만료 이후 block → prune 이 엔트리 삭제 → hits=1
    expired_at = 1020.0 + (base * 2) + 1
    res = b.block(inc, a, now=expired_at)
    assert res.action is BlockAction.BLOCKED
    assert res.hits == 1
    entry = b.store.get("203.0.113.80")
    assert entry is not None
    assert entry.hits == 1
    assert entry.expires_at == pytest.approx(expired_at + base)
