"""IpBlocker 검증 — TTL 만료 해제 / 멱등 연장 / allowlist·사설IP 예외 / 저위험 skip."""
from __future__ import annotations

from ir.analyzer.risk import assess
from ir.models.incident import Incident
from ir.responder.ip_blocker import BlockAction, IpBlocker


def _incident(atype: str, ip: str | None):
    return Incident.model_validate({"type": atype, "clientIp": ip})


def _blocker(settings) -> IpBlocker:
    return IpBlocker(settings)  # simulation 핸들러 자동 생성


def test_new_block_public_ip(settings):
    b = _blocker(settings)
    inc = _incident("SQLI_ATTEMPT", "203.0.113.10")
    res = b.block(inc, assess(inc, settings), now=1000.0)
    assert res.action is BlockAction.BLOCKED
    assert res.enforced and res.hits == 1
    assert [e.ip for e in b.store.active(1000.0)] == ["203.0.113.10"]


def test_idempotent_extends_ttl(settings):
    b = _blocker(settings)
    inc = _incident("SQLI_ATTEMPT", "203.0.113.10")
    b.block(inc, assess(inc, settings), now=1000.0)
    res2 = b.block(inc, assess(inc, settings), now=1030.0)   # 아직 활성(120s TTL)
    assert res2.action is BlockAction.EXTENDED
    assert res2.hits == 2
    assert len(b.store.active(1030.0)) == 1                  # 중복 생성 없음


def test_ttl_expiry_auto_release(settings):
    b = _blocker(settings)
    inc = _incident("XSS_ATTEMPT", "203.0.113.11")           # 60s TTL
    b.block(inc, assess(inc, settings), now=1000.0)
    assert len(b.store.active(1000.0)) == 1
    expired = b.reconcile(now=1000.0 + 61)                    # 만료 후 reconcile
    assert [e.ip for e in expired] == ["203.0.113.11"]
    assert b.store.active(1000.0 + 61) == []                  # 자동 해제


def test_allowlisted_ip_skipped(settings):
    b = _blocker(settings)
    inc = _incident("SQLI_ATTEMPT", "10.0.0.5")              # allowlist 정확일치
    res = b.block(inc, assess(inc, settings), now=1000.0)
    assert res.action is BlockAction.SKIPPED_ALLOWLIST
    assert b.store.active(1000.0) == []


def test_allowlist_cidr_skipped(settings):
    b = _blocker(settings)
    inc = _incident("SQLI_ATTEMPT", "192.168.100.42")       # CIDR 매칭
    res = b.block(inc, assess(inc, settings), now=1000.0)
    assert res.action is BlockAction.SKIPPED_ALLOWLIST


def test_private_ip_protected_by_default(settings):
    b = _blocker(settings)
    inc = _incident("SQLI_ATTEMPT", "172.16.5.5")           # 사설 대역
    res = b.block(inc, assess(inc, settings), now=1000.0)
    assert res.action is BlockAction.SKIPPED_ALLOWLIST      # block_private_ips=False


def test_low_severity_records_but_no_block(settings):
    b = _blocker(settings)
    inc = _incident("SOMETHING_NEW", "203.0.113.99")        # LOW(30)
    res = b.block(inc, assess(inc, settings), now=1000.0)
    assert res.action is BlockAction.SKIPPED_LOW
    assert b.store.active(1000.0) == []


def test_persistence_survives_new_store(settings):
    b1 = _blocker(settings)
    inc = _incident("SQLI_ATTEMPT", "203.0.113.20")
    b1.block(inc, assess(inc, settings), now=1000.0)
    b2 = _blocker(settings)                                  # 같은 blocklist.json 로드
    assert [e.ip for e in b2.store.active(1000.0)] == ["203.0.113.20"]
