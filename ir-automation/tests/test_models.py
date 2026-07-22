"""Incident 계약 검증 — 앱 camelCase JSON 을 손실 없이 수용하는지."""
from __future__ import annotations

from ir.models.incident import Incident

APP_JSON = {
    "id": "01HXULID",
    "type": "sqli_attempt",
    "endpoint": "/api/v1/products/search",
    "clientIp": "203.0.113.9",
    "actor": "guest",
    "payload": "' OR '1'='1",
    "actionTaken": "DEFENSE_ENABLED:air.sql-injection-guard",
    "status": "MITIGATED",
    "createdAt": "2026-07-03T09:30:00",
}


def test_parses_app_camelcase_contract():
    inc = Incident.model_validate(APP_JSON)
    assert inc.id == "01HXULID"
    assert inc.client_ip == "203.0.113.9"       # alias 매핑
    assert inc.action_taken.startswith("DEFENSE_ENABLED")
    assert inc.created_at.year == 2026


def test_type_normalized_uppercase():
    assert Incident.model_validate({"type": "sqli_attempt"}).type == "SQLI_ATTEMPT"
    assert Incident.model_validate({"type": ""}).type == "UNKNOWN_ANOMALY"


def test_payload_truncation():
    inc = Incident.model_validate({"type": "X", "payload": "A" * 3000})
    assert len(inc.payload) == 2001 and inc.payload.endswith("…")


def test_ensure_id_fills_when_missing():
    inc = Incident.model_validate({"type": "XSS_ATTEMPT"})
    assert inc.id is None
    first = inc.ensure_id()
    assert first and inc.ensure_id() == first  # 재호출해도 동일


def test_dedup_key_matches_app_rule():
    inc = Incident.model_validate({"type": "IDOR_ATTEMPT", "clientIp": "198.51.100.7"})
    assert inc.dedup_key() == "IDOR_ATTEMPT|198.51.100.7"


def test_roundtrip_to_contract_is_camelcase():
    out = Incident.model_validate(APP_JSON).to_contract()
    assert "clientIp" in out and "actionTaken" in out
