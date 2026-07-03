"""엔드투엔드 파이프라인 + FastAPI /ingest (simulation, Discord 비활성)."""
from __future__ import annotations

from fastapi.testclient import TestClient

from ir.notifier.discord import DiscordNotifier
from ir.pipeline import IRPipeline
from ir.responder.ip_blocker import IpBlocker
from ir.store.incident_store import IncidentStore

APP_EVENT = {
    "id": "01HXTEST",
    "type": "SQLI_ATTEMPT",
    "endpoint": "/api/v1/products/search",
    "clientIp": "203.0.113.50",
    "actor": "guest",
    "payload": "' OR 1=1--",
    "actionTaken": "DEFENSE_ENABLED:air.sql-injection-guard",
    "status": "MITIGATED",
    "createdAt": "2026-07-03T10:00:00",
}


def _pipeline(settings) -> IRPipeline:
    return IRPipeline(
        settings,
        blocker=IpBlocker(settings),
        store=IncidentStore(settings.incident_storage_path),
        notifier=DiscordNotifier(settings),  # webhook None → 전송 skip
    )


def test_pipeline_handles_incident(settings):
    p = _pipeline(settings)
    out = p.handle(APP_EVENT)
    assert out["risk"]["severity"] == "CRITICAL"
    assert out["response"]["action"] == "BLOCKED"
    assert out["response"]["enforced"] is True
    assert out["notified"] is False                     # Discord 미설정
    # 저장 확인
    rec = p.store.load(out["incidentId"])
    assert rec["playbook"]["contain"] is True
    assert rec["incident"]["clientIp"] == "203.0.113.50"


def test_pipeline_idempotent_second_event(settings):
    p = _pipeline(settings)
    p.handle(APP_EVENT)
    out2 = p.handle(APP_EVENT)
    assert out2["response"]["action"] == "EXTENDED"     # 중복 → 연장
    assert len(p.blocker.store.active()) == 1


def test_ingest_endpoint(settings, monkeypatch):
    # app 모듈의 전역 pipeline 을 테스트용(simulation/tmp)으로 교체
    import ir.app as app_module
    monkeypatch.setattr(app_module, "pipeline", _pipeline(settings))
    client = TestClient(app_module.app)

    r = client.post("/ingest", json=APP_EVENT)
    assert r.status_code == 200
    assert r.json()["response"]["action"] == "BLOCKED"

    bl = client.get("/blocklist").json()
    assert bl["count"] == 1 and bl["blocked"][0]["ip"] == "203.0.113.50"

    h = client.get("/healthz").json()
    assert h["mode"] == "simulation" and h["discord"] is False
