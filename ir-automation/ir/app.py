"""FastAPI 진입점 — 앱(Java)이 인시던트를 POST /ingest 로 밀어넣는다.

실행: (ir-automation/ 에서)
    uvicorn ir.app:app --host 0.0.0.0 --port 8090

엔드포인트:
    POST /ingest        인시던트 수신 → 대응 파이프라인 실행
    GET  /healthz       헬스체크
    GET  /blocklist     현재 활성 차단(TTL 남은 것)
    GET  /incidents/{id}  저장된 인시던트 레코드
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from config.settings import get_settings
from ir.pipeline import IRPipeline

settings = get_settings()
logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))

app = FastAPI(title="AIR IR Automation", version="0.1.0")
pipeline = IRPipeline(settings)


class IngestPayload(BaseModel):
    # 앱 계약(camelCase) 그대로 수용 + 미지 필드 무시(전방 호환)
    model_config = ConfigDict(extra="allow")
    type: str


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "mode": settings.block_mode, "discord": settings.discord_enabled}


@app.post("/ingest")
def ingest(payload: IngestPayload) -> dict:
    try:
        return pipeline.handle(payload.model_dump())
    except Exception as e:  # 파이프라인 오류를 400 으로 표면화(앱이 재시도 판단)
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.get("/blocklist")
def blocklist() -> dict:
    active = pipeline.blocker.store.active()
    return {
        "mode": settings.block_mode,
        "count": len(active),
        "blocked": [
            {"ip": e.ip, "reason": e.reason, "severity": e.severity,
             "hits": e.hits, "expiresAt": int(e.expires_at)}
            for e in active
        ],
    }


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict:
    rec = pipeline.store.load(incident_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return rec
