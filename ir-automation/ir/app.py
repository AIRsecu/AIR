"""FastAPI 진입점 — 앱(Java)이 인시던트를 POST /ingest 로 밀어넣는다.

실행: (ir-automation/ 에서)
    uvicorn ir.app:app --host 0.0.0.0 --port 8090

엔드포인트:
    POST /ingest        인시던트 수신 → 대응 파이프라인 실행
    GET  /healthz       헬스체크
    GET  /blocklist     현재 활성 차단(TTL 남은 것)
    GET  /incidents/{id}  저장된 인시던트 레코드

백그라운드: reconcile_interval_seconds 마다 만료 차단을 해제(트래픽이 없어도 제때 풀림).
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from config.settings import get_settings
from ir.pipeline import IRPipeline

settings = get_settings()
logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))
log = logging.getLogger("ir.app")

pipeline = IRPipeline(settings)


async def _reconcile_loop(interval: int) -> None:
    """주기적으로 만료 차단을 해제(이벤트가 없어도 TTL 이 제때 만료되도록)."""
    while True:
        await asyncio.sleep(interval)
        try:
            # reconcile 은 파일 I/O + nginx reload 등 블로킹 → 스레드로 오프로드
            released = await asyncio.to_thread(pipeline.blocker.reconcile)
            if released:
                log.info("[IR] 주기 reconcile — %d건 자동해제", len(released))
        except Exception as e:  # 루프가 죽지 않도록 흡수
            log.warning("[IR] 주기 reconcile 오류: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task: asyncio.Task | None = None
    if settings.reconcile_interval_seconds > 0:
        task = asyncio.create_task(_reconcile_loop(settings.reconcile_interval_seconds))
        log.info("[IR] 주기 reconcile 시작 (%ds 간격)", settings.reconcile_interval_seconds)
    yield
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="AIR IR Automation", version="0.1.0", lifespan=lifespan)


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
