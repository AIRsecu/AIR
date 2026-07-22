"""인시던트 영속 — 대응 결과까지 합친 레코드를 incidents/<id>.json 으로 저장.

앱의 원본 인시던트 + IR 이 산정한 risk + 수행한 대응(actionTaken)을 한 파일에 담아
NIST IR(Detect→Analyze→Contain→Recover) 추적 근거로 남긴다. 원자적 쓰기.

확장: 선택적 ``StatsIndex`` 훅 — save() 후 인덱스/통계 incremental 갱신.
  find()/stats_snapshot() 추가. save/load/recent 시그니처는 하위 호환 유지.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ir.models.incident import Incident
from ir.store._atomic import atomic_write_json
from ir.store.stats import StatsIndex


class IncidentStore:
    def __init__(
        self,
        base_path: Path,
        *,
        stats: StatsIndex | None = None,
    ):
        self.base = Path(base_path)
        self._stats = stats

    def save(
        self,
        incident: Incident,
        *,
        risk: dict,
        response: dict,
        notified: bool,
    ) -> Path:
        self.base.mkdir(parents=True, exist_ok=True)
        record = {
            "incident": incident.to_contract(),
            "risk": risk,                 # {score, severity, block_seconds}
            "response": response,         # {action, ip, mode, ttl_seconds, hits}
            "notified": notified,
            # NIST IR 단계 태깅 — 대시보드/보고서용
            "playbook": {
                "detect": True,
                "analyze": True,
                "contain": response.get("enforced", False),
                "recover": False,  # 회복(패치/복구)은 앱 orchestrator 담당
            },
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        path = self.base / f"{incident.ensure_id()}.json"
        atomic_write_json(path, record)
        if self._stats is not None:
            self._stats.record(
                incident_id=incident.ensure_id(),
                attack_type=incident.type,
                client_ip=incident.client_ip,
                occurred_at=incident.created_at,
            )
        return path

    def load(self, incident_id: str) -> dict | None:
        path = self.base / f"{incident_id}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def recent(self, limit: int = 50) -> list[dict]:
        if not self.base.exists():
            return []
        files = sorted(self.base.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        out = []
        for p in files[:limit]:
            try:
                out.append(json.loads(p.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError):
                continue
        return out

    def find(
        self,
        *,
        ip: str | None = None,
        type: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """인덱스 기반 검색. stats 미주입 시 []. 반환은 load() 와 동일 dict 스키마."""
        if self._stats is None:
            return []
        ids = self._stats.find(ip=ip, type=type, limit=limit)
        out: list[dict] = []
        for iid in ids:
            rec = self.load(iid)
            if rec is not None:
                out.append(rec)
        return out

    def stats_snapshot(self) -> dict | None:
        """통계 스냅샷(공개 필드만). stats 미주입 시 None."""
        if self._stats is None:
            return None
        return self._stats.stats_dict()
