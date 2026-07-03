"""인시던트 영속 — 대응 결과까지 합친 레코드를 incidents/<id>.json 으로 저장.

앱의 원본 인시던트 + IR 이 산정한 risk + 수행한 대응(actionTaken)을 한 파일에 담아
NIST IR(Detect→Analyze→Contain→Recover) 추적 근거로 남긴다. 원자적 쓰기.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from ir.models.incident import Incident


class IncidentStore:
    def __init__(self, base_path: Path):
        self.base = Path(base_path)

    def save(self, incident: Incident, *, risk: dict, response: dict,
             notified: bool) -> Path:
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
        self._atomic_write(path, record)
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

    @staticmethod
    def _atomic_write(path: Path, obj: dict) -> None:
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
