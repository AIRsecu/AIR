"""TTL 블록리스트 저장소 — 차단 IP 를 만료시각과 함께 JSON 으로 영속한다.

핵심 설계: **선언적 상태(desired state)**.
  각 IP 는 expires_at 을 가지며, 만료되면 active 집합에서 자동으로 빠진다.
  responder 는 매번 active 집합을 계산해 핸들러에 '이 목록이 지금 차단돼야 할 전부'라고
  선언한다 → 만료 해제가 별도 unblock 코드 없이 reconcile 로 자연히 처리된다.

원자적 쓰기(temp+os.replace)로 동시 쓰기 시 파일 손상을 막는다.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class BlockEntry:
    ip: str
    reason: str  # 인시던트 유형(SQLI_ATTEMPT ...)
    severity: str
    mode: str  # simulation | nginx | aws_waf
    incident_id: str
    blocked_at: float  # epoch seconds
    expires_at: float  # epoch seconds
    hits: int = 1  # 같은 IP 가 몇 번 걸렸는지(멱등 연장 시 증가)

    def is_active(self, now: float) -> bool:
        return self.expires_at > now

    def remaining(self, now: float) -> int:
        return max(0, int(self.expires_at - now))


class BlockStore:
    """IP → BlockEntry 를 JSON 파일로 관리. 프로세스 재시작에도 TTL 이 유지된다.

    threading.Lock — sync ingest + asyncio.to_thread(reconcile) 동시 접근 안전.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._entries: dict[str, BlockEntry] = self._load()

    def _load(self) -> dict[str, BlockEntry]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
        return {ip: BlockEntry(**data) for ip, data in raw.items()}

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {ip: asdict(e) for ip, e in self._entries.items()}
        # 원자적 교체 — 같은 디렉터리 temp 에 쓰고 rename
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def upsert(self, ip: str, *, reason: str, severity: str, mode: str,
               incident_id: str, ttl_seconds: int, now: float | None = None) -> tuple[BlockEntry, bool]:
        """차단 등록/재무장(rearm). 반환 (entry, is_new).

        멱등성: 이미 활성 차단 중이면 새로 만들지 않고
        만료시각을 새 TTL 로 재무장(덮어쓰기: ``expires_at = now + ttl_seconds``) + hits 증가.
        남은 TTL 에 가산하지 않는다(누적 연장이 아님).
        """
        now = time.time() if now is None else now
        with self._lock:
            existing = self._entries.get(ip)
            if existing and existing.is_active(now):
                existing.expires_at = now + ttl_seconds  # 재무장(rearm) — 남은 시간 무시하고 덮어쓰기
                existing.hits += 1
                existing.severity = severity  # 최신 등급 반영
                self._persist()
                return existing, False
            entry = BlockEntry(
                ip=ip, reason=reason, severity=severity, mode=mode,
                incident_id=incident_id, blocked_at=now, expires_at=now + ttl_seconds,
                hits=(existing.hits + 1) if existing else 1,
            )
            self._entries[ip] = entry
            self._persist()
            return entry, True

    def prune(self, now: float | None = None) -> list[BlockEntry]:
        """만료 항목 제거. 제거된 목록 반환(로그/알림용)."""
        now = time.time() if now is None else now
        with self._lock:
            expired = [e for e in self._entries.values() if not e.is_active(now)]
            if expired:
                for e in expired:
                    self._entries.pop(e.ip, None)
                self._persist()
            return expired

    def active(self, now: float | None = None) -> list[BlockEntry]:
        now = time.time() if now is None else now
        with self._lock:
            return [e for e in self._entries.values() if e.is_active(now)]

    def get(self, ip: str) -> BlockEntry | None:
        with self._lock:
            return self._entries.get(ip)
