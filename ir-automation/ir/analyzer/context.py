"""컨텍스트 스코어링 입력 — RiskContext + 인메모리 재범 트래커.

RiskContext:
    assess_with_context / RiskAnalyzer 가 소비하는 불변 스냅샷.
    Incident 필드에서 파생하며, block_hits 는 BlockStore 등 외부 신호를 담는다.

RecidivismTracker:
    IP → 최근 이벤트 시각(deque) 슬라이딩 윈도우.
    - IP별 최근 1000개 타임스탬프(maxlen) — 초과 시 오래된 것부터 eviction
    - 추적 IP 수도 1000개 LRU 상한 — 무한 누적 방지
    - **프로세스 재시작 시 전부 유실**된다. 장기 재범 신호는 BlockStore.hits 가 담당.
    - threading.Lock — sync ingest + asyncio.to_thread(reconcile) 동시 접근 안전.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime

from ir.models.incident import Incident

# IP별 / 전역 IP 수 상한 — 메모리 폭주 방지
_DEFAULT_MAX_HITS_PER_IP = 1000
_DEFAULT_MAX_TRACKED_IPS = 1000


@dataclass(frozen=True)
class RiskContext:
    """컨텍스트 스코어링용 불변 입력."""

    endpoint: str | None = None
    payload: str | None = None
    client_ip: str | None = None
    occurred_at: datetime | None = None
    block_hits: int = 0  # BlockStore 영속 hits(없으면 0)

    @classmethod
    def from_incident(
        cls,
        incident: Incident,
        *,
        block_hits: int = 0,
    ) -> RiskContext:
        """Incident 계약 필드에서 컨텍스트 스냅샷 생성."""
        return cls(
            endpoint=incident.endpoint,
            payload=incident.payload,
            client_ip=incident.client_ip,
            occurred_at=incident.created_at,
            block_hits=block_hits,
        )


class RecidivismTracker:
    """
    인메모리 IP 재범 슬라이딩 윈도우.

    한계(의도적):
      - 프로세스 재시작 시 유실 → 영속 신호는 BlockStore.hits 로 보완
      - 멀티프로세스 배포 시 워커별 파편화 (Lock 은 프로세스 내 스레드만 보호)
    """

    def __init__(
        self,
        *,
        max_hits_per_ip: int = _DEFAULT_MAX_HITS_PER_IP,
        max_tracked_ips: int = _DEFAULT_MAX_TRACKED_IPS,
    ) -> None:
        self._max_hits_per_ip = max_hits_per_ip
        self._max_tracked_ips = max_tracked_ips
        self._lock = threading.Lock()
        # OrderedDict: 최근 접근 IP 가 끝으로 — 초과 시 앞에서 pop (LRU)
        self._events: OrderedDict[str, deque[float]] = OrderedDict()

    def record(self, ip: str, *, now: float | None = None) -> None:
        """IP 이벤트 시각 기록. IP별 maxlen + 전역 LRU 상한 적용."""
        if not ip:
            return
        now = time.time() if now is None else now
        with self._lock:
            if ip in self._events:
                self._events.move_to_end(ip)
                self._events[ip].append(now)
            else:
                self._events[ip] = deque([now], maxlen=self._max_hits_per_ip)
                while len(self._events) > self._max_tracked_ips:
                    self._events.popitem(last=False)

    def count(
        self,
        ip: str,
        window_seconds: int,
        *,
        now: float | None = None,
    ) -> int:
        """윈도우 내 이전 이벤트 수. 만료분 prune 후 반환."""
        if not ip:
            return 0
        now = time.time() if now is None else now
        with self._lock:
            dq = self._events.get(ip)
            if not dq:
                return 0
            cutoff = now - window_seconds
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                self._events.pop(ip, None)
                return 0
            self._events.move_to_end(ip)  # LRU touch
            return len(dq)

    def __len__(self) -> int:
        """추적 중인 IP 수(관측/테스트용)."""
        with self._lock:
            return len(self._events)
