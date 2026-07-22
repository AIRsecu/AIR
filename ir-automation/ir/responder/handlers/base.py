"""차단 핸들러 인터페이스.

모든 핸들러는 **선언적**이다: `apply(active)` 는 '지금 차단돼야 할 IP 전체'를 받아
집행 상태를 그 목록과 정확히 일치시킨다(idempotent). 만료로 목록에서 빠진 IP 는
자동으로 해제된다 — 별도 unblock 호출이 필요 없다.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ir.responder.blocklist import BlockEntry


class BlockHandler(ABC):
    #: 모드 식별자(simulation | nginx | aws_waf)
    name: str = "base"

    @abstractmethod
    def apply(self, active: list[BlockEntry]) -> None:
        """집행 상태를 active 목록과 일치시킨다(추가·유지·해제 모두 포함)."""
        raise NotImplementedError
