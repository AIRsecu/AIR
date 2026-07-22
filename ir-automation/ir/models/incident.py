"""Incident — 모든 IR 모듈이 공유하는 단일 계약(contract).

앱(Java `com.shop.air.SecurityIncident`)의 필드/의미를 1:1로 맞춰 매핑 로스 없이
주고받는다. 앱은 camelCase(JSON: clientIp/actionTaken/createdAt)로 보내고,
파이썬 내부는 snake_case로 다룬다 — pydantic alias 로 양방향 처리한다.

앱 계약 필드: id, type, endpoint, clientIp, actor, payload, actionTaken, status, createdAt
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

# 앱 payload 절단 상한(Java IncidentService.truncate 와 동일)
_PAYLOAD_MAX = 2000


class Severity(str, Enum):
    """위험 등급 — 앱 RiskScoring 과 동일한 4단계."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Incident(BaseModel):
    """앱에서 수신하는 인시던트(사후 대응의 입력).

    - `populate_by_name=True`: 파이썬 필드명(client_ip)·alias(clientIp) 둘 다 허용.
    - `extra="ignore"`: 앱이 필드를 추가해도 깨지지 않음(전방 호환).
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    id: str | None = None
    type: str = Field(..., description="ORDER_NEGATIVE_QTY, SQLI_ATTEMPT, IDOR_ATTEMPT ...")
    endpoint: str | None = None
    client_ip: str | None = Field(default=None, alias="clientIp")
    actor: str | None = None
    payload: str | None = None
    action_taken: str | None = Field(default=None, alias="actionTaken")
    status: str | None = None
    created_at: datetime | None = Field(default=None, alias="createdAt")

    @field_validator("type")
    @classmethod
    def _normalize_type(cls, v: str) -> str:
        # 유형은 대문자 상수로 통일(앱 시그니처와 매칭되도록)
        return (v or "").strip().upper() or "UNKNOWN_ANOMALY"

    @field_validator("payload")
    @classmethod
    def _truncate_payload(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return v[:_PAYLOAD_MAX] + "…" if len(v) > _PAYLOAD_MAX else v

    def ensure_id(self) -> str:
        """id 가 비어 오면(로그 유입 등) uuid4 로 채운다. 앱 유입은 ULID 그대로 유지."""
        if not self.id:
            self.id = uuid.uuid4().hex
        return self.id

    def dedup_key(self) -> str:
        """(유형+출처) 기준 중복 판별 키 — 앱 IncidentService 의 dedupKey 규약과 동일."""
        who = self.client_ip or self.actor or self.endpoint or "-"
        return f"{self.type}|{who}"

    def to_contract(self) -> dict:
        """앱 계약(camelCase) JSON 으로 직렬화."""
        return self.model_dump(by_alias=True, mode="json")
