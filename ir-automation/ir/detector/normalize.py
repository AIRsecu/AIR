"""수신 이벤트 정규화 — 원시 dict → Incident(공용 계약).

앱이 보내는 구조화 JSON(camelCase)이 1차 입력이다. 로그 tail 같은 폴백 경로가
생기더라도 이 함수 하나만 통과시키면 이후 파이프라인은 동일하게 동작한다.
"""
from __future__ import annotations

from ir.models.incident import Incident


def normalize(raw: dict) -> Incident:
    """앱 계약(camelCase)·내부(snake_case) 를 모두 수용해 Incident 로 변환.

    pydantic 의 alias + populate_by_name 으로 양쪽 키를 허용한다.
    id 가 없으면 채우고(로그 유입 대비), type 은 모델에서 대문자 정규화된다.
    """
    incident = Incident.model_validate(raw)
    incident.ensure_id()
    return incident
