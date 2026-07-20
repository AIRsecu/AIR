"""컨텍스트 스코어링 가중치 규칙 — 코드 상수(immutable).

설계:
  - base score(앱 RiskScoring) 위에 얹는 가산점만 정의한다.
  - 딕셔너리/튜플은 MappingProxyType·tuple 로 런타임 변조를 막는다.
  - payload 정규식은 전부 re.compile 프리컴파일 + 백트래킹 유발 패턴 금지.

최종 점수: clamp(base + endpoint + payload + recidivism + time, 0, 100)
"""
from __future__ import annotations

import re
from types import MappingProxyType
from typing import Mapping

# ─────────────────────────────────────────────────────────────
# 스칼라 가중치
# ─────────────────────────────────────────────────────────────

NIGHT_WEIGHT = 5
RECIDIVISM_WEIGHT = 10
# 한 payload 에 시그니처가 여러 개 맞아도 폭주하지 않게 상한
PAYLOAD_WEIGHT_CAP = 20

# ─────────────────────────────────────────────────────────────
# endpoint 민감도 — fnmatch 패턴 → 가산점
# 여러 패턴이 동시에 매칭되면 **최댓값**만 적용(이중 가산 방지)
# ─────────────────────────────────────────────────────────────

ENDPOINT_WEIGHTS: Mapping[str, int] = MappingProxyType({
    "/admin/*": 15,
    "/api/*/admin/*": 15,
    "*/delete": 15,
    "*/tenants/*": 15,
    "/api/v1/auth/*": 10,
    "/login*": 10,
})

# ─────────────────────────────────────────────────────────────
# payload 시그니처 — (이름, compiled regex, 가산점)
#
# ReDoS 방어:
#   - 중첩 수량자 `(a+)+`, 모호 분기 `(a|a)*` 등 금지
#   - 고정 리터럴 + 단순 `\s+` / 문자클래스만 사용
# ─────────────────────────────────────────────────────────────

_PAYLOAD_SIGS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    # SQL 고위험: DDL/UNION/확장 프로시저
    (
        "sql_drop_table",
        re.compile(r"drop\s+table", re.IGNORECASE),
        20,
    ),
    (
        "sql_union_select",
        re.compile(r"union\s+select", re.IGNORECASE),
        20,
    ),
    (
        "sql_xp_cmdshell",
        re.compile(r"xp_cmdshell", re.IGNORECASE),
        20,
    ),
    # SQL/XSS 일반
    (
        "sql_or_inject",
        # `' OR ` / `' or 1` 형태 — 고정 따옴표 + 단순 or
        re.compile(r"'\s*or\s+", re.IGNORECASE),
        10,
    ),
    (
        "xss_script",
        re.compile(r"<script\b", re.IGNORECASE),
        10,
    ),
    (
        "xss_javascript_uri",
        re.compile(r"javascript\s*:", re.IGNORECASE),
        10,
    ),
    # Path traversal
    (
        "path_dotdot_slash",
        re.compile(r"\.\./"),
        15,
    ),
    (
        "path_dotdot_backslash",
        re.compile(r"\.\.\\"),
        15,
    ),
    (
        "path_dotdot_encoded",
        re.compile(r"%2e%2e", re.IGNORECASE),
        15,
    ),
)

# 외부에서 읽기 전용으로만 노출
PAYLOAD_SIGNATURES: tuple[tuple[str, re.Pattern[str], int], ...] = _PAYLOAD_SIGS


def clamp_score(value: int) -> int:
    """최종 점수를 [0, 100] 으로 제한."""
    return max(0, min(100, value))


def match_endpoint_weight(endpoint: str | None) -> int:
    """민감 endpoint 가산점. 매칭 없으면 0, 복수 매칭 시 최댓값."""
    if not endpoint:
        return 0
    from fnmatch import fnmatch

    best = 0
    for pattern, weight in ENDPOINT_WEIGHTS.items():
        if fnmatch(endpoint, pattern):
            best = max(best, weight)
    return best


def match_payload_weight(payload: str | None) -> tuple[int, list[str]]:
    """
    payload 시그니처 가산점과 매칭된 시그니처 이름 목록.

    합산 후 PAYLOAD_WEIGHT_CAP(20) 으로 clamp.
    """
    if not payload:
        return 0, []
    total = 0
    matched: list[str] = []
    for name, pattern, weight in PAYLOAD_SIGNATURES:
        if pattern.search(payload):
            total += weight
            matched.append(name)
    return min(total, PAYLOAD_WEIGHT_CAP), matched


def recidivism_weight(*, recent_hits: int, block_hits: int) -> int:
    """
    재범 가산점.

    - recent_hits: 슬라이딩 윈도우 내 이전 이벤트 수(현재 이벤트 제외)
    - block_hits: BlockStore 영속 hits
    - 단기 또는 장기 신호가 재범(≥2)이면 +RECIDIVISM_WEIGHT
    """
    if recent_hits >= 2 or block_hits >= 2:
        return RECIDIVISM_WEIGHT
    return 0
