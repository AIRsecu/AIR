"""정규 리포트 계약 (Unified Security Finding).

팀 브랜치들이 서로 다른 형태로 뱉는 리포트(semgrep/trivy/zap 추출본,
AI 판정 마크다운, 런타임 IR 인시던트)를 '단 하나의 Finding 형태'로 수렴시킨다.

설계 원칙:
  - 무의존(stdlib only): 어느 파이썬 3.11+ 환경에서나 pip 설치 없이 실행.
    (교차-브랜치 통합 도구라 설치 마찰이 0이어야 한다.)
  - 관용적 계약(ir-automation Incident 패턴 계승): 소스가 필드를 추가해도
    깨지지 않는다 — 알 수 없는 키는 raw 로 보존하고 무시한다.
  - 직렬화는 항상 to_contract() 한 경로로.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """정규 심각도 taxonomy (단일 어휘). 모든 소스 심각도가 여기로 매핑된다."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]


class Source(str, Enum):
    SEMGREP = "semgrep"   # SAST
    TRIVY = "trivy"       # 의존성/컨테이너
    ZAP = "zap"           # DAST
    IR = "ir-runtime"     # 런타임 자동대응(병록 파트)
    APP = "app"           # 앱 내 탐지(com.shop.air)
    AI = "ai"             # LLM 위험 재평가(판정 캐리어)


class Stage(str, Enum):
    BUILD = "build"       # CI 파이프라인(정적/동적 스캔)
    RUNTIME = "runtime"   # 실행 중 탐지·대응


_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def normalize_cwe(raw: Any) -> Optional[str]:
    """다양한 표기(리스트/'CWE-89: ...'/숫자)를 'CWE-89' 정규형으로."""
    if raw is None:
        return None
    if isinstance(raw, (list, tuple)):
        for x in raw:
            c = normalize_cwe(x)
            if c:
                return c
        return None
    m = _CWE_RE.search(str(raw))
    if m:
        return f"CWE-{int(m.group(1))}"
    s = str(raw).strip()
    return f"CWE-{int(s)}" if s.isdigit() else None


def _clean(d: dict) -> dict:
    """None 값을 제거한 얕은 딕셔너리."""
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class Location:
    file: Optional[str] = None
    line: Optional[int] = None
    endpoint: Optional[str] = None
    url: Optional[str] = None
    client_ip: Optional[str] = None
    package: Optional[str] = None

    def to_contract(self) -> dict:
        return _clean(self.__dict__)


@dataclass
class Verdict:
    """LLM(또는 사람) 재평가 결과. 스캔 파인딩을 '보강'하는 정보."""
    is_false_positive: Optional[bool] = None
    final_risk: Optional[Severity] = None
    reason: Optional[str] = None

    def to_contract(self) -> dict:
        d = dict(self.__dict__)
        if isinstance(d.get("final_risk"), Severity):
            d["final_risk"] = d["final_risk"].value
        return _clean(d)


@dataclass
class Response:
    """대응 조치. 런타임(IR) 소스가 채운다."""
    action_taken: Optional[str] = None
    status: Optional[str] = None
    mode: Optional[str] = None
    ttl_seconds: Optional[int] = None
    enforced: Optional[bool] = None

    def to_contract(self) -> dict:
        return _clean(self.__dict__)


@dataclass
class Finding:
    """모든 소스가 수렴하는 정규 리포트 엔벨로프."""

    id: str
    source: Source
    stage: Stage
    severity: Severity
    type: str                                   # rule_id / cve_id / alert_name / incident type
    title: Optional[str] = None
    location: Location = field(default_factory=Location)
    message: Optional[str] = None
    evidence: Optional[str] = None              # code_snippet / payload / evidence
    cwe: Optional[str] = None
    verdict: Optional[Verdict] = None
    response: Optional[Response] = None
    correlation_key: Optional[str] = None       # 빌드↔런타임 조인 키(정규 CWE 우선)
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.correlation_key:
            self.correlation_key = self._compute_correlation_key()

    def _compute_correlation_key(self) -> str:
        if self.cwe:
            return self.cwe
        base = (self.type or "unknown").strip().upper()
        return re.sub(r"[^A-Z0-9]+", "-", base).strip("-") or "UNKNOWN"

    def to_contract(self) -> dict:
        return {
            "id": self.id,
            "source": self.source.value,
            "stage": self.stage.value,
            "severity": self.severity.value,
            "type": self.type,
            "title": self.title,
            "location": self.location.to_contract() if self.location else {},
            "message": self.message,
            "evidence": self.evidence,
            "cwe": self.cwe,
            "verdict": self.verdict.to_contract() if self.verdict else None,
            "response": self.response.to_contract() if self.response else None,
            "correlation_key": self.correlation_key,
        }
