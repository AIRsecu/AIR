"""소스 산출물 발견·로딩 — reports/ 아래 각 소스 파일을 정규 Finding 으로 수집.

aggregate.py 에서 분리(SRP): 이 모듈은 '어디서 무엇을 읽어오는가'(파일 I/O + 어댑터 디스패치)만
책임진다. 상관/집계는 correlate.py, 렌더는 render.py, 배선/CLI 는 aggregate.py.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# 혼합 저장소(코드+산출물)에서 플랫 임포트가 되도록 이 디렉터리를 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from finding import Finding  # noqa: E402
from adapters import from_ir, from_semgrep, from_trivy, from_zap  # noqa: E402


def _load_json(path: Path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _read_ir_path(path: Path) -> list[dict]:
    """파일(배열/단일) 또는 디렉터리(*.json 레코드당 1파일)를 인시던트 레코드 리스트로."""
    if path.is_dir():
        out: list[dict] = []
        for p in sorted(path.glob("*.json")):
            rec = _load_json(p)
            if isinstance(rec, list):
                out.extend(rec)
            elif rec:
                out.append(rec)
        return out
    if path.exists():
        data = _load_json(path)
        if isinstance(data, list):
            return data
        return [data] if data else []
    return []


def _load_ir_records(reports_dir: Path) -> list[dict]:
    """IR 인시던트 수집.

    경로 우선순위:
      1) 환경변수 INCIDENT_STORAGE_PATH (IR store 가 실제로 쓰는 경로 — 병록 IR config)
      2) reports/ir/incidents.json
      3) reports/ir/incidents/*.json
    """
    env_path = os.environ.get("INCIDENT_STORAGE_PATH")
    if env_path:
        recs = _read_ir_path(Path(env_path))
        if recs:
            return recs
    for candidate in (reports_dir / "ir" / "incidents.json", reports_dir / "ir" / "incidents"):
        recs = _read_ir_path(candidate)
        if recs:
            return recs
    return []


def collect(reports_dir: Path) -> list[Finding]:
    """있는 소스만 골라 정규 Finding 으로 수집."""
    findings: list[Finding] = []

    semgrep = _load_json(reports_dir / "semgrep" / "semgrep_for_llm.json")
    if isinstance(semgrep, list):
        findings += from_semgrep.to_findings(semgrep)

    trivy = _load_json(reports_dir / "trivy" / "trivy_for_llm.json")
    if isinstance(trivy, list):
        findings += from_trivy.to_findings(trivy)

    zap = _load_json(reports_dir / "zap" / "zap_for_llm.json")
    if isinstance(zap, list):
        findings += from_zap.to_findings(zap)

    findings += from_ir.to_findings(_load_ir_records(reports_dir))
    return findings
