"""SSOT 크로스언어 가드 — 위험도 정본(Java `RiskScoring`) ↔ IR 포팅본(`risk.py`) 동일성.

`RiskScoring.java` 가 위험도의 정본(SSOT)이고 `ir.analyzer.risk` 는 그 값을 그대로
미러한다. 두 곳의 점수표·미지 기본값·severity 사다리가 어긋나면 같은 공격이 앱과 IR
에서 다른 등급으로 판정돼(Discord CRITICAL 웹훅/차단 게이트 오작동) 조용히 발산한다.

이 테스트는 세 번째 사본을 두지 않는다. Java 소스와 Python 소스를 각각 **파싱**해
서로 대조하므로, 어느 한쪽만 값을 바꾸면 CI 가 실패한다. Java 파일 변경도 이 가드를
돌리도록 `.github/workflows/ir-tests.yml` 의 paths 에 RiskScoring.java 를 포함한다.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from ir.analyzer.risk import _SCORE, _UNKNOWN_SCORE, _severity_from_score
from ir.models.incident import Severity

# repo/ir-automation/tests/this_file → parents[2] = repo 루트
_REPO_ROOT = Path(__file__).resolve().parents[2]
_JAVA_SRC = _REPO_ROOT / "backend" / "src" / "main" / "java" / "com" / "shop" / "air" / "RiskScoring.java"


def _read_java() -> str:
    assert _JAVA_SRC.is_file(), f"위험도 정본 Java 소스를 찾을 수 없음: {_JAVA_SRC}"
    return _JAVA_SRC.read_text(encoding="utf-8")


def _parse_java_scores(src: str) -> dict[str, int]:
    """`Map.entry("TYPE", N)` 항목 → {type: score}.

    유형명은 숫자를 포함할 수 있다(예: ANOMALY_5XX_BURST) → [A-Z0-9_].
    """
    return {
        m.group(1): int(m.group(2))
        for m in re.finditer(r'Map\.entry\(\s*"([A-Z0-9_]+)"\s*,\s*(\d+)\s*\)', src)
    }


def _parse_java_unknown(src: str) -> int:
    """`SCORE.getOrDefault(type, N)` → 미지 유형 기본 점수."""
    m = re.search(r'getOrDefault\(\s*type\s*,\s*(\d+)\s*\)', src)
    assert m, "Java 미지 유형 기본값(getOrDefault) 파싱 실패 — 소스 형식이 바뀜"
    return int(m.group(1))


def _parse_java_severity_ladder(src: str) -> tuple[list[tuple[int, str]], str]:
    """severity(...) 메서드의 (임계값, 등급) 사다리와 기본 등급을 소스 순서대로 추출."""
    body = re.search(
        r'String\s+severity\s*\([^)]*\)\s*\{(.*?)\n\s*\}', src, re.DOTALL
    )
    assert body, "Java severity() 메서드 본문 파싱 실패 — 소스 형식이 바뀜"
    text = body.group(1)
    ladder = [
        (int(m.group(1)), m.group(2))
        for m in re.finditer(r'if\s*\(\s*s\s*>=\s*(\d+)\s*\)\s*return\s*"([A-Z]+)"', text)
    ]
    returns = re.findall(r'return\s*"([A-Z]+)"\s*;', text)
    assert returns, "Java severity() 의 return 문 파싱 실패"
    default_label = returns[-1]  # 사다리 맨 끝 무조건 return = 기본 등급
    return ladder, default_label


def _java_severity(score: int, ladder: list[tuple[int, str]], default_label: str) -> str:
    """파싱한 사다리로 Java severity() 를 재현 — 소스 순서상 첫 매칭 if 가 이긴다."""
    for threshold, label in ladder:
        if score >= threshold:
            return label
    return default_label


# ─────────────────────────────────────────────────────────────
# 가드 본체
# ─────────────────────────────────────────────────────────────

def test_java_source_parses_nonempty():
    """파싱이 vacuous 통과하지 않도록 — 구조가 실제로 잡혔는지 먼저 확인."""
    src = _read_java()
    scores = _parse_java_scores(src)
    ladder, default_label = _parse_java_severity_ladder(src)
    assert len(scores) >= 10, f"Java 점수 항목이 너무 적음({len(scores)}) — 파서/소스 확인"
    assert len(ladder) >= 3, f"Java severity 사다리 단계가 너무 적음({len(ladder)})"
    assert default_label == "LOW"


def test_score_table_matches_app():
    """점수표 완전 일치 — 항목 추가/삭제/값변경 어느 쪽이든 어긋나면 실패."""
    java_scores = _parse_java_scores(_read_java())
    assert dict(_SCORE) == java_scores, (
        "위험도 점수표 발산: IR risk._SCORE 와 앱 RiskScoring.SCORE 불일치.\n"
        f"  IR only : {set(_SCORE) - set(java_scores)}\n"
        f"  Java only: {set(java_scores) - set(_SCORE)}\n"
        f"  값 차이  : "
        + ", ".join(
            f"{k}: IR={_SCORE[k]} vs Java={java_scores[k]}"
            for k in set(_SCORE) & set(java_scores)
            if _SCORE[k] != java_scores[k]
        )
    )


def test_unknown_default_matches_app():
    java_unknown = _parse_java_unknown(_read_java())
    assert _UNKNOWN_SCORE == java_unknown, (
        f"미지 유형 기본 점수 발산: IR={_UNKNOWN_SCORE} vs Java={java_unknown}"
    )


def test_severity_ladder_matches_app():
    """0~100 전 구간에서 등급 판정이 동일해야 한다(임계값 경계 포함)."""
    ladder, default_label = _parse_java_severity_ladder(_read_java())
    mismatches = [
        (s, _severity_from_score(s).value, _java_severity(s, ladder, default_label))
        for s in range(0, 101)
        if _severity_from_score(s).value != _java_severity(s, ladder, default_label)
    ]
    assert not mismatches, (
        "severity 사다리 발산(점수 → IR등급 vs Java등급):\n  "
        + "\n  ".join(f"score={s}: IR={py} vs Java={jv}" for s, py, jv in mismatches[:10])
    )


def test_severity_labels_are_the_same_set():
    """IR Severity enum 과 Java 가 내는 등급 문자열 집합이 동일해야 한다."""
    ladder, default_label = _parse_java_severity_ladder(_read_java())
    java_labels = {label for _, label in ladder} | {default_label}
    py_labels = {s.value for s in Severity}
    assert py_labels == java_labels, (
        f"등급 라벨 집합 발산: IR={sorted(py_labels)} vs Java={sorted(java_labels)}"
    )
