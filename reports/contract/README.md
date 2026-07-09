# reports/contract — 정규 보안 리포트 계약 & 통합기

팀 브랜치마다 형태가 다른 보안 리포트를 **하나의 통합 리포트**로 수렴시키는 계약(schema)과
노멀라이저(adapter) + 애그리게이터. 무의존(stdlib only), 파이썬 3.11+.

## 왜 필요한가 — 발산 3지점

브랜치별 리포트를 실측한 결과, 통계 요약(`sec-summary.json`)은 이미 동일하지만 다음이 발산한다:

1. **심각도 어휘 3종** — semgrep `ERROR/WARNING/INFO` · trivy/IR `CRITICAL~LOW` · zap `High (Medium)` · AI `Critical~Info`
2. **리포트 형태 4종** — 카운트 JSON · 파인딩 배열 JSON · 자유서술 마크다운(`ai_final_report.md`) · 런타임 인시던트 객체
3. **빌드타임↔런타임 단절** — CI 스캔과 런타임 IR 인시던트가 공유 식별자 없음

이 모듈은 ①심각도를 정규 taxonomy 1종으로, ②모두를 정규 `Finding` 엔벨로프로,
③`correlation_key`(정규 CWE 우선)로 빌드↔런타임을 조인해 해소한다.

## 구조

```
reports/contract/
  finding.py         # 정규 엔벨로프(Finding) + Severity/Source/Stage + CWE 정규화
  severity_map.py    # 3종 어휘 → 정규 taxonomy 1종
  adapters/
    from_semgrep.py  # semgrep_for_llm.json → Finding[]
    from_trivy.py    # trivy_for_llm.json   → Finding[]
    from_zap.py      # zap_for_llm.json     → Finding[]
    from_ir.py       # IR 인시던트 레코드   → Finding[]   (병록 파트/런타임)
    from_ai.py       # ai_findings.json     → 판정 캐리어(verdict 보강)
  aggregate.py       # 수집→AI보강→상관→ unified_report.json + .md
  samples/           # --demo 용 픽스처(교차상관 시연 포함)
  test_contract.py   # 무의존 스모크 테스트(unittest)
```

## 사용

```bash
# 번들 샘플로 즉시 시연 (스캔 산출물 없이)
python reports/contract/aggregate.py --demo

# 실제 CI 산출물 통합 (reports/ 아래에서 있는 것만 자동 수집)
python reports/contract/aggregate.py

# 테스트
python reports/contract/test_contract.py
```

기대 입력 경로(있는 것만 사용):
```
reports/semgrep/semgrep_for_llm.json
reports/trivy/trivy_for_llm.json
reports/zap/zap_for_llm.json
reports/summary/ai_findings.json          # ← AI 구조화 판정(아래 '연결' 참고)
reports/ir/incidents.json  또는  reports/ir/incidents/*.json
```
출력: `reports/summary/unified_report.json`, `reports/summary/unified_report.md`

## CI 연결 (security.yml)

기존 `summary` 잡의 `Generate Security Summary` 다음에 한 스텝만 추가:
```yaml
      - name: Aggregate unified report
        run: python reports/contract/aggregate.py
      - name: Publish unified report
        run: cat reports/summary/unified_report.md >> $GITHUB_STEP_SUMMARY
```
→ 팀원들은 각자 `security.yml`/`generate_summary.py`를 손대는 대신 **계약(Finding)만 타깃**하면
되므로, 같은 파일 재편집으로 인한 병합 충돌이 줄어든다.

### AI 판정을 기계 병합 가능하게 (from_ai 입력)

현재 `run_ai_pipeline.py`는 판정을 마크다운으로만 배출한다. 아래 구조의
`reports/summary/ai_findings.json`을 **추가 배출**하면 `from_ai`가 스캐너 파인딩에 verdict를 보강한다:
```json
[{ "scan_tool": "SAST", "rule_id": "...", "cwe": "CWE-89",
   "file_path": "...", "line_number": 42,
   "triage": {"is_false_positive": false, "reason": "..."},
   "assessment": {"final_risk": "High", "reason": "..."} }]
```
(각 노드의 `TriageResult`/`RiskAssessment`를 리스트에 append 후 `json.dump` 한 줄이면 됨.)

## 확장

- 새 소스 추가 = `adapters/from_<x>.py`에 `to_findings(payload) -> list[Finding]` 하나만 작성하고
  `aggregate.collect()`에 한 줄 등록. 계약(finding.py)은 건드리지 않는다.
- 심각도 매핑 변경 = `severity_map.py` 표만 수정.
- 런타임 유형↔CWE 상관 추가 = `adapters/from_ir.py`의 `IR_TYPE_TO_CWE`.

## 한계 (스캐폴드)

- AI verdict 매칭은 `correlation_key`(CWE) 기준이라, 같은 CWE의 서로 다른 파인딩에
  동일 판정이 붙을 수 있다. 파일/라인 정밀 매칭이 필요하면 `enrich_with_ai`를 강화.
- `from_app`(com.shop.air 앱 내 탐지)은 미구현 — IR와 동일 패턴으로 추가 가능.
