# 핸드오프 → Digrass: 구조화 판정 배출 `ai_findings.json` (1줄 수준)

현재 `run_ai_pipeline.py` 는 판정을 `ai_final_report.md`(사람용 서술)로만 씁니다.
병록의 통합기(`reports/contract/aggregate.py`)가 AI 판정을 스캐너 파인딩에 **자동 보강**하려면
기계가 읽을 구조화 JSON 이 하나 더 필요합니다. **MD 배출은 그대로 두고** 아래만 추가하면 됩니다.

## 계약 — `reports/summary/ai_findings.json`

```json
[
  {
    "scan_tool": "SAST",
    "rule_id": "java.lang.security.audit.sqli.jdbc-sqli",
    "cwe": "CWE-89",
    "file_path": "backend/.../ProductMapper.java",
    "line_number": 42,
    "triage":     { "is_false_positive": false, "reason": "..." },
    "assessment": { "final_risk": "High", "reason": "..." }
  }
]
```

`triage` = `TriageResult`, `assessment` = `RiskAssessment` — 이미 그래프가 생성하는 값 그대로입니다.

## 구현 스케치 (`run_ai_pipeline.py`)

각 finding 루프에서 최종 state 를 리스트에 담고 끝에서 dump:

```python
ai_records = []
# ... 루프 안:
final_state = security_pipeline.invoke(initial_state)
ai_records.append({
    "scan_tool": scan_tool,
    "rule_id": vuln.get("rule_id"),
    "cwe": vuln.get("cwe") or vuln.get("cwe_id"),
    "file_path": vuln.get("file_path"),
    "line_number": vuln.get("line_number"),
    "triage": final_state["triage_result"].model_dump(),
    "assessment": (final_state.get("risk_assessment").model_dump()
                   if final_state.get("risk_assessment") else {}),
})
# ... 루프 뒤:
import json
Path("reports/summary/ai_final_report.md")  # 기존 그대로
Path("reports/summary/ai_findings.json").write_text(
    json.dumps(ai_records, ensure_ascii=False, indent=2), encoding="utf-8")
```

## 없어도 안 깨짐

`ai_findings.json` 이 없으면 병록 통합기는 **AI 보강만 생략**하고 정상 동작합니다(graceful).
즉 이 핸드오프는 '통합 리포트에 AI 판정을 얹으려면' 필요한 것이지, 파이프라인 필수는 아닙니다.
