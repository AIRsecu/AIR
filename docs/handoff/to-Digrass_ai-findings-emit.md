# 핸드오프 → Digrass: 구조화 판정 배출 `ai_findings.json`

현재 `run_ai_pipeline.py` 는 판정을 `ai_final_report.md`(사람용)로만 씁니다.
병록 통합기가 AI 판정을 스캐너 파인딩에 **자동 보강**하려면 기계가 읽을 JSON 이 하나 더 필요합니다.
**MD 배출은 그대로 두고** 아래만 추가하면 됩니다. (판정 사유 키는 `fp_reason`/`impact_reason`
그대로 둬도 병록 어댑터가 수용 — `.model_dump()` 만 하면 됩니다.)

## 패치 — `scripts/ai_agent/run_ai_pipeline.py`

### 1) 상단에 수집 리스트 + 헬퍼 추가
```python
ai_records = []

def _record(scan_tool, vuln, final_state):
    triage = final_state.get("triage_result")
    risk = final_state.get("risk_assessment")
    ai_records.append({
        "scan_tool": scan_tool,
        "rule_id": vuln.get("rule_id") or vuln.get("cve_id") or vuln.get("alert_name"),
        "cwe": vuln.get("cwe") or vuln.get("cwe_id"),
        "file_path": vuln.get("file_path"),
        "line_number": vuln.get("line_number"),
        "triage": triage.model_dump() if triage else {},
        "assessment": risk.model_dump() if risk else {},
    })
```

### 2) `run_agent_for_finding` 이 final_state 를 돌려주게 (return 한 줄만)
```python
def run_agent_for_finding(scan_tool, vuln_data, sys_context):
    initial_state = {"scan_tool": scan_tool, "system_context": sys_context, "vuln_data": vuln_data}
    final_state = security_pipeline.invoke(initial_state)
    return final_state            # 기존: return final_state["final_report_md"]
```

### 3) 세 호출부(SAST/Trivy/DAST) 각각 2줄로
```python
    final_state = run_agent_for_finding("SAST", vuln, sys_context)   # 스캔툴명만 각기
    report_md = final_state["final_report_md"]
    _record("SAST", vuln, final_state)
    f.write(report_md + "\n\n")
```

### 4) main() 끝(FINAL_MD with 블록 뒤)에서 dump
```python
    import json
    (FINAL_MD.parent / "ai_findings.json").write_text(
        json.dumps(ai_records, ensure_ascii=False, indent=2), encoding="utf-8")
```

## 결과

`reports/summary/ai_findings.json` 이 생기고, 병록 `aggregate.py` 가 이를 읽어
스캐너 파인딩에 `verdict`(오탐 여부 / 재산정 위험도 / 사유)를 자동으로 얹습니다.

## 없어도 안 깨짐

이 파일이 없으면 통합기는 **AI 보강만 생략**하고 정상 동작(graceful). 즉 파이프라인 필수 아님,
'통합 리포트에 AI 판정을 얹으려면' 필요한 옵션 배선입니다.
