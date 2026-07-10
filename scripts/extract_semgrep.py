import json
from pathlib import Path

SEMGREP_PATH = Path("reports/semgrep/semgrep.json")
OUTPUT_PATH = Path("reports/semgrep/semgrep_for_llm.json")

print("Extracting Semgrep vulnerabilities for LLM analysis...")

extracted_findings = []

if SEMGREP_PATH.exists():
    with open(SEMGREP_PATH, encoding="utf-8") as f:
        semgrep_data = json.load(f)

    for result in semgrep_data.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        
        # 라인 번호 추출 (여러 줄에 걸쳐 있을 경우 시작-끝 표시)
        start_line = result.get("start", {}).get("line", "Unknown")
        end_line = result.get("end", {}).get("line", "Unknown")
        line_info = str(start_line) if start_line == end_line else f"{start_line}-{end_line}"

        # CWE(Common Weakness Enumeration) 정보 추출 (배열인 경우 첫 번째 항목 사용)
        cwe_info = metadata.get("cwe", ["Unknown"])
        if isinstance(cwe_info, list) and len(cwe_info) > 0:
            cwe_info = cwe_info[0]

        # LLM 분석에 필요한 핵심 필드만 딕셔너리로 조립
        extracted_findings.append({
            "rule_id": result.get("check_id", "Unknown"),
            "severity": extra.get("severity", "UNKNOWN"),
            "file_path": result.get("path", ""),
            "line_number": line_info,
            "message": extra.get("message", "").strip(),
            "code_snippet": extra.get("lines", "").strip(), # 취약점으로 탐지된 실제 코드 라인
            "cwe": cwe_info
        })

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(extracted_findings, f, indent=2, ensure_ascii=False)

print(f"Extraction complete. {len(extracted_findings)} Semgrep findings saved.")