import json
import glob
from pathlib import Path

CODEQL_DIR = Path("reports/codeql")
OUTPUT_PATH = Path("reports/codeql/codeql_for_llm.json")

print("Extracting CodeQL vulnerabilities for LLM analysis...")

extracted_findings = []

if CODEQL_DIR.exists():
    # 폴더 내의 모든 .sarif 파일 검색 (java, javascript 등)
    for sarif_file in CODEQL_DIR.glob("*.sarif"):
        with open(sarif_file, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                print(f"[!] Warning: Could not parse JSON from {sarif_file.name}")
                continue

        # SARIF 규격: runs 배열 안에 분석 결과가 담김
        for run in data.get("runs", []):
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "Unknown")
                
                # 보안과 무관한 '코드 품질(Quality)' 룰 필터링 (Drop)
                # unused, empty, naming, formatting 등과 관련된 룰은 건너뜁니다.
                if any(ignored in rule_id.lower() for ignored in ["unused", "empty", "naming", "comment", "import", "used-once"]):
                    continue

                message = result.get("message", {}).get("text", "").strip()
                level = result.get("level", "warning")

                # 위치 추출
                locations = result.get("locations", [])
                file_path = "Unknown"
                line_number = "Unknown"
                
                if locations:
                    phys_loc = locations[0].get("physicalLocation", {})
                    file_path = phys_loc.get("artifactLocation", {}).get("uri", "Unknown")
                    line_number = phys_loc.get("region", {}).get("startLine", "Unknown")

                # Data Flow 중복 라인 압축 (Deduplication)
                data_flow_steps = []
                code_flows = result.get("codeFlows", [])
                if code_flows:
                    for thread_flow in code_flows[0].get("threadFlows", []):
                        for loc in thread_flow.get("locations", []):
                            loc_info = loc.get("location", {}).get("physicalLocation", {})
                            step_file = loc_info.get("artifactLocation", {}).get("uri", "Unknown")
                            step_line = loc_info.get("region", {}).get("startLine", "Unknown")
                            
                            step_str = f"{step_file}:{step_line}"
                            
                            # 바로 직전에 추가한 스텝과 동일하면 추가하지 않음 (연속 중복 제거)
                            if not data_flow_steps or data_flow_steps[-1] != step_str:
                                data_flow_steps.append(step_str)

                # LLM 분석에 필요한 핵심 필드만 딕셔너리로 조립
                extracted_findings.append({
                    "rule_id": rule_id,
                    "severity": level,
                    "file_path": file_path,
                    "line_number": str(line_number),
                    "message": message,
                    "data_flow": data_flow_steps  # 깔끔하게 압축된 경로 리스트
                })

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(extracted_findings, f, indent=2, ensure_ascii=False)

print(f"Extraction complete. {len(extracted_findings)} CodeQL findings saved.")