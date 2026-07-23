from pathlib import Path
import json
import re
import xml.etree.ElementTree as ET

REPORT_PATH = Path("reports/openapi/schemathesis-report.xml")
OUTPUT_PATH = Path("reports/openapi/schemathesis_for_llm.json")

print("Extracting Schemathesis vulnerabilities for LLM analysis...")

extracted_results = []

if REPORT_PATH.exists():
        
    # XML 깨짐 문자 제거
    xml_text = REPORT_PATH.read_text(encoding="utf-8")
    # XML 1.0에서 허용하지 않는 제어문자 제거
    xml_text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", xml_text)

    root = ET.fromstring(xml_text)

    for testcase in root.iter("testcase"):

        failure = testcase.find("failure")
        error = testcase.find("error")

        # 정상 테스트는 LLM 분석 대상이 아님
        if failure is None and error is None:
            continue
        message = ""

        issue_node = failure if failure is not None else error

        if failure is not None:
            message = (failure.attrib.get("message") or failure.text or "")

        elif error is not None:
            message = (error.attrib.get("message") or error.text or "")
        
        testcase_name = testcase.attrib.get("name", "Unknown API")
        classname = testcase.attrib.get("classname", "")

        if issue_node is None:
            continue

        extracted_results.append({
            # 테스트 대상 API 정보
            "test_case": testcase.attrib.get("name", "Unknown"),
            "test_class": testcase.attrib.get("classname", "Unknown"),
            
            # 실패 유형
            "status": ("failed" if failure is not None else "error"),
            "failure_type": (issue_node.tag),

            # 핵심 오류 내용
            "error_message": (issue_node.attrib.get("message", "") or issue_node.text or "").strip(),

            # 실행 시간
            "execution_time": testcase.attrib.get("time", "0")
        })

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(extracted_results, f, indent=2, ensure_ascii=False)

print(f"Extraction complete. " f"{len(extracted_results)} Schemathesis issues saved.")