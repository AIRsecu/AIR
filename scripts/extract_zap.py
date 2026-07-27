import json
from pathlib import Path

ZAP_PATH = Path("reports/zap/zap-report.json")
OUTPUT_PATH = Path("reports/zap/zap_for_llm.json")

print("Extracting ZAP vulnerabilities for LLM analysis...")

extracted_alerts = []

if ZAP_PATH.exists():
    with open(ZAP_PATH, encoding="utf-8") as f:
        zap_data = json.load(f)

    sites = zap_data.get("site", [])
    
    for site in sites:
        for alert in site.get("alerts", []):
            risk_desc = alert.get("riskdesc", "")

            # 해당 취약점이 발견된 모든 URI(공격 타겟) 목록 추출
            affected_urls = []
            for instance in alert.get("instances", []):
                uri = instance.get("uri", "")
                method = instance.get("method", "")
                param = instance.get("param", "")
                evidence = instance.get("evidence", "")
                
                affected_urls.append({
                    "url": uri,
                    "method": method,
                    "parameter": param,
                    "evidence": evidence
                })

            # LLM 분석에 필요한 핵심 필드만 딕셔너리로 조립
            extracted_alerts.append({
                "alert_name": alert.get("name"),
                "risk_level": risk_desc,
                "cwe_id": alert.get("cweid", "Unknown"),
                "description": alert.get("desc", "").replace("<p>", "").replace("</p>", "\n").strip(),
                "solution": alert.get("solution", "").replace("<p>", "").replace("</p>", "\n").strip(),
                "instances_count": alert.get("count", "0"),
                "affected_targets": affected_urls
            })

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(extracted_alerts, f, indent=2, ensure_ascii=False)

print(f"Extraction complete. {len(extracted_alerts)} ZAP alerts saved.")