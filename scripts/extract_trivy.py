import json
from pathlib import Path

TRIVY_PATH = Path("reports/trivy/trivy.json")
OUTPUT_PATH = Path("reports/trivy/trivy_for_llm.json")

print("Extracting Trivy vulnerabilities for LLM analysis...")

extracted_vulns = []

if TRIVY_PATH.exists():
    with open(TRIVY_PATH) as f:
        trivy_data = json.load(f)

    for result in trivy_data.get("Results", []):
        target_name = result.get("Target", "Unknown Target")
        
        for vuln in result.get("Vulnerabilities", []):
            # CVSS 점수 정제 (NVD 우선, 없으면 GHSA)
            cvss_info = vuln.get("CVSS", {})
            cvss_score = None
            
            if "nvd" in cvss_info:
                cvss_score = cvss_info["nvd"].get("V3Score")
            elif "ghsa" in cvss_info:
                cvss_score = cvss_info["ghsa"].get("V3Score")

            # LLM 분석에 필요한 핵심 필드만 딕셔너리로 추출
            extracted_vulns.append({
                "target": target_name,
                "cve_id": vuln.get("VulnerabilityID"),
                "severity": vuln.get("Severity"),
                "cvss_score": cvss_score,
                "package_name": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion", "No Fix Available"),
                "title": vuln.get("Title", "No Title"),
                "description": vuln.get("Description", "")
            })

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

with open(OUTPUT_PATH, "w") as f:
    json.dump(extracted_vulns, f, indent=2)

print(f"Extraction complete. {len(extracted_vulns)} vulnerabilities saved.")