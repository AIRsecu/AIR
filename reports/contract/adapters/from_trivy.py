"""trivy_for_llm.json → Finding[].

입력 스키마(scripts/extract_trivy.py 실측):
  {target, cve_id, severity, cvss_score, package_name, installed_version,
   fixed_version, title, description, pkg_path?}

위치(location) 주의:
  이미지 스캔에서 Trivy 는 jar 등 언어 패키지를 개별 매니페스트가 아니라 언어명으로
  집계한다 → Target 이 "Java"/"Node.js" 같은 언어명이 된다. 이 값은 '파일 위치'가 아니라
  '생태계 라벨'이므로 location.file 에 넣으면 통합 리포트 위치 컬럼이 전부 "Java" 로
  덮인다(실제 패키지명이 가려짐). 따라서:
    - file    ← 진짜 경로일 때만(pkg_path[Trivy PkgPath] 우선, 없으면 경로 형태의 target)
    - package ← 패키지 좌표 "name@version" (의존성 취약점의 자연스러운 위치)
  extract 단계가 pkg_path(=vuln.PkgPath)를 채워 주면 실제 jar 경로까지 표시된다.
"""
from __future__ import annotations

from finding import Finding, Location, Source, Stage
from severity_map import normalize_severity


def _looks_like_path(s: str | None) -> bool:
    """target 이 실제 파일/경로인지(예: 'app/BOOT-INF/lib/x.jar'), 아니면 언어명('Java')인지."""
    if not s:
        return False
    tail = s.replace("\\", "/").rsplit("/", 1)[-1]
    return "/" in s or "\\" in s or tail.endswith(
        (".jar", ".war", ".ear", ".xml", ".json", ".txt", ".lock", ".gradle")
    )


def to_findings(items: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for i, it in enumerate(items or []):
        cve = it.get("cve_id") or "UNKNOWN-CVE"
        pkg = it.get("package_name")
        ver = it.get("installed_version")
        # 의존성 취약점의 위치 = 패키지 좌표. 언어명 target("Java")은 file 로 쓰지 않는다.
        coord = f"{pkg}@{ver}" if pkg and ver else pkg
        target = it.get("target")
        file_loc = it.get("pkg_path") or (target if _looks_like_path(target) else None)
        out.append(
            Finding(
                id=f"trivy:{cve}:{pkg or ''}:{i}",
                source=Source.TRIVY,
                stage=Stage.BUILD,
                severity=normalize_severity("trivy", it.get("severity")),
                type=cve,
                title=it.get("title") or cve,
                location=Location(package=coord, file=file_loc),
                message=(it.get("description") or "").strip() or None,
                evidence=(
                    f"{pkg} {ver or '?'} "
                    f"→ fix: {it.get('fixed_version', 'No Fix Available')}"
                ),
                # 의존성 취약점은 CWE 대신 CVE 로 상관 — correlation_key 는 type(CVE)로 자동 산출
                cwe=None,
                raw=it,
            )
        )
    return out
