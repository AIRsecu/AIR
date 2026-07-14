"""SBOM 정규화 명세서 — CycloneDX SBOM → 표준 의존성 명세(+취약점 교차참조).

멘토 권고("오탐제거·위험재평가 '전에' 각 스캐너 결과를 정규화 후 출력하는 SBOM 등 명세서를
별도로 작성")에 대응한다. 이 모듈은 LLM 트리아지 파이프라인과 '디커플링'된 별도 산출물이다:
  - 입력: 표준 CycloneDX SBOM (예: `trivy sbom --format cyclonedx`)  ← 생성은 CI(JHyye 레인)
  - (선택) Trivy 취약점 추출본(trivy_for_llm.json)으로 컴포넌트별 CVE 교차참조
  - 출력: sbom_normalized.json + sbom.md (컴포넌트 인벤토리 + 취약 컴포넌트 표시)

설계 원칙(계약과 동일):
  - 무의존(stdlib only): 어느 파이썬 3.11+ 환경에서나 pip 설치 없이 실행.
  - SBOM 은 '컴포넌트 인벤토리'라 정규 Finding 계약과 분리한다(취약점이 아니라 자산 명세).
    취약점은 Trivy Finding(from_trivy) 이 담당 — 여기서는 교차참조로 연결만 한다.

사용:
  python reports/contract/sbom.py --demo
  python reports/contract/sbom.py --sbom reports/sbom/sbom.cyclonedx.json \
      --trivy reports/trivy/trivy_for_llm.json --out-dir reports/summary
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_CONTRACT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
_PURL_ECOSYSTEM = re.compile(r"^pkg:([^/]+)/")


def _load_json(path: Path) -> Any:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _canonical_name(component: dict) -> str:
    """maven 처럼 group 이 있으면 'group:name', 아니면 name (Trivy package_name 규약과 일치)."""
    name = (component.get("name") or "").strip()
    group = (component.get("group") or "").strip()
    return f"{group}:{name}" if group else name


def _ecosystem(component: dict) -> Optional[str]:
    purl = component.get("purl") or ""
    m = _PURL_ECOSYSTEM.match(purl)
    return m.group(1) if m else None


def _licenses(component: dict) -> list[str]:
    out: list[str] = []
    for lic in component.get("licenses") or []:
        if not isinstance(lic, dict):
            continue
        if "expression" in lic:
            out.append(str(lic["expression"]))
            continue
        inner = lic.get("license") or {}
        val = inner.get("id") or inner.get("name")
        if val:
            out.append(str(val))
    return out


@dataclass
class Component:
    name: str
    version: Optional[str] = None
    ecosystem: Optional[str] = None
    purl: Optional[str] = None
    type: Optional[str] = None
    licenses: list[str] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)  # 교차참조된 CVE

    def to_contract(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "purl": self.purl,
            "type": self.type,
            "licenses": self.licenses,
            "vulnerabilities": self.vulnerabilities,
        }


def _index_trivy(trivy: Any) -> dict[tuple[str, str], list[dict]]:
    """(package_name, installed_version) → [{cve_id, severity, fixed_version}] 색인."""
    idx: dict[tuple[str, str], list[dict]] = {}
    if not isinstance(trivy, list):
        return idx
    for it in trivy:
        if not isinstance(it, dict):
            continue
        key = ((it.get("package_name") or "").strip(), (it.get("installed_version") or "").strip())
        idx.setdefault(key, []).append(
            {
                "cve_id": it.get("cve_id"),
                "severity": it.get("severity"),
                "fixed_version": it.get("fixed_version"),
            }
        )
    return idx


def normalize(sbom: dict, trivy: Any = None) -> list[Component]:
    """CycloneDX SBOM dict → Component[]. trivy 가 있으면 컴포넌트별 CVE 를 붙인다."""
    idx = _index_trivy(trivy)
    out: list[Component] = []
    for c in (sbom or {}).get("components") or []:
        if not isinstance(c, dict):
            continue
        name = _canonical_name(c)
        version = (c.get("version") or "").strip() or None
        comp = Component(
            name=name,
            version=version,
            ecosystem=_ecosystem(c),
            purl=c.get("purl"),
            type=c.get("type"),
            licenses=_licenses(c),
            vulnerabilities=idx.get((name, version or ""), []),
        )
        out.append(comp)
    return out


def build_manifest(sbom: dict, components: list[Component]) -> dict:
    by_eco: dict[str, int] = {}
    for c in components:
        eco = c.ecosystem or "unknown"
        by_eco[eco] = by_eco.get(eco, 0) + 1
    spec = sbom.get("specVersion")
    fmt = sbom.get("bomFormat") or "CycloneDX"
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "schema": "air.security.sbom/v1",
        "source_format": f"{fmt}/{spec}" if spec else fmt,
        "totals": {
            "components": len(components),
            "vulnerable": sum(1 for c in components if c.vulnerabilities),
            "by_ecosystem": by_eco,
        },
        "components": [c.to_contract() for c in components],
    }


def render_markdown(manifest: dict) -> str:
    t = manifest["totals"]
    lines = ["# 📦 AIR SBOM 명세서 (Software Bill of Materials)", ""]
    lines.append(f"> 생성: {manifest['generated_at']}  ·  원본 `{manifest['source_format']}`  ·  스키마 `{manifest['schema']}`")
    lines.append("")
    lines.append(
        f"- 컴포넌트 {t['components']}개  ·  **취약 {t['vulnerable']}개**  "
        f"·  생태계: " + ", ".join(f"`{k}`={v}" for k, v in t["by_ecosystem"].items())
    )
    lines.append("")
    lines.append("| 컴포넌트 | 버전 | 생태계 | 라이선스 | 취약점(CVE) |")
    lines.append("|---|---|---|---|---|")
    # 취약 컴포넌트 우선 정렬
    comps = sorted(manifest["components"], key=lambda c: (not c["vulnerabilities"], c["name"]))
    for c in comps:
        vulns = ", ".join(
            f"{v.get('cve_id')}({v.get('severity')})" for v in c["vulnerabilities"]
        ) or "-"
        lic = ", ".join(c["licenses"]) or "-"
        lines.append(
            f"| `{c['name']}` | {c['version'] or '-'} | {c['ecosystem'] or '-'} | {lic} | {vulns} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="AIR SBOM 정규화 명세서 생성기")
    ap.add_argument("--sbom", default=None, help="CycloneDX SBOM JSON 경로")
    ap.add_argument("--trivy", default=None, help="(선택) trivy_for_llm.json — 컴포넌트별 CVE 교차참조")
    ap.add_argument("--out-dir", default=None, help="출력 디렉터리 (기본 <sbom 부모>/../summary 또는 samples/summary)")
    ap.add_argument("--demo", action="store_true", help="번들 샘플로 시연")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    if args.demo:
        sbom_path = _CONTRACT_DIR / "samples" / "sbom" / "sbom.cyclonedx.json"
        trivy_path = _CONTRACT_DIR / "samples" / "trivy" / "trivy_for_llm.json"
        out_dir = Path(args.out_dir) if args.out_dir else (_CONTRACT_DIR / "samples" / "summary")
    else:
        if not args.sbom:
            ap.error("--sbom 이 필요합니다 (또는 --demo).")
        sbom_path = Path(args.sbom)
        trivy_path = Path(args.trivy) if args.trivy else None
        out_dir = Path(args.out_dir) if args.out_dir else (sbom_path.parent.parent / "summary")

    sbom = _load_json(sbom_path)
    if not isinstance(sbom, dict):
        print(f"[!] SBOM 을 읽을 수 없음: {sbom_path}")
        return 1
    trivy = _load_json(trivy_path) if trivy_path and trivy_path.exists() else None

    components = normalize(sbom, trivy)
    manifest = build_manifest(sbom, components)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "sbom_normalized.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out_dir / "sbom.md").write_text(render_markdown(manifest), encoding="utf-8")

    t = manifest["totals"]
    print(f"[+] SBOM 정규화 완료: components={t['components']} (취약 {t['vulnerable']})")
    print(f"    → {out_dir / 'sbom_normalized.json'}")
    print(f"    → {out_dir / 'sbom.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
