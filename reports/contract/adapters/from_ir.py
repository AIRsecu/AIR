"""IR 인시던트 저장 레코드 → Finding[]  (병록 파트 · 런타임 대응).

입력 스키마(ir-automation/ir/store/incident_store.py 실측 save() 레코드):
  {incident: {id,type,endpoint,client_ip,actor,payload,action_taken,status,created_at},
   risk: {score, severity, block_seconds},
   response: {action, ip, mode, ttl_seconds, hits, enforced},
   notified, playbook:{detect,analyze,contain,recover}, recorded_at}

빌드타임 스캔(semgrep/zap)의 CWE 와 조인되도록 인시던트 type → CWE 를 매핑한다.
"""
from __future__ import annotations

from finding import Finding, Location, Response, Source, Stage, normalize_cwe
from severity_map import normalize_severity

# 런타임 공격 유형 → 표준 CWE (빌드↔런타임 상관용). 미매핑은 type 슬러그로 상관.
IR_TYPE_TO_CWE = {
    "SQLI_ATTEMPT": "CWE-89",
    "XSS_ATTEMPT": "CWE-79",
    "IDOR_ATTEMPT": "CWE-639",
    "UPLOAD_MALICIOUS": "CWE-434",
    "PATH_TRAVERSAL": "CWE-22",
    "ORDER_NEGATIVE_QTY": "CWE-840",  # business logic error
}


def to_findings(records: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for i, rec in enumerate(records or []):
        inc = rec.get("incident") or {}
        risk = rec.get("risk") or {}
        resp = rec.get("response") or {}
        itype = inc.get("type") or "UNKNOWN"
        cwe = normalize_cwe(IR_TYPE_TO_CWE.get(itype))
        out.append(
            Finding(
                id=f"ir:{inc.get('id', i)}",
                source=Source.IR,
                stage=Stage.RUNTIME,
                severity=normalize_severity("ir-runtime", risk.get("severity")),
                type=itype,
                title=f"{itype} @ {inc.get('endpoint', '?')}",
                location=Location(
                    endpoint=inc.get("endpoint"),
                    client_ip=inc.get("client_ip") or (resp.get("ip")),
                ),
                message=inc.get("action_taken") or inc.get("status"),
                evidence=inc.get("payload"),
                cwe=cwe,
                response=Response(
                    action_taken=resp.get("action") or inc.get("action_taken"),
                    status=inc.get("status"),
                    mode=resp.get("mode"),
                    ttl_seconds=resp.get("ttl_seconds") or risk.get("block_seconds"),
                    enforced=resp.get("enforced"),
                ),
                raw=rec,
            )
        )
    return out
