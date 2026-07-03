"""aws_waf 핸들러 — WAFv2 IP Set 을 활성 차단 목록으로 덮어쓴다.

선언적: UpdateIPSet 은 주소 목록 전체를 교체하므로 active 집합을 그대로 넣으면
만료 IP 는 자동으로 빠진다(해제). 낙관적 잠금(LockToken) 규약을 따른다.

필요:
  - 의존성: boto3 (extra `waf`) — `pip install '.[waf]'`
  - env: AWS_REGION, WAF_IPSET_ID, WAF_IPSET_NAME, WAF_SCOPE(REGIONAL|CLOUDFRONT)
  - 최소권한 IAM: wafv2:GetIPSet, wafv2:UpdateIPSet (해당 IPSet 리소스로 한정 권장)
"""
from __future__ import annotations

import logging

from ir.responder.blocklist import BlockEntry
from ir.responder.handlers.base import BlockHandler

log = logging.getLogger("ir.responder.aws_waf")


class AwsWafHandler(BlockHandler):
    name = "aws_waf"

    def __init__(self, *, region: str, ipset_id: str, ipset_name: str, scope: str = "REGIONAL"):
        if not all([region, ipset_id, ipset_name]):
            raise ValueError("aws_waf 모드는 AWS_REGION, WAF_IPSET_ID, WAF_IPSET_NAME 필요")
        try:
            import boto3  # 지연 임포트 — waf 모드에서만 필요
        except ImportError as e:
            raise RuntimeError("aws_waf 모드는 boto3 필요: pip install '.[waf]'") from e
        self._client = boto3.client("wafv2", region_name=region)
        self.ipset_id = ipset_id
        self.ipset_name = ipset_name
        self.scope = scope

    def apply(self, active: list[BlockEntry]) -> None:
        # WAFv2 는 CIDR 표기를 요구 → 단일 IP 는 /32
        desired = sorted({f"{e.ip}/32" for e in active})
        current = self._client.get_ip_set(
            Name=self.ipset_name, Scope=self.scope, Id=self.ipset_id
        )
        existing = sorted(current["IPSet"]["Addresses"])
        if existing == desired:
            return  # 변경 없음
        self._client.update_ip_set(
            Name=self.ipset_name, Scope=self.scope, Id=self.ipset_id,
            Addresses=desired, LockToken=current["LockToken"],
        )
        log.info("[WAF] IPSet 갱신 — 활성 %d건", len(desired))
