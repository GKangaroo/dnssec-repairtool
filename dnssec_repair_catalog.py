#!/usr/bin/env python3
"""Machine-readable repair plan catalog for DNSSEC DNSViz codes.

The catalog is intentionally conservative: it describes the repair action and
required authority even when the current PowerDNS demo cannot reproduce the
exact DNSViz code.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from dataclasses import asdict


@dataclass(frozen=True)
class RepairPlan:
    group: str
    executor: str
    required_permission: str
    action: str
    powerdns_note: str
    dfixer_logic: str = ""


GROUP_PLANS: dict[str, RepairPlan] = {
    "cds_cdnskey_multi_signal": RepairPlan(
        group="cds_cdnskey_multi_signal",
        executor="multi-auth sync / child-zone repair",
        required_permission="子区全部权威服务器或统一 zone backend 写权限",
        action="枚举所有权威服务器的 CDS/CDNSKEY 响应，保留唯一、合法、与父区 DS 意图一致的自动化信号，删除冲突变体，统一 serial，重签并 reload。",
        powerdns_note="已用双 PowerDNS 权威服务器复现 MULTIPLE_CDS/MULTIPLE_CDNSKEY；修复路径是同步所有权威的 CDS/CDNSKEY RRset 并重签。",
    ),
    "dname_response_behavior": RepairPlan(
        group="dname_response_behavior",
        executor="server-behavior repair",
        required_permission="权威服务器配置、代理层或权威实现修改权限",
        action="修正 DNAME 合成 CNAME 的生成逻辑，保证目标名和 TTL 符合 RFC 6672；必要时升级权威软件或修复中间层响应改写。",
        powerdns_note="PowerDNS/BIND 会按规范合成 CNAME，普通 zone 数据难以复现这些错误。",
        dfixer_logic="DFixer 当前未覆盖 DNAME 响应合成类错误；本项目扩展为 server-behavior repair。",
    ),
    "unsupported_or_legacy_algorithm": RepairPlan(
        group="unsupported_or_legacy_algorithm",
        executor="child-zone repair + parent-side repair",
        required_permission="子区 DNSKEY/签名权限；若 KSK 改动则需要父区 DS 权限",
        action="移除 GOST 或其他遗留/不支持算法的 DNSKEY/RRSIG，迁移到当前推荐算法，重新生成 KSK/ZSK，重签 zone，并同步父区 DS。",
        powerdns_note="当前本地算法栈不稳定支持 GOST 畸形构造。",
        dfixer_logic="DFixer 对 DNSKEY_BAD_LENGTH_* 的通用逻辑是生成同 flags/algorithm 的新 key、替换 DNSKEY、重签并同步 DS；GOST 场景扩展为迁移到推荐算法。",
    ),
    "ds_rrset_repair": RepairPlan(
        group="ds_rrset_repair",
        executor="parent-side repair",
        required_permission="父区 DS 或注册商 API 权限；本地 lab 中为父区 zone 写权限",
        action="定位异常 DS 的 key tag、digest type 和 digest value；删除错误 DS，使用当前有效 KSK 重新生成 DS，发布到父区并重签父区。",
        powerdns_note="PowerDNS demo 可通过父区 zone mutation 复现 DS digest/algorithm 类错误；修复路径是恢复父区 DS 并重签。",
        dfixer_logic="DFixer 对 DIGEST_INVALID 会从 ds_map 找出 INVALID_DIGEST 的 DS，重新生成正确 DS 并上传父区；对弱/禁用 digest 则移除弱 DS。",
    ),
    "signature_resign": RepairPlan(
        group="signature_resign",
        executor="child-zone repair",
        required_permission="子区签名权限",
        action="定位异常 RRSIG 或缺失签名的 RRset，使用正确 signer、algorithm、labels、inception/expiration 和 private key 重新签名；必要时整区重签。",
        powerdns_note="PowerDNS demo 中多数 RRSIG 类错误可通过重建 clean signed zone 修复。",
        dfixer_logic="DFixer 对 MISSING_RRSIG、SIGNATURE_INVALID、SIGNER_NOT_ZONE、RRSIG_LABELS_EXCEED_* 的核心动作是重签 zone。",
    ),
    "key_chain_repair": RepairPlan(
        group="key_chain_repair",
        executor="child-zone repair + parent-side repair",
        required_permission="子区 DNSKEY/签名权限；若 DS 缺失或多余则需要父区 DS 权限",
        action="检查 DS/DNSKEY/RRSIG DNSKEY 的 key tag 与 algorithm 链路；补齐 KSK/ZSK 或删除多余 DS，重签 DNSKEY RRset，并同步父区 DS。",
        powerdns_note="PowerDNS demo 中 NO_SEP/MISSING_SEP_FOR_ALG 常作为伴随错误出现，修复依赖 key chain 归一化。",
        dfixer_logic="DFixer 对 MISSING_SEP_FOR_ALG 会区分多余 DS、缺 KSK、KSK 未签 DNSKEY RRset 等 case，再生成 key/DS/重签动作。",
    ),
    "multi_auth_dnskey_sync": RepairPlan(
        group="multi_auth_dnskey_sync",
        executor="multi-auth sync",
        required_permission="全部权威服务器或发布流水线权限",
        action="逐 NS 查询 DNSKEY RRset 和 RRSIG，统一 DNSKEY、RRSIG、serial 和发布版本，reload 后逐 NS 验证一致性。",
        powerdns_note="已用双 PowerDNS 权威服务器复现 DNSKEY_MISSING_FROM_SERVERS；修复路径是同步所有权威的 DNSKEY RRset 并重签。",
    ),
    "dnskey_rrset_cleanup": RepairPlan(
        group="dnskey_rrset_cleanup",
        executor="child-zone repair",
        required_permission="子区 zone/backend 与签名权限",
        action="删除非法 DNSKEY RRset，重新生成有效 KSK/ZSK，确保 DNSKEY 只发布在 zone apex，重签所有相关 RRset；必要时同步父区 DS。",
        powerdns_note="零长度或非 apex DNSKEY 在 PowerDNS/DNSViz 路径下会退化为通用错误或触发 DNSViz grok 异常。",
        dfixer_logic="DFixer 对 DNSKEY_ZERO_LENGTH/DNSKEY_BAD_LENGTH_* 的逻辑是替换非法 key、重签、必要时重新生成并上传 DS；非 apex DNSKEY 是本项目补充的 cleanup 规则。",
    ),
    "revoked_key_lifecycle": RepairPlan(
        group="revoked_key_lifecycle",
        executor="child-zone repair",
        required_permission="子区 DNSKEY/签名权限",
        action="按 RFC 5011 处理 revoked key：不要发布 revoked ZSK；KSK revoke 流程中确保 revoked KSK 正确签署 DNSKEY RRset，完成 hold-down 后移除并重签。",
        powerdns_note="当前 PowerDNS demo 退化为 MISSING_RRSIG，未命中 REVOKED_NOT_SIGNING。",
        dfixer_logic="DFixer 将 REVOKED_NOT_SIGNING 作为 DNSKEY_REVOKED_RRSIG 的依赖情形处理：生成新 ZSK、移除 revoked ZSK、重签 zone。",
    ),
    "inactive_digest_policy": RepairPlan(
        group="inactive_digest_policy",
        executor="parent-side repair",
        required_permission="父区 DS 或注册商 API 权限",
        action="策略启用后，移除不推荐或 validation-prohibited digest 的 DS，发布 SHA-256/SHA-384 DS，父区重签并等待缓存过期。",
        powerdns_note="DNSViz 0.11.1 对应策略集合为空，当前不可触发。",
        dfixer_logic="DFixer 当前策略集合中该类 digest policy 为空；本项目保留父侧 DS 替换规则作为 inactive policy。",
    ),
    "parent_ds_response_behavior": RepairPlan(
        group="parent_ds_response_behavior",
        executor="parent-side repair / server-behavior repair",
        required_permission="父区权威配置或注册商/API 权限",
        action="修正父区对 child DS 查询的权威响应：有 DS 返回 DS，无 DS 返回 authoritative NODATA，不应返回 referral。",
        powerdns_note="需要父区响应行为控制，单子区 PowerDNS demo 不适合稳定复现。",
        dfixer_logic="DFixer 未覆盖父区 DS 查询返回 referral 的服务器行为错误；本项目归入 parent-side/server-behavior repair。",
    ),
    "nsec_nsec3_regenerate": RepairPlan(
        group="nsec_nsec3_regenerate",
        executor="child-zone repair",
        required_permission="子区 zone/backend 与签名权限",
        action="丢弃当前 NSEC/NSEC3 派生数据，重新生成一致的 denial-of-existence 链和 bitmap，优先使用 NSEC 或 NSEC3 iteration 0 + empty salt，然后重签 zone。",
        powerdns_note="PowerDNS bind backend 常规整或重组 denial proof，目标码常退化为 MISSING_RRSIG/SIGNATURE_INVALID。",
        dfixer_logic="DFixer 对 NSEC/NSEC3 proof、bitmap、closest-encloser、wildcard、unsupported algorithm 的主逻辑均是重新生成 NSEC/NSEC3 配置并重签；NONZERO_NSEC3_ITERATION_COUNT 明确要求 iteration=0。",
    ),
    "delegation_nsec_bitmap": RepairPlan(
        group="delegation_nsec_bitmap",
        executor="parent-side repair",
        required_permission="父区/委派侧 zone 写权限",
        action="修正委派点 NSEC/NSEC3 bitmap：委派 proof 必须包含 NS bit，不应错误包含 SOA；DS bit 必须与实际 DS 响应语义一致；父区重签。",
        powerdns_note="PowerDNS bind backend 下 bitmap 变异常退化为 SIGNATURE_INVALID。",
        dfixer_logic="DFixer 对 REFERRAL_WITH_DS/SOA/WITHOUT_NS 的逻辑是定位 delegated name，请父区修正 NSEC/NSEC3 bitmap 并重签父区。",
    ),
    "ttl_resign": RepairPlan(
        group="ttl_resign",
        executor="child-zone repair",
        required_permission="子区 zone/backend 与签名权限",
        action="统一 RRset TTL、RRSIG TTL 和 RRSIG original TTL；推荐直接重签整区，让签名器生成一致 TTL。",
        powerdns_note="PowerDNS 可能统一 TTL 或转化为 ORIGINAL_TTL_EXCEEDED_*，不一定命中 RRSET_TTL_MISMATCH。",
        dfixer_logic="DFixer 对 RRSET_TTL_MISMATCH 会根据 TTL 与签名有效期给出降 TTL/延长签名有效期建议；ORIGINAL_TTL_EXCEEDED_* 直接重签。",
    ),
    "rrsig_bad_length": RepairPlan(
        group="rrsig_bad_length",
        executor="child-zone repair",
        required_permission="子区签名权限",
        action="丢弃错误长度 RRSIG，使用正确算法和私钥重新签名对应 RRset；若算法已废弃则迁移算法并同步 DS。",
        powerdns_note="PowerDNS 会退化为 INVALID_RCODE；精确复现需要 wire-level/custom responder。",
        dfixer_logic="DFixer 对 RRSIG_BAD_LENGTH_* 的修复逻辑是重签 zone；本项目扩展到 Ed25519/Ed448/GOST。",
    ),
}


CODE_TO_GROUP: dict[str, str] = {
    "DNAME_NO_CNAME": "dname_response_behavior",
    "DNAME_TARGET_MISMATCH": "dname_response_behavior",
    "DNAME_TTL_MISMATCH": "dname_response_behavior",
    "DNAME_TTL_ZERO": "dname_response_behavior",
    "DNSKEY_ZERO_LENGTH": "dnskey_rrset_cleanup",
    "DIGEST_ALGORITHM_NOT_RECOMMENDED": "inactive_digest_policy",
    "DIGEST_ALGORITHM_VALIDATION_PROHIBITED": "inactive_digest_policy",
    "REFERRAL_FOR_DS_QUERY": "parent_ds_response_behavior",
    "INVALID_NSEC3_HASH": "nsec_nsec3_regenerate",
    "INVALID_NSEC3_OWNER_NAME": "nsec_nsec3_regenerate",
    "LAST_NSEC_NEXT_NOT_ZONE": "nsec_nsec3_regenerate",
    "NEXT_CLOSEST_ENCLOSER_NOT_COVERED": "nsec_nsec3_regenerate",
    "NO_CLOSEST_ENCLOSER": "nsec_nsec3_regenerate",
    "NO_NSEC3_MATCHING_SNAME": "nsec_nsec3_regenerate",
    "NO_NSEC_MATCHING_SNAME": "nsec_nsec3_regenerate",
    "OPT_OUT_FLAG_NOT_SET": "nsec_nsec3_regenerate",
    "SNAME_COVERED": "nsec_nsec3_regenerate",
    "SNAME_NOT_COVERED": "nsec_nsec3_regenerate",
    "STYPE_IN_BITMAP": "nsec_nsec3_regenerate",
    "UNSUPPORTED_NSEC3_ALGORITHM": "nsec_nsec3_regenerate",
    "WILDCARD_COVERED": "nsec_nsec3_regenerate",
    "WILDCARD_EXPANSION_INVALID": "nsec_nsec3_regenerate",
    "WILDCARD_NOT_COVERED": "nsec_nsec3_regenerate",
    "REFERRAL_WITHOUT_NS": "delegation_nsec_bitmap",
    "REFERRAL_WITH_DS": "delegation_nsec_bitmap",
    "REFERRAL_WITH_SOA": "delegation_nsec_bitmap",
    "RRSET_TTL_MISMATCH": "ttl_resign",
    "RRSIG_BAD_LENGTH_ECDSA256": "rrsig_bad_length",
    "RRSIG_BAD_LENGTH_ECDSA384": "rrsig_bad_length",
    "RRSIG_BAD_LENGTH_ED25519": "rrsig_bad_length",
    "RRSIG_BAD_LENGTH_ED448": "rrsig_bad_length",
    "RRSIG_BAD_LENGTH_GOST": "rrsig_bad_length",
}


BIND9_SCENARIO: dict[str, str] = {
    "LAST_NSEC_NEXT_NOT_ZONE": "last-nsec-next-not-zone",
    "NO_CLOSEST_ENCLOSER": "no-closest-encloser",
    "NO_NSEC3_MATCHING_SNAME": "no-nsec3-matching-sname",
    "NO_NSEC_MATCHING_SNAME": "no-nsec-matching-sname",
    "REFERRAL_WITHOUT_NS": "referral-without-ns",
    "REFERRAL_WITH_DS": "referral-with-ds",
    "REFERRAL_WITH_SOA": "referral-with-soa",
    "SNAME_NOT_COVERED": "sname-not-covered",
    "STYPE_IN_BITMAP": "stype-in-bitmap",
    "WILDCARD_COVERED": "wildcard-covered",
    "WILDCARD_NOT_COVERED": "wildcard-not-covered",
    "RRSET_TTL_MISMATCH": "rrset-ttl-mismatch",
}


def get_bind9_scenario(code: str) -> str | None:
    return BIND9_SCENARIO.get(code)


def get_repair_plan(code: str) -> RepairPlan | None:
    group = CODE_TO_GROUP.get(code)
    if group is None:
        return None
    return GROUP_PLANS[group]


def remaining_powerdns_codes() -> list[str]:
    return sorted(CODE_TO_GROUP)


def repair_record(code: str) -> dict[str, str] | None:
    plan = get_repair_plan(code)
    if plan is None:
        return None
    record = asdict(plan)
    record["code"] = code
    record["bind9_scenario"] = get_bind9_scenario(code) or ""
    record["powerdns_status"] = "target-miss"
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description="Query DNSViz DNSSEC repair catalog entries.")
    parser.add_argument("code", nargs="?", help="DNSViz error code, e.g. STYPE_IN_BITMAP")
    parser.add_argument("--list", action="store_true", help="List all remaining PowerDNS target-miss codes")
    args = parser.parse_args()

    if args.list:
        print(json.dumps([repair_record(code) for code in remaining_powerdns_codes()], ensure_ascii=False, indent=2))
        return

    if not args.code:
        parser.error("provide a DNSViz error code or --list")
    record = repair_record(args.code)
    if record is None:
        raise SystemExit(f"unknown or already-covered code: {args.code}")
    print(json.dumps(record, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
