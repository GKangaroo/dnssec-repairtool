#!/usr/bin/env python3
import ast
import json
from collections import Counter
from pathlib import Path


LAB_ROOT = Path(__file__).resolve().parents[1]
REPO = LAB_ROOT.parent / "dnsviz"
ERRORS = REPO / "dnsviz" / "analysis" / "errors.py"
OUT_JSON = LAB_ROOT / "docs" / "dnsviz_error_coverage.json"
OUT_MD = LAB_ROOT / "docs" / "dnsviz_error_coverage.md"

DONE = {
    "ALGORITHM_NOT_RECOMMENDED": "algorithm-not-recommended",
    "ALGORITHM_NOT_SUPPORTED": "algorithm-not-supported",
    "ALGORITHM_PROHIBITED": "algorithm-prohibited",
    "ALGORITHM_VALIDATION_PROHIBITED": "algorithm-prohibited",
    "DIGEST_INVALID": "bad-ds",
    "NO_SEP": "bad-ds / expired-rrsig / missing-ksk",
    "EXPIRATION_IN_PAST": "expired-rrsig",
    "INCEPTION_IN_FUTURE": "future-rrsig",
    "EXPIRATION_WITHIN_CLOCK_SKEW": "expiration-within-clock-skew",
    "INCEPTION_WITHIN_CLOCK_SKEW": "inception-within-clock-skew",
    "MISSING_RRSIG": "missing-rrsig",
    "MISSING_RRSIG_FOR_ALG_DNSKEY": "missing-rrsig-for-alg-dnskey",
    "MISSING_NSEC_FOR_NXDOMAIN": "missing-nsec-for-nxdomain",
    "MISSING_NSEC_FOR_NODATA": "missing-nsec-for-nodata",
    "MISSING_SEP_FOR_ALG": "missing-ksk",
    "DNSKEY_BAD_LENGTH_ECDSA256": "dnskey-bad-length-ecdsa256",
    "DNSKEY_BAD_LENGTH_ECDSA384": "dnskey-bad-length-ecdsa384",
    "DNSKEY_BAD_LENGTH_ED25519": "dnskey-bad-length-ed25519",
    "DNSKEY_BAD_LENGTH_ED448": "dnskey-bad-length-ed448",
    "STYPE_IN_BITMAP": "stype-in-bitmap",
    "REFERRAL_WITH_DS": "referral-with-ds",
    "REFERRAL_WITH_SOA": "referral-with-soa",
    "REFERRAL_WITHOUT_NS": "referral-without-ns",
    "LAST_NSEC_NEXT_NOT_ZONE": "last-nsec-next-not-zone",
    "SNAME_NOT_COVERED": "sname-not-covered",
    "NONZERO_NSEC3_ITERATION_COUNT": "nonzero-nsec3-iteration-count",
    "NONEMPTY_NSEC3_SALT": "nonzero-nsec3-iteration-count",
    "NO_CLOSEST_ENCLOSER": "no-closest-encloser",
    "NO_NSEC3_MATCHING_SNAME": "no-nsec3-matching-sname",
    "NO_NSEC_MATCHING_SNAME": "no-nsec-matching-sname",
    "NO_TRUST_ANCHOR_SIGNING": "no-trust-anchor-signing",
    "EXISTING_TYPE_NOT_IN_BITMAP": "existing-type-not-in-bitmap",
    "WILDCARD_NOT_COVERED": "wildcard-not-covered",
    "WILDCARD_COVERED": "wildcard-covered",
    "RRSET_TTL_MISMATCH": "rrset-ttl-mismatch",
    "ORIGINAL_TTL_EXCEEDED_RRSET": "original-ttl-exceeded-rrset",
    "ORIGINAL_TTL_EXCEEDED_RRSIG": "original-ttl-exceeded-rrsig",
    "REVOKED_NOT_SIGNING": "dnskey-revoked-rrsig",
    "DNSKEY_REVOKED_DS": "dnskey-revoked-ds",
    "DNSKEY_REVOKED_RRSIG": "dnskey-revoked-rrsig",
    "RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS": "rrsig-labels-exceed-owner-labels",
    "SIGNATURE_INVALID": "signature-invalid / missing-ksk",
    "SIGNER_NOT_ZONE": "signer-not-zone",
    "TTL_BEYOND_EXPIRATION": "ttl-beyond-expiration",
    "CDS_INCONSISTENT_WITH_DS": "cds-inconsistent-with-ds",
    "CDNSKEY_INCONSISTENT_WITH_DS": "cdnskey-inconsistent-with-ds",
    "CDNSKEY_INCONSISTENT_WITH_CDS": "cdnskey-inconsistent-with-cds",
    "CDS_SIGNER_INVALID": "cds-signer-invalid",
    "CDNSKEY_SIGNER_INVALID": "cdnskey-signer-invalid",
    "CNAME_LOOP": "cname-loop",
    "DIGEST_ALGORITHM_NOT_SUPPORTED": "digest-algorithm-not-supported",
    "DIGEST_ALGORITHM_PROHIBITED": "ds-digest-algorithm-prohibited",
    "DS_DIGEST_ALGORITHM_IGNORED": "ds-digest-algorithm-prohibited / ds-digest-algorithm-maybe-ignored",
    "DS_DIGEST_ALGORITHM_MAYBE_IGNORED": "ds-digest-algorithm-maybe-ignored",
}

BIND_ZONE_CANDIDATES = {
    "SIGNER_NOT_ZONE",
    "RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS",
    "RRSET_TTL_MISMATCH",
    "ORIGINAL_TTL_EXCEEDED_RRSET",
    "ORIGINAL_TTL_EXCEEDED_RRSIG",
    "TTL_BEYOND_EXPIRATION",
    "INCEPTION_IN_FUTURE",
    "INCEPTION_WITHIN_CLOCK_SKEW",
    "EXPIRATION_WITHIN_CLOCK_SKEW",
    "MISSING_RRSIG_FOR_ALG_DNSKEY",
    "MISSING_NSEC_FOR_NXDOMAIN",
    "MISSING_NSEC_FOR_NODATA",
    "DNSKEY_REVOKED_DS",
    "DNSKEY_REVOKED_RRSIG",
    "REVOKED_NOT_SIGNING",
    "NO_TRUST_ANCHOR_SIGNING",
    "DNSKEY_MISSING_FROM_SERVERS",
    "DNSKEY_NOT_AT_ZONE_APEX",
    "CDS_INCONSISTENT_WITH_DS",
    "CDNSKEY_INCONSISTENT_WITH_DS",
    "CDNSKEY_INCONSISTENT_WITH_CDS",
    "CNAME_WITH_OTHER_DATA",
    "CNAME_LOOP",
    "DNAME_NO_CNAME",
    "DNAME_TARGET_MISMATCH",
    "DNAME_TTL_ZERO",
    "DNAME_TTL_MISMATCH",
}

BIND_DELEGATION_CANDIDATES = {
    "NO_NS_IN_PARENT_NXDOMAIN",
    "NO_NS_IN_PARENT_NODATA",
    "NO_NS_ADDRESSES_FOR_IPV4",
    "NO_NS_ADDRESSES_FOR_IPV6",
    "NS_NAME_NOT_IN_CHILD",
    "NS_NAME_NOT_IN_PARENT",
    "ERROR_RESOLVING_NS_NAME",
    "MISSING_GLUE_FOR_NS_NAME",
    "NO_ADDRESS_FOR_NS_NAME",
    "NS_NAME_PRIVATE_IP",
    "GLUE_PRIVATE_IP",
    "GLUE_MISMATCH",
    "MISSING_GLUE_IPV4",
    "MISSING_GLUE_IPV6",
    "EXTRA_GLUE_IPV4",
    "EXTRA_GLUE_IPV6",
    "SERVER_UNRESPONSIVE_UDP",
    "SERVER_UNRESPONSIVE_TCP",
    "SERVER_NOT_AUTHORITATIVE",
}

CUSTOM_SERVER_CANDIDATES = {
    "NETWORK_ERROR",
    "FORMERR",
    "TIMEOUT",
    "RESPONSE_ERROR",
    "INVALID_RCODE",
    "NOT_AUTHORITATIVE",
    "AUTHORITATIVE_REFERRAL",
    "RECURSION_NOT_AVAILABLE",
    "ERROR_WITH_REQUEST_FLAG",
    "ERROR_WITHOUT_REQUEST_FLAG",
    "ERROR_WITH_EDNS",
    "ERROR_WITH_EDNS_VERSION",
    "ERROR_WITH_EDNS_FLAG",
    "ERROR_WITHOUT_EDNS_FLAG",
    "ERROR_WITH_EDNS_OPTION",
    "ERROR_WITHOUT_EDNS_OPTION",
    "EDNS_VERSION_MISMATCH",
    "EDNS_IGNORED",
    "EDNS_SUPPORT_NO_OPT",
    "GRATUITOUS_OPT",
    "IMPLEMENTED_EDNS_VERSION_NOT_PROVIDED",
    "EDNS_UNDEFINED_FLAGS_SET",
    "DNSSEC_DOWNGRADE_DO_CLEARED",
    "DNSSEC_DOWNGRADE_EDNS_DISABLED",
    "MULTIPLE_CDS",
    "MULTIPLE_CDNSKEY",
    "MISSING_RRSIG_FOR_ALG_DS",
    "REFERRAL_FOR_DS_QUERY",
    "MISSING_SOA_FOR_NXDOMAIN",
    "MISSING_SOA_FOR_NODATA",
    "GRATUITOUS_COOKIE",
    "MALFORMED_COOKIE_WITHOUT_FORMERR",
    "NO_COOKIE_OPTION",
    "NO_SERVER_COOKIE_WITHOUT_BADCOOKIE",
    "INVALID_SERVER_COOKIE_WITHOUT_BADCOOKIE",
    "NO_SERVER_COOKIE",
    "CLIENT_COOKIE_MISMATCH",
    "COOKIE_INVALID_LENGTH",
    "UNABLE_TO_RETRIEVE_DNSSEC_RECORDS",
    "UPWARD_REFERRAL",
    "INCONSISTENT_NXDOMAIN",
    "INCONSISTENT_NXDOMAIN_ANCESTOR",
    "PMTU_EXCEEDED",
    "FOREIGN_CLASS_DATA_ANSWER",
    "FOREIGN_CLASS_DATA_AUTHORITY",
    "FOREIGN_CLASS_DATA_ADDITIONAL",
    "CASE_NOT_PRESERVED",
    "SERVER_INVALID_RESPONSE_UDP",
    "SERVER_INVALID_RESPONSE_TCP",
}

WIRE_MALFORMED_CANDIDATES = {
    "ALGORITHM_NOT_SUPPORTED",
    "ALGORITHM_PROHIBITED",
    "ALGORITHM_VALIDATION_PROHIBITED",
    "RRSIG_BAD_LENGTH_GOST",
    "RRSIG_BAD_LENGTH_ECDSA256",
    "RRSIG_BAD_LENGTH_ECDSA384",
    "RRSIG_BAD_LENGTH_ED25519",
    "RRSIG_BAD_LENGTH_ED448",
    "DNSKEY_ZERO_LENGTH",
    "DNSKEY_BAD_LENGTH_GOST",
    "DNSKEY_BAD_LENGTH_ECDSA256",
    "DNSKEY_BAD_LENGTH_ECDSA384",
    "DNSKEY_BAD_LENGTH_ED25519",
    "DNSKEY_BAD_LENGTH_ED448",
}

BIND9_EXCLUDED = {
    # BIND refuses malformed DNSSEC wire data or serves it as a generic invalid response.
    "DNSKEY_ZERO_LENGTH",
    "RRSIG_BAD_LENGTH_ECDSA256",
    "RRSIG_BAD_LENGTH_ECDSA384",
    "RRSIG_BAD_LENGTH_ED25519",
    "RRSIG_BAD_LENGTH_ED448",
    "RRSIG_BAD_LENGTH_GOST",
    "DNSKEY_BAD_LENGTH_GOST",
    # These require authoritative behavior inconsistent with normal BIND zone loading/serving.
    "INCONSISTENT_NXDOMAIN_ANCESTOR",
    "INVALID_NSEC3_HASH",
    "INVALID_NSEC3_OWNER_NAME",
    "UNSUPPORTED_NSEC3_ALGORITHM",
    # These require contradictory denial-of-existence proof RRsets to be present
    # in a specific positive/negative response. BIND either returns the normal
    # proof, omits the mutated proof, or the condition collapses into a broader
    # proof failure such as NO_CLOSEST_ENCLOSER / INVALID_RCODE.
    "EXISTING_NAME_COVERED",
    "NEXT_CLOSEST_ENCLOSER_NOT_COVERED",
    "OPT_OUT_FLAG_NOT_SET",
    "SNAME_COVERED",
    "WILDCARD_EXPANSION_INVALID",
    # Deleting the DNSKEY RRset is loadable enough to probe, but DNSViz grok crashes in this lab.
    "DNSKEY_MISSING_FROM_SERVERS",
    # BIND/dnssec-signzone rejects DNSKEY RRsets outside the zone apex.
    "DNSKEY_NOT_AT_ZONE_APEX",
    # BIND serves CDS delete-signal RRsets as a generic invalid response in this lab.
    "CDS_DELETE_MULTIPLE_RECORDS",
    "CDNSKEY_DELETE_MULTIPLE_RECORDS",
    "CDS_INCORRECT_DELETE_VALUES",
    "CDNSKEY_INCORRECT_DELETE_VALUES",
    # BIND/dnssec-signzone rejects CNAME owners with other data.
    "CNAME_WITH_OTHER_DATA",
    # BIND synthesizes DNAME companion CNAMEs correctly; bad/missing companion
    # CNAME behavior requires controlling the authoritative response packet.
    "DNAME_NO_CNAME",
    "DNAME_TARGET_MISMATCH",
    "DNAME_TTL_ZERO",
    "DNAME_TTL_MISMATCH",
}

DNSVIZ_INACTIVE = {
    # DNSViz 0.11.1 defines these codes, but the corresponding RFC8624 sets
    # are empty in analysis/status.py, so regular zone data cannot trigger them.
    "DIGEST_ALGORITHM_NOT_RECOMMENDED",
    "DIGEST_ALGORITHM_VALIDATION_PROHIBITED",
}

CUSTOM_RESPONDER_DEFERRED = {
    "MULTIPLE_CDS",
    "MULTIPLE_CDNSKEY",
    "DNSSEC_DOWNGRADE_DO_CLEARED",
    "DNSSEC_DOWNGRADE_EDNS_DISABLED",
    "MISSING_RRSIG_FOR_ALG_DS",
    "MISSING_SOA_FOR_NODATA",
    "MISSING_SOA_FOR_NXDOMAIN",
    "REFERRAL_FOR_DS_QUERY",
}


def literal_assignments(node):
    values = {}
    for item in node.body:
        if not isinstance(item, ast.Assign):
            continue
        for target in item.targets:
            if isinstance(target, ast.Name):
                try:
                    values[target.id] = ast.literal_eval(item.value)
                except Exception:
                    pass
    return values


def base_names(node):
    names = []
    for base in node.bases:
        if isinstance(base, ast.Name):
            names.append(base.id)
        elif isinstance(base, ast.Attribute):
            names.append(base.attr)
    return names


def classify(code, category):
    if code in DONE:
        return "done", "existing-lab", DONE[code]
    if code in BIND9_EXCLUDED:
        return "excluded-bind9", "not-bind9-reproducible", ""
    if code in DNSVIZ_INACTIVE:
        return "inactive-dnsviz-policy", "dnsviz-inactive-condition", ""
    if code in CUSTOM_RESPONDER_DEFERRED:
        return "deferred-custom-responder", "custom-dns-responder", ""
    if code in BIND_ZONE_CANDIDATES:
        return "planned", "bind-zone-mutation", ""
    if code in BIND_DELEGATION_CANDIDATES:
        return "planned", "bind-delegation-mutation", ""
    if code in CUSTOM_SERVER_CANDIDATES:
        return "planned", "custom-dns-responder", ""
    if code in WIRE_MALFORMED_CANDIDATES:
        return "planned", "custom-wire-record", ""
    if category == "NSECError":
        return "planned", "nsec-nsec3-zone-mutation", ""
    if category in {"DSError", "DSDigestError"}:
        return "planned", "ds-dnskey-zone-mutation", ""
    if category == "RRSIGError":
        return "planned", "rrsig-zone-mutation", ""
    return "triage", "manual-classification-needed", ""


def main():
    module = ast.parse(ERRORS.read_text())
    parents = {}
    classes = {}
    for node in module.body:
        if not isinstance(node, ast.ClassDef):
            continue
        parents[node.name] = base_names(node)
        values = literal_assignments(node)
        if values.get("code"):
            classes[node.name] = {
                "class": node.name,
                "code": values["code"],
                "bases": parents[node.name],
                "description": values.get("description_template", ""),
            }

    def ancestors(name):
        seen = []
        stack = [name]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.append(cur)
            stack.extend(parents.get(cur, []))
        return seen

    category_order = [
        "RRSIGError",
        "DSError",
        "DSDigestError",
        "NSECError",
        "InvalidResponseError",
        "ResponseError",
        "EDNSError",
        "DNSCookieError",
        "DelegationError",
        "NSNameError",
        "DNSKEYError",
        "TrustAnchorError",
        "DNAMEError",
        "ZoneDataError",
        "CDNSKEYCDSError",
        "DSConsistencyError",
    ]

    rows = []
    for item in classes.values():
        lineage = ancestors(item["class"])
        category = next((c for c in category_order if c in lineage), "Other")
        status, method, scenario = classify(item["code"], category)
        rows.append(
            {
                **item,
                "category": category,
                "status": status,
                "repro_method": method,
                "scenario": scenario,
            }
        )
    rows.sort(key=lambda r: (r["category"], r["code"]))

    OUT_JSON.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")

    counts = Counter(r["status"] for r in rows)
    methods = Counter(r["repro_method"] for r in rows)
    cats = Counter(r["category"] for r in rows)
    lines = [
        "# DNSViz 错误复现覆盖矩阵",
        "",
        f"来源：`{ERRORS}`",
        f"错误码总数：`{len(rows)}`",
        "",
        "## 状态统计",
        "",
        "| 状态 | 数量 |",
        "|---|---:|",
    ]
    for key, val in sorted(counts.items()):
        lines.append(f"| `{key}` | {val} |")
    lines += ["", "## 复现方法统计", "", "| 复现方法 | 数量 |", "|---|---:|"]
    for key, val in sorted(methods.items()):
        lines.append(f"| `{key}` | {val} |")
    lines += ["", "## 错误类别统计", "", "| 错误类别 | 数量 |", "|---|---:|"]
    for key, val in sorted(cats.items()):
        lines.append(f"| `{key}` | {val} |")
    lines += [
        "",
        "## 覆盖明细",
        "",
        "| 错误码 | 类别 | 状态 | 复现方法 | 场景 |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| `{row['code']}` | `{row['category']}` | `{row['status']}` | `{row['repro_method']}` | `{row['scenario']}` |"
        )
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT_JSON}")
    print(f"wrote {OUT_MD}")
    print(f"total={len(rows)} done={counts.get('done', 0)} planned={counts.get('planned', 0)} triage={counts.get('triage', 0)}")


if __name__ == "__main__":
    main()
