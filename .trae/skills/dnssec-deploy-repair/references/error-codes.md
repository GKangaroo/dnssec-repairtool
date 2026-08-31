# DNSViz DNSSEC Error Catalog

## Catalog Definition

This project defines the 77-code DNSSEC set as these DNSViz categories:

```text
CDNSKEYCDSError  11
DNAMEError        4
DNSKEYError       9
DSError           9
NSECError        22
RRSIGError       21
TrustAnchorError  1
Total            77
```

The full DNSViz coverage file contains 154 diagnostics. The other codes cover
delegation reachability, glue, EDNS, cookies, malformed responses, transport,
and generic response behavior; they are outside this 77-code repair catalog.

Priority rank below is the effective ordering produced from
`TOPOLOGICAL_CODE_ORDER`: listed codes use their tuple position, then missing
codes use fallback priority and lexical order. Rank 1 is repaired first.

Coverage status describes demo reproducibility, not whether a production repair
exists:

- `done`: an existing lab scenario can trigger the target code;
- `excluded-bind9`: normal BIND9 data cannot stably emit the malformed response;
- `deferred-custom-responder`: precise reproduction needs wire-level control;
- `inactive-dnsviz-policy`: the DNSViz policy condition is currently inactive.

## Repair Families

| Family | Required authority | Concrete repair |
|---|---|---|
| `multi_auth_dnskey_sync` | All authoritative servers or publication pipeline | Query every NS for DNSKEY/RRSIG, publish one DNSKEY RRset and serial everywhere, reload, then verify each NS. |
| `revoked_key_lifecycle` | Child signing authority; parent access if KSK/DS changes | Follow RFC 5011 lifecycle, replace an invalid revoked ZSK, ensure a revoked KSK signs DNSKEY during hold-down, remove it at the correct time, update DS when needed, and resign. |
| `dnskey_rrset_cleanup` | Child zone and signing authority; parent access if KSK changes | Remove malformed, zero-length, wrong-location, or bad-length DNSKEYs; generate valid KSK/ZSK; resign and replace parent DS when needed. |
| `ds_rrset_repair` | Parent zone or registrar/registry API | Remove the bad DS; derive a new DS from the active child KSK; publish it in the parent and resign the parent. |
| `signature_resign` | Child signing authority | Replace missing or invalid RRSIG with the correct signer, algorithm, labels, validity period, and private key; normally resign the whole zone. |
| `rrsig_bad_length` | Child signing authority | Discard malformed signatures and sign again with a valid key; migrate legacy algorithms and update DS when applicable. |
| `ttl_resign` | Child zone and signing authority | Align RRset TTL, RRSIG TTL, original TTL, inception, and expiration; then resign. |
| `nsec_nsec3_regenerate` | Child zone/backend and signing authority | Discard derived denial data; rebuild NSEC or NSEC3 using algorithm 1, iteration 0, and empty salt where NSEC3 is retained; then resign. |
| `delegation_nsec_bitmap` | Parent/delegation zone authority | Make delegation proof include NS, exclude SOA, and make the DS bit agree with actual DS semantics; resign the parent. |
| `cds_cdnskey_multi_signal` | Child zone plus all authorities or publication pipeline | Retain one legal CDS/CDNSKEY intent consistent with parent DS, remove conflicting variants, synchronize serial/RRsets, and resign. |
| `unsupported_or_legacy_algorithm` | Child signing authority and parent DS authority | Replace prohibited, unsupported, or legacy DNSKEY/RRSIG algorithms with a recommended algorithm; resign and update DS. |
| `inactive_digest_policy` | Parent DS or registrar API | When policy applies, replace weak/prohibited digest DS records with SHA-256 or SHA-384 DS and resign the parent. |
| `dname_response_behavior` | Authoritative server, proxy, or implementation access | Correct RFC 6672 synthesized CNAME target and TTL behavior; upgrade or fix the response-producing layer. |
| `parent_ds_response_behavior` | Parent authoritative service or API | Return DS when present and authoritative NODATA when absent; never return an incorrect referral for a child DS query. |

Special case: `NO_TRUST_ANCHOR_SIGNING` currently falls through to
`ttl_resign` in the catalog. Diagnose the validating resolver's trust-anchor
set and make the chain terminate at a DNSKEY matching an installed trust
anchor. Resigning alone is insufficient if the trust anchor is stale or wrong.

## Ordered 77-Code Catalog

| Priority | DNSViz code | Current repair family | Coverage |
|---:|---|---|---|
| 1 | `DNSKEY_MISSING_FROM_SERVERS` | `multi_auth_dnskey_sync` | `excluded-bind9` |
| 2 | `DNSKEY_REVOKED_DS` | `revoked_key_lifecycle` | `done` |
| 3 | `DNSKEY_REVOKED_RRSIG` | `revoked_key_lifecycle` | `done` |
| 4 | `DNSKEY_BAD_LENGTH_ECDSA256` | `dnskey_rrset_cleanup` | `done` |
| 5 | `DNSKEY_BAD_LENGTH_ECDSA384` | `dnskey_rrset_cleanup` | `done` |
| 6 | `DNSKEY_BAD_LENGTH_ED25519` | `dnskey_rrset_cleanup` | `done` |
| 7 | `DNSKEY_BAD_LENGTH_ED448` | `dnskey_rrset_cleanup` | `done` |
| 8 | `DNSKEY_BAD_LENGTH_GOST` | `dnskey_rrset_cleanup` | `excluded-bind9` |
| 9 | `DNSKEY_ZERO_LENGTH` | `dnskey_rrset_cleanup` | `excluded-bind9` |
| 10 | `DNSKEY_NOT_AT_ZONE_APEX` | `dnskey_rrset_cleanup` | `excluded-bind9` |
| 11 | `DIGEST_INVALID` | `ds_rrset_repair` | `done` |
| 12 | `DIGEST_ALGORITHM_NOT_SUPPORTED` | `ds_rrset_repair` | `done` |
| 13 | `DIGEST_ALGORITHM_PROHIBITED` | `ds_rrset_repair` | `done` |
| 14 | `DS_DIGEST_ALGORITHM_IGNORED` | `ds_rrset_repair` | `done` |
| 15 | `DS_DIGEST_ALGORITHM_MAYBE_IGNORED` | `ds_rrset_repair` | `done` |
| 16 | `SIGNATURE_INVALID` | `signature_resign` | `done` |
| 17 | `RRSIG_BAD_LENGTH_ECDSA256` | `rrsig_bad_length` | `excluded-bind9` |
| 18 | `RRSIG_BAD_LENGTH_ECDSA384` | `rrsig_bad_length` | `excluded-bind9` |
| 19 | `RRSIG_BAD_LENGTH_ED25519` | `rrsig_bad_length` | `excluded-bind9` |
| 20 | `RRSIG_BAD_LENGTH_ED448` | `rrsig_bad_length` | `excluded-bind9` |
| 21 | `RRSIG_BAD_LENGTH_GOST` | `rrsig_bad_length` | `excluded-bind9` |
| 22 | `SIGNER_NOT_ZONE` | `signature_resign` | `done` |
| 23 | `RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS` | `signature_resign` | `done` |
| 24 | `INCEPTION_IN_FUTURE` | `ttl_resign` | `done` |
| 25 | `INCEPTION_WITHIN_CLOCK_SKEW` | `ttl_resign` | `done` |
| 26 | `EXPIRATION_IN_PAST` | `ttl_resign` | `done` |
| 27 | `EXPIRATION_WITHIN_CLOCK_SKEW` | `ttl_resign` | `done` |
| 28 | `TTL_BEYOND_EXPIRATION` | `ttl_resign` | `done` |
| 29 | `ORIGINAL_TTL_EXCEEDED_RRSET` | `ttl_resign` | `done` |
| 30 | `ORIGINAL_TTL_EXCEEDED_RRSIG` | `ttl_resign` | `done` |
| 31 | `RRSET_TTL_MISMATCH` | `ttl_resign` | `done` |
| 32 | `NONEMPTY_NSEC3_SALT` | `nsec_nsec3_regenerate` | `done` |
| 33 | `NONZERO_NSEC3_ITERATION_COUNT` | `nsec_nsec3_regenerate` | `done` |
| 34 | `LAST_NSEC_NEXT_NOT_ZONE` | `nsec_nsec3_regenerate` | `done` |
| 35 | `NO_CLOSEST_ENCLOSER` | `nsec_nsec3_regenerate` | `done` |
| 36 | `NO_NSEC3_MATCHING_SNAME` | `nsec_nsec3_regenerate` | `done` |
| 37 | `NO_NSEC_MATCHING_SNAME` | `nsec_nsec3_regenerate` | `done` |
| 38 | `NEXT_CLOSEST_ENCLOSER_NOT_COVERED` | `nsec_nsec3_regenerate` | `excluded-bind9` |
| 39 | `INVALID_NSEC3_HASH` | `nsec_nsec3_regenerate` | `excluded-bind9` |
| 40 | `INVALID_NSEC3_OWNER_NAME` | `nsec_nsec3_regenerate` | `excluded-bind9` |
| 41 | `OPT_OUT_FLAG_NOT_SET` | `nsec_nsec3_regenerate` | `excluded-bind9` |
| 42 | `EXISTING_NAME_COVERED` | `nsec_nsec3_regenerate` | `excluded-bind9` |
| 43 | `EXISTING_TYPE_NOT_IN_BITMAP` | `nsec_nsec3_regenerate` | `done` |
| 44 | `REFERRAL_WITHOUT_NS` | `delegation_nsec_bitmap` | `done` |
| 45 | `REFERRAL_WITH_DS` | `delegation_nsec_bitmap` | `done` |
| 46 | `REFERRAL_WITH_SOA` | `delegation_nsec_bitmap` | `done` |
| 47 | `SNAME_COVERED` | `nsec_nsec3_regenerate` | `excluded-bind9` |
| 48 | `SNAME_NOT_COVERED` | `nsec_nsec3_regenerate` | `done` |
| 49 | `STYPE_IN_BITMAP` | `nsec_nsec3_regenerate` | `done` |
| 50 | `UNSUPPORTED_NSEC3_ALGORITHM` | `nsec_nsec3_regenerate` | `excluded-bind9` |
| 51 | `WILDCARD_COVERED` | `nsec_nsec3_regenerate` | `done` |
| 52 | `WILDCARD_EXPANSION_INVALID` | `nsec_nsec3_regenerate` | `excluded-bind9` |
| 53 | `WILDCARD_NOT_COVERED` | `nsec_nsec3_regenerate` | `done` |
| 54 | `CDS_DELETE_MULTIPLE_RECORDS` | `cds_cdnskey_multi_signal` | `excluded-bind9` |
| 55 | `CDS_INCORRECT_DELETE_VALUES` | `cds_cdnskey_multi_signal` | `excluded-bind9` |
| 56 | `CDS_INCONSISTENT_WITH_DS` | `cds_cdnskey_multi_signal` | `done` |
| 57 | `CDS_SIGNER_INVALID` | `cds_cdnskey_multi_signal` | `done` |
| 58 | `CDNSKEY_DELETE_MULTIPLE_RECORDS` | `cds_cdnskey_multi_signal` | `excluded-bind9` |
| 59 | `CDNSKEY_INCORRECT_DELETE_VALUES` | `cds_cdnskey_multi_signal` | `excluded-bind9` |
| 60 | `CDNSKEY_INCONSISTENT_WITH_DS` | `cds_cdnskey_multi_signal` | `done` |
| 61 | `CDNSKEY_INCONSISTENT_WITH_CDS` | `cds_cdnskey_multi_signal` | `done` |
| 62 | `CDNSKEY_SIGNER_INVALID` | `cds_cdnskey_multi_signal` | `done` |
| 63 | `MULTIPLE_CDS` | `cds_cdnskey_multi_signal` | `deferred-custom-responder` |
| 64 | `MULTIPLE_CDNSKEY` | `cds_cdnskey_multi_signal` | `deferred-custom-responder` |
| 65 | `ALGORITHM_NOT_RECOMMENDED` | `unsupported_or_legacy_algorithm` | `done` |
| 66 | `ALGORITHM_NOT_SUPPORTED` | `unsupported_or_legacy_algorithm` | `done` |
| 67 | `ALGORITHM_PROHIBITED` | `unsupported_or_legacy_algorithm` | `done` |
| 68 | `ALGORITHM_VALIDATION_PROHIBITED` | `unsupported_or_legacy_algorithm` | `done` |
| 69 | `NO_TRUST_ANCHOR_SIGNING` | `ttl_resign` (see special case) | `done` |
| 70 | `DIGEST_ALGORITHM_NOT_RECOMMENDED` | `inactive_digest_policy` | `inactive-dnsviz-policy` |
| 71 | `DIGEST_ALGORITHM_VALIDATION_PROHIBITED` | `inactive_digest_policy` | `inactive-dnsviz-policy` |
| 72 | `DNAME_NO_CNAME` | `dname_response_behavior` | `excluded-bind9` |
| 73 | `DNAME_TARGET_MISMATCH` | `dname_response_behavior` | `excluded-bind9` |
| 74 | `DNAME_TTL_MISMATCH` | `dname_response_behavior` | `excluded-bind9` |
| 75 | `DNAME_TTL_ZERO` | `dname_response_behavior` | `excluded-bind9` |
| 76 | `REFERRAL_FOR_DS_QUERY` | `parent_ds_response_behavior` | `deferred-custom-responder` |
| 77 | `REVOKED_NOT_SIGNING` | `revoked_key_lifecycle` | `done` |

## Dependent And Companion Codes

DNSViz often emits codes outside the 77-code set alongside a root cause. The
engine explicitly treats these as dependent:

```text
MISSING_RRSIG_FOR_ALG_DS
NO_SEP
REVOKED_NOT_SIGNING
```

Other common companion codes include `MISSING_RRSIG`,
`MISSING_RRSIG_FOR_ALG_DNSKEY`, `MISSING_NSEC_FOR_NODATA`,
`MISSING_NSEC_FOR_NXDOMAIN`, and `MISSING_NSEC_FOR_WILDCARD`. Repair the
independent DNSKEY/DS/signature/NSEC cause first and diagnose again.

## Backend Limitations

- BIND9 and PowerDNS may reject or normalize malformed wire data before DNSViz
  can emit the intended code.
- PowerDNS bind backend often turns malformed NSEC/NSEC3 or bad-length errors
  into `MISSING_RRSIG`, `SIGNATURE_INVALID`, `INVALID_RCODE`, or `SERVFAIL`.
- A target miss in a demo is not proof that no repair exists.
- DNAME response errors, incorrect DS referrals, and some malformed signatures
  require a custom responder to reproduce precisely; production repair means
  eliminating that response behavior.
