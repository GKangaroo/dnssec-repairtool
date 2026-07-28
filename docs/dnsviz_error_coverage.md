# DNSViz 错误复现覆盖矩阵

来源：`/mlx_devbox/users/guiqingxin.gqx/playground/dnssec-tool/dnsviz/dnsviz/analysis/errors.py`
错误码总数：`154`

## 状态统计

| 状态 | 数量 |
|---|---:|
| `deferred-custom-responder` | 8 |
| `done` | 54 |
| `excluded-bind9` | 27 |
| `inactive-dnsviz-policy` | 2 |
| `planned` | 59 |
| `triage` | 4 |

## 复现方法统计

| 复现方法 | 数量 |
|---|---:|
| `bind-delegation-mutation` | 19 |
| `custom-dns-responder` | 48 |
| `dnsviz-inactive-condition` | 2 |
| `existing-lab` | 54 |
| `manual-classification-needed` | 4 |
| `not-bind9-reproducible` | 27 |

## 错误类别统计

| 错误类别 | 数量 |
|---|---:|
| `CDNSKEYCDSError` | 11 |
| `DNAMEError` | 4 |
| `DNSKEYError` | 9 |
| `DSError` | 9 |
| `DelegationError` | 23 |
| `InvalidResponseError` | 5 |
| `NSECError` | 22 |
| `RRSIGError` | 21 |
| `ResponseError` | 47 |
| `TrustAnchorError` | 1 |
| `ZoneDataError` | 2 |

## 覆盖明细

| 错误码 | 类别 | 状态 | 复现方法 | 场景 |
|---|---|---|---|---|
| `CDNSKEY_DELETE_MULTIPLE_RECORDS` | `CDNSKEYCDSError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `CDNSKEY_INCONSISTENT_WITH_CDS` | `CDNSKEYCDSError` | `done` | `existing-lab` | `cdnskey-inconsistent-with-cds` |
| `CDNSKEY_INCONSISTENT_WITH_DS` | `CDNSKEYCDSError` | `done` | `existing-lab` | `cdnskey-inconsistent-with-ds` |
| `CDNSKEY_INCORRECT_DELETE_VALUES` | `CDNSKEYCDSError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `CDNSKEY_SIGNER_INVALID` | `CDNSKEYCDSError` | `done` | `existing-lab` | `cdnskey-signer-invalid` |
| `CDS_DELETE_MULTIPLE_RECORDS` | `CDNSKEYCDSError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `CDS_INCONSISTENT_WITH_DS` | `CDNSKEYCDSError` | `done` | `existing-lab` | `cds-inconsistent-with-ds` |
| `CDS_INCORRECT_DELETE_VALUES` | `CDNSKEYCDSError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `CDS_SIGNER_INVALID` | `CDNSKEYCDSError` | `done` | `existing-lab` | `cds-signer-invalid` |
| `MULTIPLE_CDNSKEY` | `CDNSKEYCDSError` | `deferred-custom-responder` | `custom-dns-responder` | `` |
| `MULTIPLE_CDS` | `CDNSKEYCDSError` | `deferred-custom-responder` | `custom-dns-responder` | `` |
| `DNAME_NO_CNAME` | `DNAMEError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `DNAME_TARGET_MISMATCH` | `DNAMEError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `DNAME_TTL_MISMATCH` | `DNAMEError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `DNAME_TTL_ZERO` | `DNAMEError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `DNSKEY_BAD_LENGTH_ECDSA256` | `DNSKEYError` | `done` | `existing-lab` | `dnskey-bad-length-ecdsa256` |
| `DNSKEY_BAD_LENGTH_ECDSA384` | `DNSKEYError` | `done` | `existing-lab` | `dnskey-bad-length-ecdsa384` |
| `DNSKEY_BAD_LENGTH_ED25519` | `DNSKEYError` | `done` | `existing-lab` | `dnskey-bad-length-ed25519` |
| `DNSKEY_BAD_LENGTH_ED448` | `DNSKEYError` | `done` | `existing-lab` | `dnskey-bad-length-ed448` |
| `DNSKEY_BAD_LENGTH_GOST` | `DNSKEYError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `DNSKEY_MISSING_FROM_SERVERS` | `DNSKEYError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `DNSKEY_NOT_AT_ZONE_APEX` | `DNSKEYError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `DNSKEY_ZERO_LENGTH` | `DNSKEYError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `REVOKED_NOT_SIGNING` | `DNSKEYError` | `done` | `existing-lab` | `dnskey-revoked-rrsig` |
| `DIGEST_ALGORITHM_NOT_RECOMMENDED` | `DSError` | `inactive-dnsviz-policy` | `dnsviz-inactive-condition` | `` |
| `DIGEST_ALGORITHM_NOT_SUPPORTED` | `DSError` | `done` | `existing-lab` | `digest-algorithm-not-supported` |
| `DIGEST_ALGORITHM_PROHIBITED` | `DSError` | `done` | `existing-lab` | `ds-digest-algorithm-prohibited` |
| `DIGEST_ALGORITHM_VALIDATION_PROHIBITED` | `DSError` | `inactive-dnsviz-policy` | `dnsviz-inactive-condition` | `` |
| `DIGEST_INVALID` | `DSError` | `done` | `existing-lab` | `bad-ds` |
| `DNSKEY_REVOKED_DS` | `DSError` | `done` | `existing-lab` | `dnskey-revoked-ds` |
| `DS_DIGEST_ALGORITHM_IGNORED` | `DSError` | `done` | `existing-lab` | `ds-digest-algorithm-prohibited / ds-digest-algorithm-maybe-ignored` |
| `DS_DIGEST_ALGORITHM_MAYBE_IGNORED` | `DSError` | `done` | `existing-lab` | `ds-digest-algorithm-maybe-ignored` |
| `REFERRAL_FOR_DS_QUERY` | `DSError` | `deferred-custom-responder` | `custom-dns-responder` | `` |
| `ERROR_RESOLVING_NS_NAME` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `EXTRA_GLUE_IPV4` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `EXTRA_GLUE_IPV6` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `GLUE_MISMATCH` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `GLUE_PRIVATE_IP` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `MISSING_GLUE_FOR_NS_NAME` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `MISSING_GLUE_IPV4` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `MISSING_GLUE_IPV6` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `MISSING_SEP_FOR_ALG` | `DelegationError` | `done` | `existing-lab` | `missing-ksk` |
| `NO_ADDRESS_FOR_NS_NAME` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `NO_NS_ADDRESSES_FOR_IPV4` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `NO_NS_ADDRESSES_FOR_IPV6` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `NO_NS_IN_PARENT_NODATA` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `NO_NS_IN_PARENT_NXDOMAIN` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `NO_SEP` | `DelegationError` | `done` | `existing-lab` | `bad-ds / expired-rrsig / missing-ksk` |
| `NS_NAME_NOT_IN_CHILD` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `NS_NAME_NOT_IN_PARENT` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `NS_NAME_PRIVATE_IP` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `SERVER_INVALID_RESPONSE_TCP` | `DelegationError` | `planned` | `custom-dns-responder` | `` |
| `SERVER_INVALID_RESPONSE_UDP` | `DelegationError` | `planned` | `custom-dns-responder` | `` |
| `SERVER_NOT_AUTHORITATIVE` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `SERVER_UNRESPONSIVE_TCP` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `SERVER_UNRESPONSIVE_UDP` | `DelegationError` | `planned` | `bind-delegation-mutation` | `` |
| `FORMERR` | `InvalidResponseError` | `planned` | `custom-dns-responder` | `` |
| `INVALID_RCODE` | `InvalidResponseError` | `planned` | `custom-dns-responder` | `` |
| `NETWORK_ERROR` | `InvalidResponseError` | `planned` | `custom-dns-responder` | `` |
| `RESPONSE_ERROR` | `InvalidResponseError` | `planned` | `custom-dns-responder` | `` |
| `TIMEOUT` | `InvalidResponseError` | `planned` | `custom-dns-responder` | `` |
| `EXISTING_NAME_COVERED` | `NSECError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `EXISTING_TYPE_NOT_IN_BITMAP` | `NSECError` | `done` | `existing-lab` | `existing-type-not-in-bitmap` |
| `INVALID_NSEC3_HASH` | `NSECError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `INVALID_NSEC3_OWNER_NAME` | `NSECError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `LAST_NSEC_NEXT_NOT_ZONE` | `NSECError` | `done` | `existing-lab` | `last-nsec-next-not-zone` |
| `NEXT_CLOSEST_ENCLOSER_NOT_COVERED` | `NSECError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `NONEMPTY_NSEC3_SALT` | `NSECError` | `done` | `existing-lab` | `nonzero-nsec3-iteration-count` |
| `NONZERO_NSEC3_ITERATION_COUNT` | `NSECError` | `done` | `existing-lab` | `nonzero-nsec3-iteration-count` |
| `NO_CLOSEST_ENCLOSER` | `NSECError` | `done` | `existing-lab` | `no-closest-encloser` |
| `NO_NSEC3_MATCHING_SNAME` | `NSECError` | `done` | `existing-lab` | `no-nsec3-matching-sname` |
| `NO_NSEC_MATCHING_SNAME` | `NSECError` | `done` | `existing-lab` | `no-nsec-matching-sname` |
| `OPT_OUT_FLAG_NOT_SET` | `NSECError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `REFERRAL_WITHOUT_NS` | `NSECError` | `done` | `existing-lab` | `referral-without-ns` |
| `REFERRAL_WITH_DS` | `NSECError` | `done` | `existing-lab` | `referral-with-ds` |
| `REFERRAL_WITH_SOA` | `NSECError` | `done` | `existing-lab` | `referral-with-soa` |
| `SNAME_COVERED` | `NSECError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `SNAME_NOT_COVERED` | `NSECError` | `done` | `existing-lab` | `sname-not-covered` |
| `STYPE_IN_BITMAP` | `NSECError` | `done` | `existing-lab` | `stype-in-bitmap` |
| `UNSUPPORTED_NSEC3_ALGORITHM` | `NSECError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `WILDCARD_COVERED` | `NSECError` | `done` | `existing-lab` | `wildcard-covered` |
| `WILDCARD_EXPANSION_INVALID` | `NSECError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `WILDCARD_NOT_COVERED` | `NSECError` | `done` | `existing-lab` | `wildcard-not-covered` |
| `ALGORITHM_NOT_RECOMMENDED` | `RRSIGError` | `done` | `existing-lab` | `algorithm-not-recommended` |
| `ALGORITHM_NOT_SUPPORTED` | `RRSIGError` | `done` | `existing-lab` | `algorithm-not-supported` |
| `ALGORITHM_PROHIBITED` | `RRSIGError` | `done` | `existing-lab` | `algorithm-prohibited` |
| `ALGORITHM_VALIDATION_PROHIBITED` | `RRSIGError` | `done` | `existing-lab` | `algorithm-prohibited` |
| `DNSKEY_REVOKED_RRSIG` | `RRSIGError` | `done` | `existing-lab` | `dnskey-revoked-rrsig` |
| `EXPIRATION_IN_PAST` | `RRSIGError` | `done` | `existing-lab` | `expired-rrsig` |
| `EXPIRATION_WITHIN_CLOCK_SKEW` | `RRSIGError` | `done` | `existing-lab` | `expiration-within-clock-skew` |
| `INCEPTION_IN_FUTURE` | `RRSIGError` | `done` | `existing-lab` | `future-rrsig` |
| `INCEPTION_WITHIN_CLOCK_SKEW` | `RRSIGError` | `done` | `existing-lab` | `inception-within-clock-skew` |
| `ORIGINAL_TTL_EXCEEDED_RRSET` | `RRSIGError` | `done` | `existing-lab` | `original-ttl-exceeded-rrset` |
| `ORIGINAL_TTL_EXCEEDED_RRSIG` | `RRSIGError` | `done` | `existing-lab` | `original-ttl-exceeded-rrsig` |
| `RRSET_TTL_MISMATCH` | `RRSIGError` | `done` | `existing-lab` | `rrset-ttl-mismatch` |
| `RRSIG_BAD_LENGTH_ECDSA256` | `RRSIGError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `RRSIG_BAD_LENGTH_ECDSA384` | `RRSIGError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `RRSIG_BAD_LENGTH_ED25519` | `RRSIGError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `RRSIG_BAD_LENGTH_ED448` | `RRSIGError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `RRSIG_BAD_LENGTH_GOST` | `RRSIGError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS` | `RRSIGError` | `done` | `existing-lab` | `rrsig-labels-exceed-owner-labels` |
| `SIGNATURE_INVALID` | `RRSIGError` | `done` | `existing-lab` | `signature-invalid / missing-ksk` |
| `SIGNER_NOT_ZONE` | `RRSIGError` | `done` | `existing-lab` | `signer-not-zone` |
| `TTL_BEYOND_EXPIRATION` | `RRSIGError` | `done` | `existing-lab` | `ttl-beyond-expiration` |
| `AUTHORITATIVE_REFERRAL` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `CASE_NOT_PRESERVED` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `CLIENT_COOKIE_MISMATCH` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `COOKIE_INVALID_LENGTH` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `DNSSEC_DOWNGRADE_DO_CLEARED` | `ResponseError` | `deferred-custom-responder` | `custom-dns-responder` | `` |
| `DNSSEC_DOWNGRADE_EDNS_DISABLED` | `ResponseError` | `deferred-custom-responder` | `custom-dns-responder` | `` |
| `EDNS_IGNORED` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `EDNS_SUPPORT_NO_OPT` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `EDNS_UNDEFINED_FLAGS_SET` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `EDNS_VERSION_MISMATCH` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `ERROR_WITHOUT_EDNS_FLAG` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `ERROR_WITHOUT_EDNS_OPTION` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `ERROR_WITHOUT_REQUEST_FLAG` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `ERROR_WITH_EDNS` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `ERROR_WITH_EDNS_FLAG` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `ERROR_WITH_EDNS_OPTION` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `ERROR_WITH_EDNS_VERSION` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `ERROR_WITH_REQUEST_FLAG` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `FOREIGN_CLASS_DATA_ADDITIONAL` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `FOREIGN_CLASS_DATA_ANSWER` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `FOREIGN_CLASS_DATA_AUTHORITY` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `GRATUITOUS_COOKIE` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `GRATUITOUS_OPT` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `IMPLEMENTED_EDNS_VERSION_NOT_PROVIDED` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `INCONSISTENT_NXDOMAIN` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `INCONSISTENT_NXDOMAIN_ANCESTOR` | `ResponseError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
| `INVALID_SERVER_COOKIE_WITHOUT_BADCOOKIE` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `MALFORMED_COOKIE_WITHOUT_FORMERR` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `MISSING_NSEC_FOR_NODATA` | `ResponseError` | `done` | `existing-lab` | `missing-nsec-for-nodata` |
| `MISSING_NSEC_FOR_NXDOMAIN` | `ResponseError` | `done` | `existing-lab` | `missing-nsec-for-nxdomain` |
| `MISSING_NSEC_FOR_WILDCARD` | `ResponseError` | `triage` | `manual-classification-needed` | `` |
| `MISSING_RRSIG` | `ResponseError` | `done` | `existing-lab` | `missing-rrsig` |
| `MISSING_RRSIG_FOR_ALG_DLV` | `ResponseError` | `triage` | `manual-classification-needed` | `` |
| `MISSING_RRSIG_FOR_ALG_DNSKEY` | `ResponseError` | `done` | `existing-lab` | `missing-rrsig-for-alg-dnskey` |
| `MISSING_RRSIG_FOR_ALG_DS` | `ResponseError` | `deferred-custom-responder` | `custom-dns-responder` | `` |
| `MISSING_SOA_FOR_NODATA` | `ResponseError` | `deferred-custom-responder` | `custom-dns-responder` | `` |
| `MISSING_SOA_FOR_NXDOMAIN` | `ResponseError` | `deferred-custom-responder` | `custom-dns-responder` | `` |
| `NOT_AUTHORITATIVE` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `NO_COOKIE_OPTION` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `NO_SERVER_COOKIE` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `NO_SERVER_COOKIE_WITHOUT_BADCOOKIE` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `PMTU_EXCEEDED` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `RECURSION_NOT_AVAILABLE` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `SOA_NOT_OWNER_FOR_NODATA` | `ResponseError` | `triage` | `manual-classification-needed` | `` |
| `SOA_NOT_OWNER_FOR_NXDOMAIN` | `ResponseError` | `triage` | `manual-classification-needed` | `` |
| `UNABLE_TO_RETRIEVE_DNSSEC_RECORDS` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `UPWARD_REFERRAL` | `ResponseError` | `planned` | `custom-dns-responder` | `` |
| `NO_TRUST_ANCHOR_SIGNING` | `TrustAnchorError` | `done` | `existing-lab` | `no-trust-anchor-signing` |
| `CNAME_LOOP` | `ZoneDataError` | `done` | `existing-lab` | `cname-loop` |
| `CNAME_WITH_OTHER_DATA` | `ZoneDataError` | `excluded-bind9` | `not-bind9-reproducible` | `` |
