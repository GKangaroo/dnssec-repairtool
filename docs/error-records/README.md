# DNSViz 错误记录

记录总数：`154`

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

## 按类别索引

### CDNSKEYCDSError

- [`CDNSKEY_DELETE_MULTIPLE_RECORDS`](cdnskey-delete-multiple-records.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`CDNSKEY_INCONSISTENT_WITH_CDS`](cdnskey-inconsistent-with-cds.md) - `done` / `existing-lab` / `cdnskey-inconsistent-with-cds`
- [`CDNSKEY_INCONSISTENT_WITH_DS`](cdnskey-inconsistent-with-ds.md) - `done` / `existing-lab` / `cdnskey-inconsistent-with-ds`
- [`CDNSKEY_INCORRECT_DELETE_VALUES`](cdnskey-incorrect-delete-values.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`CDNSKEY_SIGNER_INVALID`](cdnskey-signer-invalid.md) - `done` / `existing-lab` / `cdnskey-signer-invalid`
- [`CDS_DELETE_MULTIPLE_RECORDS`](cds-delete-multiple-records.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`CDS_INCONSISTENT_WITH_DS`](cds-inconsistent-with-ds.md) - `done` / `existing-lab` / `cds-inconsistent-with-ds`
- [`CDS_INCORRECT_DELETE_VALUES`](cds-incorrect-delete-values.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`CDS_SIGNER_INVALID`](cds-signer-invalid.md) - `done` / `existing-lab` / `cds-signer-invalid`
- [`MULTIPLE_CDNSKEY`](multiple-cdnskey.md) - `deferred-custom-responder` / `custom-dns-responder`
- [`MULTIPLE_CDS`](multiple-cds.md) - `deferred-custom-responder` / `custom-dns-responder`

### DNAMEError

- [`DNAME_NO_CNAME`](dname-no-cname.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`DNAME_TARGET_MISMATCH`](dname-target-mismatch.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`DNAME_TTL_MISMATCH`](dname-ttl-mismatch.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`DNAME_TTL_ZERO`](dname-ttl-zero.md) - `excluded-bind9` / `not-bind9-reproducible`

### DNSKEYError

- [`DNSKEY_BAD_LENGTH_ECDSA256`](dnskey-bad-length-ecdsa256.md) - `done` / `existing-lab` / `dnskey-bad-length-ecdsa256`
- [`DNSKEY_BAD_LENGTH_ECDSA384`](dnskey-bad-length-ecdsa384.md) - `done` / `existing-lab` / `dnskey-bad-length-ecdsa384`
- [`DNSKEY_BAD_LENGTH_ED25519`](dnskey-bad-length-ed25519.md) - `done` / `existing-lab` / `dnskey-bad-length-ed25519`
- [`DNSKEY_BAD_LENGTH_ED448`](dnskey-bad-length-ed448.md) - `done` / `existing-lab` / `dnskey-bad-length-ed448`
- [`DNSKEY_BAD_LENGTH_GOST`](dnskey-bad-length-gost.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`DNSKEY_MISSING_FROM_SERVERS`](dnskey-missing-from-servers.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`DNSKEY_NOT_AT_ZONE_APEX`](dnskey-not-at-zone-apex.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`DNSKEY_ZERO_LENGTH`](dnskey-zero-length.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`REVOKED_NOT_SIGNING`](revoked-not-signing.md) - `done` / `existing-lab` / `dnskey-revoked-rrsig`

### DSError

- [`DIGEST_ALGORITHM_NOT_RECOMMENDED`](digest-algorithm-not-recommended.md) - `inactive-dnsviz-policy` / `dnsviz-inactive-condition`
- [`DIGEST_ALGORITHM_NOT_SUPPORTED`](digest-algorithm-not-supported.md) - `done` / `existing-lab` / `digest-algorithm-not-supported`
- [`DIGEST_ALGORITHM_PROHIBITED`](digest-algorithm-prohibited.md) - `done` / `existing-lab` / `ds-digest-algorithm-prohibited`
- [`DIGEST_ALGORITHM_VALIDATION_PROHIBITED`](digest-algorithm-validation-prohibited.md) - `inactive-dnsviz-policy` / `dnsviz-inactive-condition`
- [`DIGEST_INVALID`](digest-invalid.md) - `done` / `existing-lab` / `bad-ds`
- [`DNSKEY_REVOKED_DS`](dnskey-revoked-ds.md) - `done` / `existing-lab` / `dnskey-revoked-ds`
- [`DS_DIGEST_ALGORITHM_IGNORED`](ds-digest-algorithm-ignored.md) - `done` / `existing-lab` / `ds-digest-algorithm-prohibited / ds-digest-algorithm-maybe-ignored`
- [`DS_DIGEST_ALGORITHM_MAYBE_IGNORED`](ds-digest-algorithm-maybe-ignored.md) - `done` / `existing-lab` / `ds-digest-algorithm-maybe-ignored`
- [`REFERRAL_FOR_DS_QUERY`](referral-for-ds-query.md) - `deferred-custom-responder` / `custom-dns-responder`

### DelegationError

- [`ERROR_RESOLVING_NS_NAME`](error-resolving-ns-name.md) - `planned` / `bind-delegation-mutation`
- [`EXTRA_GLUE_IPV4`](extra-glue-ipv4.md) - `planned` / `bind-delegation-mutation`
- [`EXTRA_GLUE_IPV6`](extra-glue-ipv6.md) - `planned` / `bind-delegation-mutation`
- [`GLUE_MISMATCH`](glue-mismatch.md) - `planned` / `bind-delegation-mutation`
- [`GLUE_PRIVATE_IP`](glue-private-ip.md) - `planned` / `bind-delegation-mutation`
- [`MISSING_GLUE_FOR_NS_NAME`](missing-glue-for-ns-name.md) - `planned` / `bind-delegation-mutation`
- [`MISSING_GLUE_IPV4`](missing-glue-ipv4.md) - `planned` / `bind-delegation-mutation`
- [`MISSING_GLUE_IPV6`](missing-glue-ipv6.md) - `planned` / `bind-delegation-mutation`
- [`MISSING_SEP_FOR_ALG`](missing-sep-for-alg.md) - `done` / `existing-lab` / `missing-ksk`
- [`NO_ADDRESS_FOR_NS_NAME`](no-address-for-ns-name.md) - `planned` / `bind-delegation-mutation`
- [`NO_NS_ADDRESSES_FOR_IPV4`](no-ns-addresses-for-ipv4.md) - `planned` / `bind-delegation-mutation`
- [`NO_NS_ADDRESSES_FOR_IPV6`](no-ns-addresses-for-ipv6.md) - `planned` / `bind-delegation-mutation`
- [`NO_NS_IN_PARENT_NODATA`](no-ns-in-parent-nodata.md) - `planned` / `bind-delegation-mutation`
- [`NO_NS_IN_PARENT_NXDOMAIN`](no-ns-in-parent-nxdomain.md) - `planned` / `bind-delegation-mutation`
- [`NO_SEP`](no-sep.md) - `done` / `existing-lab` / `bad-ds / expired-rrsig / missing-ksk`
- [`NS_NAME_NOT_IN_CHILD`](ns-name-not-in-child.md) - `planned` / `bind-delegation-mutation`
- [`NS_NAME_NOT_IN_PARENT`](ns-name-not-in-parent.md) - `planned` / `bind-delegation-mutation`
- [`NS_NAME_PRIVATE_IP`](ns-name-private-ip.md) - `planned` / `bind-delegation-mutation`
- [`SERVER_INVALID_RESPONSE_TCP`](server-invalid-response-tcp.md) - `planned` / `custom-dns-responder`
- [`SERVER_INVALID_RESPONSE_UDP`](server-invalid-response-udp.md) - `planned` / `custom-dns-responder`
- [`SERVER_NOT_AUTHORITATIVE`](server-not-authoritative.md) - `planned` / `bind-delegation-mutation`
- [`SERVER_UNRESPONSIVE_TCP`](server-unresponsive-tcp.md) - `planned` / `bind-delegation-mutation`
- [`SERVER_UNRESPONSIVE_UDP`](server-unresponsive-udp.md) - `planned` / `bind-delegation-mutation`

### InvalidResponseError

- [`FORMERR`](formerr.md) - `planned` / `custom-dns-responder`
- [`INVALID_RCODE`](invalid-rcode.md) - `planned` / `custom-dns-responder`
- [`NETWORK_ERROR`](network-error.md) - `planned` / `custom-dns-responder`
- [`RESPONSE_ERROR`](response-error.md) - `planned` / `custom-dns-responder`
- [`TIMEOUT`](timeout.md) - `planned` / `custom-dns-responder`

### NSECError

- [`EXISTING_NAME_COVERED`](existing-name-covered.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`EXISTING_TYPE_NOT_IN_BITMAP`](existing-type-not-in-bitmap.md) - `done` / `existing-lab` / `existing-type-not-in-bitmap`
- [`INVALID_NSEC3_HASH`](invalid-nsec3-hash.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`INVALID_NSEC3_OWNER_NAME`](invalid-nsec3-owner-name.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`LAST_NSEC_NEXT_NOT_ZONE`](last-nsec-next-not-zone.md) - `done` / `existing-lab` / `last-nsec-next-not-zone`
- [`NEXT_CLOSEST_ENCLOSER_NOT_COVERED`](next-closest-encloser-not-covered.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`NONEMPTY_NSEC3_SALT`](nonempty-nsec3-salt.md) - `done` / `existing-lab` / `nonzero-nsec3-iteration-count`
- [`NONZERO_NSEC3_ITERATION_COUNT`](nonzero-nsec3-iteration-count.md) - `done` / `existing-lab` / `nonzero-nsec3-iteration-count`
- [`NO_CLOSEST_ENCLOSER`](no-closest-encloser.md) - `done` / `existing-lab` / `no-closest-encloser`
- [`NO_NSEC3_MATCHING_SNAME`](no-nsec3-matching-sname.md) - `done` / `existing-lab` / `no-nsec3-matching-sname`
- [`NO_NSEC_MATCHING_SNAME`](no-nsec-matching-sname.md) - `done` / `existing-lab` / `no-nsec-matching-sname`
- [`OPT_OUT_FLAG_NOT_SET`](opt-out-flag-not-set.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`REFERRAL_WITHOUT_NS`](referral-without-ns.md) - `done` / `existing-lab` / `referral-without-ns`
- [`REFERRAL_WITH_DS`](referral-with-ds.md) - `done` / `existing-lab` / `referral-with-ds`
- [`REFERRAL_WITH_SOA`](referral-with-soa.md) - `done` / `existing-lab` / `referral-with-soa`
- [`SNAME_COVERED`](sname-covered.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`SNAME_NOT_COVERED`](sname-not-covered.md) - `done` / `existing-lab` / `sname-not-covered`
- [`STYPE_IN_BITMAP`](stype-in-bitmap.md) - `done` / `existing-lab` / `stype-in-bitmap`
- [`UNSUPPORTED_NSEC3_ALGORITHM`](unsupported-nsec3-algorithm.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`WILDCARD_COVERED`](wildcard-covered.md) - `done` / `existing-lab` / `wildcard-covered`
- [`WILDCARD_EXPANSION_INVALID`](wildcard-expansion-invalid.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`WILDCARD_NOT_COVERED`](wildcard-not-covered.md) - `done` / `existing-lab` / `wildcard-not-covered`

### RRSIGError

- [`ALGORITHM_NOT_RECOMMENDED`](algorithm-not-recommended.md) - `done` / `existing-lab` / `algorithm-not-recommended`
- [`ALGORITHM_NOT_SUPPORTED`](algorithm-not-supported.md) - `done` / `existing-lab` / `algorithm-not-supported`
- [`ALGORITHM_PROHIBITED`](algorithm-prohibited.md) - `done` / `existing-lab` / `algorithm-prohibited`
- [`ALGORITHM_VALIDATION_PROHIBITED`](algorithm-validation-prohibited.md) - `done` / `existing-lab` / `algorithm-prohibited`
- [`DNSKEY_REVOKED_RRSIG`](dnskey-revoked-rrsig.md) - `done` / `existing-lab` / `dnskey-revoked-rrsig`
- [`EXPIRATION_IN_PAST`](expiration-in-past.md) - `done` / `existing-lab` / `expired-rrsig`
- [`EXPIRATION_WITHIN_CLOCK_SKEW`](expiration-within-clock-skew.md) - `done` / `existing-lab` / `expiration-within-clock-skew`
- [`INCEPTION_IN_FUTURE`](inception-in-future.md) - `done` / `existing-lab` / `future-rrsig`
- [`INCEPTION_WITHIN_CLOCK_SKEW`](inception-within-clock-skew.md) - `done` / `existing-lab` / `inception-within-clock-skew`
- [`ORIGINAL_TTL_EXCEEDED_RRSET`](original-ttl-exceeded-rrset.md) - `done` / `existing-lab` / `original-ttl-exceeded-rrset`
- [`ORIGINAL_TTL_EXCEEDED_RRSIG`](original-ttl-exceeded-rrsig.md) - `done` / `existing-lab` / `original-ttl-exceeded-rrsig`
- [`RRSET_TTL_MISMATCH`](rrset-ttl-mismatch.md) - `done` / `existing-lab` / `rrset-ttl-mismatch`
- [`RRSIG_BAD_LENGTH_ECDSA256`](rrsig-bad-length-ecdsa256.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`RRSIG_BAD_LENGTH_ECDSA384`](rrsig-bad-length-ecdsa384.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`RRSIG_BAD_LENGTH_ED25519`](rrsig-bad-length-ed25519.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`RRSIG_BAD_LENGTH_ED448`](rrsig-bad-length-ed448.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`RRSIG_BAD_LENGTH_GOST`](rrsig-bad-length-gost.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS`](rrsig-labels-exceed-rrset-owner-labels.md) - `done` / `existing-lab` / `rrsig-labels-exceed-owner-labels`
- [`SIGNATURE_INVALID`](signature-invalid.md) - `done` / `existing-lab` / `signature-invalid / missing-ksk`
- [`SIGNER_NOT_ZONE`](signer-not-zone.md) - `done` / `existing-lab` / `signer-not-zone`
- [`TTL_BEYOND_EXPIRATION`](ttl-beyond-expiration.md) - `done` / `existing-lab` / `ttl-beyond-expiration`

### ResponseError

- [`AUTHORITATIVE_REFERRAL`](authoritative-referral.md) - `planned` / `custom-dns-responder`
- [`CASE_NOT_PRESERVED`](case-not-preserved.md) - `planned` / `custom-dns-responder`
- [`CLIENT_COOKIE_MISMATCH`](client-cookie-mismatch.md) - `planned` / `custom-dns-responder`
- [`COOKIE_INVALID_LENGTH`](cookie-invalid-length.md) - `planned` / `custom-dns-responder`
- [`DNSSEC_DOWNGRADE_DO_CLEARED`](dnssec-downgrade-do-cleared.md) - `deferred-custom-responder` / `custom-dns-responder`
- [`DNSSEC_DOWNGRADE_EDNS_DISABLED`](dnssec-downgrade-edns-disabled.md) - `deferred-custom-responder` / `custom-dns-responder`
- [`EDNS_IGNORED`](edns-ignored.md) - `planned` / `custom-dns-responder`
- [`EDNS_SUPPORT_NO_OPT`](edns-support-no-opt.md) - `planned` / `custom-dns-responder`
- [`EDNS_UNDEFINED_FLAGS_SET`](edns-undefined-flags-set.md) - `planned` / `custom-dns-responder`
- [`EDNS_VERSION_MISMATCH`](edns-version-mismatch.md) - `planned` / `custom-dns-responder`
- [`ERROR_WITHOUT_EDNS_FLAG`](error-without-edns-flag.md) - `planned` / `custom-dns-responder`
- [`ERROR_WITHOUT_EDNS_OPTION`](error-without-edns-option.md) - `planned` / `custom-dns-responder`
- [`ERROR_WITHOUT_REQUEST_FLAG`](error-without-request-flag.md) - `planned` / `custom-dns-responder`
- [`ERROR_WITH_EDNS`](error-with-edns.md) - `planned` / `custom-dns-responder`
- [`ERROR_WITH_EDNS_FLAG`](error-with-edns-flag.md) - `planned` / `custom-dns-responder`
- [`ERROR_WITH_EDNS_OPTION`](error-with-edns-option.md) - `planned` / `custom-dns-responder`
- [`ERROR_WITH_EDNS_VERSION`](error-with-edns-version.md) - `planned` / `custom-dns-responder`
- [`ERROR_WITH_REQUEST_FLAG`](error-with-request-flag.md) - `planned` / `custom-dns-responder`
- [`FOREIGN_CLASS_DATA_ADDITIONAL`](foreign-class-data-additional.md) - `planned` / `custom-dns-responder`
- [`FOREIGN_CLASS_DATA_ANSWER`](foreign-class-data-answer.md) - `planned` / `custom-dns-responder`
- [`FOREIGN_CLASS_DATA_AUTHORITY`](foreign-class-data-authority.md) - `planned` / `custom-dns-responder`
- [`GRATUITOUS_COOKIE`](gratuitous-cookie.md) - `planned` / `custom-dns-responder`
- [`GRATUITOUS_OPT`](gratuitous-opt.md) - `planned` / `custom-dns-responder`
- [`IMPLEMENTED_EDNS_VERSION_NOT_PROVIDED`](implemented-edns-version-not-provided.md) - `planned` / `custom-dns-responder`
- [`INCONSISTENT_NXDOMAIN`](inconsistent-nxdomain.md) - `planned` / `custom-dns-responder`
- [`INCONSISTENT_NXDOMAIN_ANCESTOR`](inconsistent-nxdomain-ancestor.md) - `excluded-bind9` / `not-bind9-reproducible`
- [`INVALID_SERVER_COOKIE_WITHOUT_BADCOOKIE`](invalid-server-cookie-without-badcookie.md) - `planned` / `custom-dns-responder`
- [`MALFORMED_COOKIE_WITHOUT_FORMERR`](malformed-cookie-without-formerr.md) - `planned` / `custom-dns-responder`
- [`MISSING_NSEC_FOR_NODATA`](missing-nsec-for-nodata.md) - `done` / `existing-lab` / `missing-nsec-for-nodata`
- [`MISSING_NSEC_FOR_NXDOMAIN`](missing-nsec-for-nxdomain.md) - `done` / `existing-lab` / `missing-nsec-for-nxdomain`
- [`MISSING_NSEC_FOR_WILDCARD`](missing-nsec-for-wildcard.md) - `triage` / `manual-classification-needed`
- [`MISSING_RRSIG`](missing-rrsig.md) - `done` / `existing-lab` / `missing-rrsig`
- [`MISSING_RRSIG_FOR_ALG_DLV`](missing-rrsig-for-alg-dlv.md) - `triage` / `manual-classification-needed`
- [`MISSING_RRSIG_FOR_ALG_DNSKEY`](missing-rrsig-for-alg-dnskey.md) - `done` / `existing-lab` / `missing-rrsig-for-alg-dnskey`
- [`MISSING_RRSIG_FOR_ALG_DS`](missing-rrsig-for-alg-ds.md) - `deferred-custom-responder` / `custom-dns-responder`
- [`MISSING_SOA_FOR_NODATA`](missing-soa-for-nodata.md) - `deferred-custom-responder` / `custom-dns-responder`
- [`MISSING_SOA_FOR_NXDOMAIN`](missing-soa-for-nxdomain.md) - `deferred-custom-responder` / `custom-dns-responder`
- [`NOT_AUTHORITATIVE`](not-authoritative.md) - `planned` / `custom-dns-responder`
- [`NO_COOKIE_OPTION`](no-cookie-option.md) - `planned` / `custom-dns-responder`
- [`NO_SERVER_COOKIE`](no-server-cookie.md) - `planned` / `custom-dns-responder`
- [`NO_SERVER_COOKIE_WITHOUT_BADCOOKIE`](no-server-cookie-without-badcookie.md) - `planned` / `custom-dns-responder`
- [`PMTU_EXCEEDED`](pmtu-exceeded.md) - `planned` / `custom-dns-responder`
- [`RECURSION_NOT_AVAILABLE`](recursion-not-available.md) - `planned` / `custom-dns-responder`
- [`SOA_NOT_OWNER_FOR_NODATA`](soa-not-owner-for-nodata.md) - `triage` / `manual-classification-needed`
- [`SOA_NOT_OWNER_FOR_NXDOMAIN`](soa-not-owner-for-nxdomain.md) - `triage` / `manual-classification-needed`
- [`UNABLE_TO_RETRIEVE_DNSSEC_RECORDS`](unable-to-retrieve-dnssec-records.md) - `planned` / `custom-dns-responder`
- [`UPWARD_REFERRAL`](upward-referral.md) - `planned` / `custom-dns-responder`

### TrustAnchorError

- [`NO_TRUST_ANCHOR_SIGNING`](no-trust-anchor-signing.md) - `done` / `existing-lab` / `no-trust-anchor-signing`

### ZoneDataError

- [`CNAME_LOOP`](cname-loop.md) - `done` / `existing-lab` / `cname-loop`
- [`CNAME_WITH_OTHER_DATA`](cname-with-other-data.md) - `excluded-bind9` / `not-bind9-reproducible`
