from .algorithm_not_recommended import scenario as algorithm_not_recommended
from .algorithm_not_supported import scenario as algorithm_not_supported
from .algorithm_prohibited import scenario as algorithm_prohibited
from .bad_ds import scenario as bad_ds
from .cdnskey_delete_multiple_records import scenario as cdnskey_delete_multiple_records
from .cdnskey_inconsistent_with_cds import scenario as cdnskey_inconsistent_with_cds
from .cdnskey_inconsistent_with_ds import scenario as cdnskey_inconsistent_with_ds
from .cdnskey_incorrect_delete_values import scenario as cdnskey_incorrect_delete_values
from .cdnskey_signer_invalid import scenario as cdnskey_signer_invalid
from .cds_delete_multiple_records import scenario as cds_delete_multiple_records
from .cds_inconsistent_with_ds import scenario as cds_inconsistent_with_ds
from .cds_incorrect_delete_values import scenario as cds_incorrect_delete_values
from .cds_signer_invalid import scenario as cds_signer_invalid
from .cname_loop import scenario as cname_loop
from .digest_algorithm_not_supported import scenario as digest_algorithm_not_supported
from .dnskey_bad_length_ecdsa256 import scenario as dnskey_bad_length_ecdsa256
from .dnskey_bad_length_ecdsa384 import scenario as dnskey_bad_length_ecdsa384
from .dnskey_bad_length_ed25519 import scenario as dnskey_bad_length_ed25519
from .dnskey_bad_length_ed448 import scenario as dnskey_bad_length_ed448
from .dnskey_bad_length_gost import scenario as dnskey_bad_length_gost
from .dnskey_missing_from_servers import scenario as dnskey_missing_from_servers
from .dnskey_not_at_zone_apex import scenario as dnskey_not_at_zone_apex
from .dnskey_revoked_ds import scenario as dnskey_revoked_ds
from .dnskey_revoked_rrsig import scenario as dnskey_revoked_rrsig
from .dnskey_zero_length import scenario as dnskey_zero_length
from .ds_digest_algorithm_maybe_ignored import scenario as ds_digest_algorithm_maybe_ignored
from .ds_digest_algorithm_prohibited import scenario as ds_digest_algorithm_prohibited
from .expired_rrsig import scenario as expired_rrsig
from .expiration_within_clock_skew import scenario as expiration_within_clock_skew
from .existing_name_covered import scenario as existing_name_covered
from .existing_type_not_in_bitmap import scenario as existing_type_not_in_bitmap
from .future_rrsig import scenario as future_rrsig
from .inception_within_clock_skew import scenario as inception_within_clock_skew
from .last_nsec_next_not_zone import scenario as last_nsec_next_not_zone
from .missing_ksk import scenario as missing_ksk
from .missing_nsec_for_nodata import scenario as missing_nsec_for_nodata
from .missing_nsec_for_nxdomain import scenario as missing_nsec_for_nxdomain
from .missing_nsec_for_wildcard import scenario as missing_nsec_for_wildcard
from .missing_rrsig import scenario as missing_rrsig
from .missing_rrsig_for_alg_dnskey import scenario as missing_rrsig_for_alg_dnskey
from .multiple_cdnskey import scenario as multiple_cdnskey
from .multiple_cds import scenario as multiple_cds
from .nonempty_nsec3_salt import scenario as nonempty_nsec3_salt
from .nonzero_nsec3_iteration_count import scenario as nonzero_nsec3_iteration_count
from .no_closest_encloser import scenario as no_closest_encloser
from .no_nsec3_matching_sname import scenario as no_nsec3_matching_sname
from .no_nsec_matching_sname import scenario as no_nsec_matching_sname
from .no_trust_anchor_signing import scenario as no_trust_anchor_signing
from .original_ttl_exceeded_rrset import scenario as original_ttl_exceeded_rrset
from .original_ttl_exceeded_rrsig import scenario as original_ttl_exceeded_rrsig
from .referral_with_ds import scenario as referral_with_ds
from .referral_with_soa import scenario as referral_with_soa
from .referral_without_ns import scenario as referral_without_ns
from .realcase_al_stale_ds_rollover import scenario as realcase_al_stale_ds_rollover
from .realcase_dnssec_failed_org import scenario as realcase_dnssec_failed_org
from .realcase_sigfail_ippacket_stream import scenario as realcase_sigfail_ippacket_stream
from .realcase_tamu_edu_expired_rrsig import scenario as realcase_tamu_edu_expired_rrsig
from .revoked_not_signing import scenario as revoked_not_signing
from .rrset_ttl_mismatch import scenario as rrset_ttl_mismatch
from .rrsig_bad_length_ecdsa256 import scenario as rrsig_bad_length_ecdsa256
from .rrsig_bad_length_ecdsa384 import scenario as rrsig_bad_length_ecdsa384
from .rrsig_bad_length_ed25519 import scenario as rrsig_bad_length_ed25519
from .rrsig_bad_length_ed448 import scenario as rrsig_bad_length_ed448
from .rrsig_labels_exceed_owner_labels import scenario as rrsig_labels_exceed_owner_labels
from .signature_invalid import scenario as signature_invalid
from .signer_not_zone import scenario as signer_not_zone
from .sname_not_covered import scenario as sname_not_covered
from .stype_in_bitmap import scenario as stype_in_bitmap
from .ttl_beyond_expiration import scenario as ttl_beyond_expiration
from .wildcard_not_covered import scenario as wildcard_not_covered
from .wildcard_covered import scenario as wildcard_covered


SCENARIOS = {
    item.name: item
    for item in [
        algorithm_not_recommended,
        algorithm_not_supported,
        algorithm_prohibited,
        bad_ds,
        cdnskey_delete_multiple_records,
        cdnskey_inconsistent_with_cds,
        cdnskey_inconsistent_with_ds,
        cdnskey_incorrect_delete_values,
        cdnskey_signer_invalid,
        cds_delete_multiple_records,
        cds_inconsistent_with_ds,
        cds_incorrect_delete_values,
        cds_signer_invalid,
        cname_loop,
        digest_algorithm_not_supported,
        dnskey_bad_length_ecdsa256,
        dnskey_bad_length_ecdsa384,
        dnskey_bad_length_ed25519,
        dnskey_bad_length_ed448,
        dnskey_bad_length_gost,
        dnskey_missing_from_servers,
        dnskey_not_at_zone_apex,
        dnskey_revoked_ds,
        dnskey_revoked_rrsig,
        dnskey_zero_length,
        ds_digest_algorithm_maybe_ignored,
        ds_digest_algorithm_prohibited,
        expired_rrsig,
        expiration_within_clock_skew,
        existing_name_covered,
        existing_type_not_in_bitmap,
        future_rrsig,
        inception_within_clock_skew,
        last_nsec_next_not_zone,
        missing_ksk,
        missing_nsec_for_nodata,
        missing_nsec_for_nxdomain,
        missing_nsec_for_wildcard,
        missing_rrsig,
        missing_rrsig_for_alg_dnskey,
        multiple_cdnskey,
        multiple_cds,
        nonempty_nsec3_salt,
        nonzero_nsec3_iteration_count,
        no_closest_encloser,
        no_nsec3_matching_sname,
        no_nsec_matching_sname,
        no_trust_anchor_signing,
        original_ttl_exceeded_rrset,
        original_ttl_exceeded_rrsig,
        referral_with_ds,
        referral_with_soa,
        referral_without_ns,
        realcase_al_stale_ds_rollover,
        realcase_dnssec_failed_org,
        realcase_sigfail_ippacket_stream,
        realcase_tamu_edu_expired_rrsig,
        revoked_not_signing,
        rrset_ttl_mismatch,
        rrsig_bad_length_ecdsa256,
        rrsig_bad_length_ecdsa384,
        rrsig_bad_length_ed25519,
        rrsig_bad_length_ed448,
        rrsig_labels_exceed_owner_labels,
        signature_invalid,
        signer_not_zone,
        sname_not_covered,
        stype_in_bitmap,
        ttl_beyond_expiration,
        wildcard_not_covered,
        wildcard_covered,
    ]
}


def get(name: str):
    return SCENARIOS.get(name)


def names() -> list[str]:
    return sorted(SCENARIOS)
