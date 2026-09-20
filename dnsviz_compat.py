#!/usr/bin/env python3
"""Runtime compatibility shims for system-installed dnsviz.

Some Debian/Ubuntu dnsviz builds crash when a DNSViz analysis contains a
negative response whose SOA RRset belongs to an unsigned zone reachable only
through a CNAME chain (for example deb.debian.org -> debian.map.fastlydns.net).
The CNAME-target zone is never inserted into the authoritative-auth graph, so
``response_component_status`` has no entry for that SOA RRsetInfo, and
serialization raises ``KeyError`` (``rrset_status_mapping[None]`` style).

The shim below makes ``response_component_status`` a tolerant dict whose
``__missing__`` returns ``RRSET_STATUS_INSECURE`` for any unknown component.
All serialization sites in dnsviz (rrset/negative-response/DNSKEY status) then
complete without raising and report an honest "INSECURE" status for the
unsigned CNAME-target records.
"""

from __future__ import annotations


def apply() -> None:
    """Idempotently patch dnsviz serialization so unknown statuses never crash."""
    if getattr(apply, "_applied", False):
        return
    try:
        from dnsviz.analysis import offline as _offline
        from dnsviz.analysis import status as _status

        class _TolerantStatusMapping(dict):
            def __missing__(self, key):  # noqa: D105
                return "INDETERMINATE"

        # Guard the int->label mapping as well; some builds index it directly.
        if not isinstance(_status.rrset_status_mapping, _TolerantStatusMapping):
            _status.rrset_status_mapping = _TolerantStatusMapping(_status.rrset_status_mapping)

        class _TolerantComponentStatus(dict):
            def __missing__(self, key):  # noqa: D105
                return _status.RRSET_STATUS_INSECURE

        _set = _offline.OfflineDomainNameAnalysis._set_response_component_status

        def _patched_set(self, response_component_status, is_dlv=False, trace=None, follow_mx=True):
            if not isinstance(response_component_status, _TolerantComponentStatus):
                response_component_status = _TolerantComponentStatus(response_component_status)
            return _set(self, response_component_status, is_dlv=is_dlv, trace=trace, follow_mx=follow_mx)

        _offline.OfflineDomainNameAnalysis._set_response_component_status = _patched_set
    except Exception:  # dnsviz may be absent; the shim must never break startup
        return
    apply._applied = True


if __name__ == "__main__":
    apply()
