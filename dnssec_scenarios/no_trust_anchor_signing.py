from pathlib import Path

from .common import Scenario


def after_trusted_keys(ctx) -> None:
    ctx.ensure_algorithm_keys("com", "ED25519")
    root = Path.cwd()
    keydir = root / "work" / "keys" / "com"
    ed25519_ksks = [
        p
        for p in keydir.glob("Kcom.+015+*.key")
        if " DNSKEY 257 3 15 " in p.read_text(encoding="ascii")
    ]
    if not ed25519_ksks:
        raise SystemExit("could not find generated com. ED25519 KSK")
    (root / "work" / "out" / "trusted.keys").write_text(
        ed25519_ksks[0].read_text(encoding="ascii").strip() + "\n",
        encoding="ascii",
    )


scenario = Scenario(
    name="no-trust-anchor-signing",
    description="DNSViz 信任锚指向未发布且未自签的 com. KSK。",
    expected_codes=("NO_TRUST_ANCHOR_SIGNING",),
    qname="com.",
    rrtypes="DNSKEY",
    after_trusted_keys=after_trusted_keys,
    fix_message="fixing invalid trust anchor input by restoring trusted.keys to the published self-signing KSK.",
)
