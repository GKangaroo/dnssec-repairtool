import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import dnssec_lab


def write_grok(path: Path, zone: str = "broken.example.", parent: str = "example.") -> None:
    data = {
        parent: {"zone": {"status": "SECURE"}},
        zone: {
            "zone": {"status": "INVALID", "servers": {"ns." + zone: {"auth": ["192.0.2.53"]}}},
            "delegation": {"errors": [{"code": "DIGEST_INVALID"}]},
        },
    }
    path.write_text(json.dumps(data), encoding="utf-8")


class TestRealcaseRepair(unittest.TestCase):
    def tearDown(self):
        dnssec_lab.reset_lab_zones()

    def test_arbitrary_domain_uses_live_grok_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            grok = root / "capture.grok.json"
            zone_file = root / "db.broken.example"
            write_grok(grok)
            zone_file.write_text(
                """$ORIGIN broken.example.
$TTL 300
@ IN SOA ns.broken.example. hostmaster.broken.example. 1 300 300 1200 300
@ IN NS ns.broken.example.
www IN A 192.0.2.10
_sip._tcp IN SRV 10 5 5060 sip.broken.example.
""",
                encoding="ascii",
            )
            with (
                mock.patch("controlled_dnssec_deploy.setup_unsigned_lab", return_value=("initialize lab",)),
                mock.patch("controlled_dnssec_deploy.write_unsigned_child_with_records") as write_child,
                mock.patch("controlled_dnssec_deploy.publish_child_ds_to_parent", return_value="DS"),
                mock.patch("controlled_dnssec_deploy.sign_deployed_chain"),
                mock.patch("controlled_dnssec_deploy.start_backend"),
                mock.patch("controlled_dnssec_deploy.stop_backend") as stop_backend,
                mock.patch(
                    "controlled_dnssec_deploy.verify_deployment",
                    return_value=(root / "local-after.grok.json", ()),
                ),
                mock.patch(
                    "controlled_zone_repair.repair_backend_from_grok",
                    return_value=SimpleNamespace(actions=("replace parent DS", "resign zones")),
                ) as execute,
                mock.patch("lab_config_exporter.export_config_bundle", return_value=str(root / "bundle")),
            ):
                result = dnssec_lab.repair_realcase(
                    domain="broken.example",
                    backend="bind9",
                    out_dir=root / "out",
                    grok=grok,
                    zone_file=zone_file,
                )

        self.assertEqual(result.source_domain, "broken.example.")
        self.assertEqual(result.observed_codes, ("DIGEST_INVALID",))
        self.assertEqual(result.repair_plan["codes"], ["DIGEST_INVALID"])
        self.assertTrue(result.records_complete)
        self.assertTrue(result.local_converged)
        self.assertEqual(result.verification_scope, "local-controlled")
        self.assertFalse(result.public_changes_applied)
        self.assertEqual(write_child.call_args.args[0][0].owner, "_sip._tcp.broken.example.")
        execute.assert_called_once_with("bind9", grok, rotate_keys=False)
        stop_backend.assert_called_once_with("bind9")

    def test_live_capture_failure_is_not_silently_ignored(self):
        with (
            mock.patch("dnssec_lab.dnsviz_live_domain", side_effect=SystemExit("capture failed")),
            mock.patch("controlled_dnssec_deploy.setup_unsigned_lab") as setup,
        ):
            with self.assertRaisesRegex(SystemExit, "capture failed"):
                dnssec_lab.repair_realcase(
                    domain="arbitrary.example",
                    zone_file=Path("unused.zone"),
                )
        setup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
