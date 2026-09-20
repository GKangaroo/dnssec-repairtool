import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import controlled_dnssec_deploy as deploy
import dnssec_lab


class TestControlledDNSSECDeploy(unittest.TestCase):
    def tearDown(self):
        dnssec_lab.reset_lab_zones()

    def test_deploy_controlled_wiring_without_verify(self):
        with (
            mock.patch("controlled_dnssec_deploy.setup_unsigned_lab", return_value=("init unsigned",)),
            mock.patch("controlled_dnssec_deploy.publish_child_ds_to_parent", return_value="example.com. IN DS 123 13 2 GOOD"),
            mock.patch("controlled_dnssec_deploy.sign_deployed_chain") as sign_chain,
            mock.patch("controlled_dnssec_deploy.start_backend") as start_backend,
        ):
            result = deploy.deploy_controlled("bind9", verify=False)

        self.assertEqual(result.backend, "bind9")
        self.assertEqual(result.zone, "example.com.")
        self.assertEqual(result.parent_zone, "com.")
        self.assertEqual(result.final_codes, ())
        self.assertIsNone(result.converged)
        self.assertEqual(result.verification_scope, "local-controlled")
        self.assertIn("publish DS", " ".join(result.actions))
        sign_chain.assert_called_once_with()
        start_backend.assert_called_once_with("bind9")

    def test_deploy_controlled_runs_dnsviz_verification(self):
        with (
            mock.patch("controlled_dnssec_deploy.setup_unsigned_lab", return_value=("init unsigned",)),
            mock.patch("controlled_dnssec_deploy.publish_child_ds_to_parent", return_value="example.com. IN DS 123 13 2 GOOD"),
            mock.patch("controlled_dnssec_deploy.sign_deployed_chain"),
            mock.patch("controlled_dnssec_deploy.start_backend"),
            mock.patch("controlled_dnssec_deploy.verify_deployment", return_value=(Path("work/out/deploy.grok.json"), ("NO_SEP",))),
        ):
            result = deploy.deploy_controlled("powerdns", prefix="deploy", verify=True)

        self.assertEqual(result.backend, "powerdns")
        self.assertEqual(result.final_codes, ("NO_SEP",))
        self.assertFalse(result.converged)
        self.assertEqual(result.verify_grok, "work/out/deploy.grok.json")

    def test_deploy_realcase_imports_business_records_before_signing(self):
        imported = (
            deploy.ImportedRecord("example.com.", 300, "A", "203.0.113.10", "source.example."),
            deploy.ImportedRecord("www.example.com.", 300, "A", "203.0.113.20", "www.source.example."),
        )
        record_import = deploy.RecordImportResult(imported, "zone-file:test.zone", True)
        with (
            mock.patch("dnssec_lab.dnsviz_live_domain", return_value=Path("live.grok.json")),
            mock.patch(
                "dnsviz_grok_adapter.diagnose_grok",
                return_value=SimpleNamespace(zone="source.example.", error_codes=("DIGEST_INVALID",)),
            ),
            mock.patch(
                "realcase_chain_importer.import_realcase",
                return_value=SimpleNamespace(files={"before_records": "before.zone", "summary": "summary.json"}),
            ),
            mock.patch("controlled_dnssec_deploy.setup_unsigned_lab", return_value=("init unsigned",)),
            mock.patch("controlled_dnssec_deploy.acquire_business_records", return_value=record_import) as acquire,
            mock.patch("controlled_dnssec_deploy.write_unsigned_child_with_records") as write_child,
            mock.patch("controlled_dnssec_deploy.publish_child_ds_to_parent", return_value="example.com. IN DS 123 13 2 GOOD"),
            mock.patch("controlled_dnssec_deploy.sign_deployed_chain") as sign_chain,
            mock.patch("controlled_dnssec_deploy.start_backend") as start_backend,
            mock.patch("controlled_dnssec_deploy.write_imported_records") as write_imported,
            mock.patch("lab_config_exporter.export_config_bundle", return_value="bundle"),
        ):
            result = deploy.deploy_realcase("bind9", domain="source.example", verify=False)

        self.assertEqual(result.source_domain, "source.example.")
        self.assertEqual(result.qnames, ("source.example.", "www.source.example."))
        self.assertEqual(result.imported_records, imported)
        self.assertIsNone(result.deploy.converged)
        self.assertTrue(result.records_complete)
        self.assertEqual(result.live_observed_codes, ("DIGEST_INVALID",))
        self.assertFalse(result.public_changes_applied)
        self.assertIn("import 2 business record", " ".join(result.deploy.actions))
        acquire.assert_called_once_with(
            "source.example.",
            qnames=("source.example.", "www.source.example."),
            zone_file=None,
            axfr_server=None,
            axfr_port=53,
            allow_partial_records=False,
        )
        write_child.assert_called_once_with(imported)
        sign_chain.assert_called_once_with()
        start_backend.assert_called_once_with("bind9")
        write_imported.assert_called_once()

    def test_public_record_rewrite_maps_source_domain_to_lab_zone(self):
        dnssec_lab.configure_lab_zones("source.example.")
        self.assertEqual(deploy._rewrite_owner_to_lab("www.source.example.", "source.example"), "www.source.example.")
        self.assertEqual(deploy._rewrite_owner_to_lab("source.example.", "source.example"), "source.example.")
        self.assertIsNone(deploy._rewrite_owner_to_lab("other.example.", "source.example"))
        self.assertEqual(
            deploy._rewrite_owner_to_lab("www.source.example.", "source.example", "example.com."),
            "www.example.com.",
        )

    def test_unsigned_child_publishes_cds_and_cdnskey_signals(self):
        dnssec_lab.reset_workdir()
        dnssec_lab.ensure_keys()
        deploy.write_unsigned_child_with_records(
            (deploy.ImportedRecord("example.com.", 300, "A", "203.0.113.10", "source.example."),)
        )

        child_zone = dnssec_lab.LabContext().unsigned_zone_path("example")
        text = child_zone.read_text(encoding="ascii")
        self.assertIn(dnssec_lab.cds_from_ksk("example"), text)
        self.assertIn(dnssec_lab.cdnskey_from_ksk("example"), text)

    def test_recursive_sample_requires_explicit_partial_opt_in(self):
        with mock.patch("controlled_dnssec_deploy.collect_public_business_records", return_value=()):
            with self.assertRaisesRegex(SystemExit, "incomplete recursive-DNS sample"):
                deploy.acquire_business_records("example.com.")

    def test_deploy_realcase_does_not_hide_live_capture_failure(self):
        with (
            mock.patch("dnssec_lab.dnsviz_live_domain", side_effect=SystemExit("capture failed")),
            mock.patch("controlled_dnssec_deploy.setup_unsigned_lab") as setup,
        ):
            with self.assertRaisesRegex(SystemExit, "capture failed"):
                deploy.deploy_realcase(
                    "bind9",
                    domain="example.com",
                    zone_file=Path("unused.zone"),
                )
        setup.assert_not_called()

    def test_zone_file_import_preserves_arbitrary_business_records(self):
        zone_text = """$ORIGIN example.com.
$TTL 300
@ IN SOA ns.example.com. hostmaster.example.com. 1 300 300 1200 300
@ IN NS ns.example.com.
@ IN MX 10 mail.example.com.
_sip._tcp IN SRV 10 5 5060 sip.example.com.
_443._tcp IN TLSA 3 1 1 AABB
child IN DS 12345 13 2 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
www IN A 192.0.2.10
"""
        with tempfile.TemporaryDirectory() as tmp:
            zone_file = Path(tmp) / "db.example.com"
            zone_file.write_text(zone_text, encoding="ascii")
            result = deploy.acquire_business_records("example.com.", zone_file=zone_file)

        lines = {record.to_zone_line() for record in result.records}
        self.assertTrue(result.complete)
        self.assertIn("example.com. 300 IN MX 10 mail.example.com.", lines)
        self.assertIn("_sip._tcp.example.com. 300 IN SRV 10 5 5060 sip.example.com.", lines)
        self.assertIn("_443._tcp.example.com. 300 IN TLSA 3 1 1 aabb", lines)
        self.assertIn(
            "child.example.com. 300 IN DS 12345 13 2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            lines,
        )
        self.assertNotIn("example.com. 300 IN NS ns.example.com.", lines)


if __name__ == "__main__":
    unittest.main()
