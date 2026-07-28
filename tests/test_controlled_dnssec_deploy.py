import unittest
from pathlib import Path
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
        self.assertTrue(result.converged)
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
        with (
            mock.patch("controlled_dnssec_deploy.setup_unsigned_lab", return_value=("init unsigned",)),
            mock.patch("controlled_dnssec_deploy.collect_public_business_records", return_value=imported) as collect,
            mock.patch("controlled_dnssec_deploy.write_unsigned_child_with_records") as write_child,
            mock.patch("controlled_dnssec_deploy.publish_child_ds_to_parent", return_value="example.com. IN DS 123 13 2 GOOD"),
            mock.patch("controlled_dnssec_deploy.sign_deployed_chain") as sign_chain,
            mock.patch("controlled_dnssec_deploy.start_backend") as start_backend,
            mock.patch("controlled_dnssec_deploy.write_imported_records") as write_imported,
        ):
            result = deploy.deploy_realcase("bind9", domain="source.example", verify=False)

        self.assertEqual(result.source_domain, "source.example.")
        self.assertEqual(result.qnames, ("source.example.", "www.source.example."))
        self.assertEqual(result.imported_records, imported)
        self.assertTrue(result.deploy.converged)
        self.assertIn("import 2 public business record", " ".join(result.deploy.actions))
        collect.assert_called_once_with("source.example.", ("source.example.", "www.source.example."))
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


if __name__ == "__main__":
    unittest.main()
