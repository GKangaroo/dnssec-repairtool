import tempfile
import unittest
from pathlib import Path
from unittest import mock

import dnssec_repair_engine as repair
import zone_backend_adapter as adapter


class TestZoneBackendAdapter(unittest.TestCase):
    def test_zonefile_adapter_repairs_ds_and_child_signals_without_template_rebuild(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            child = tmp_path / "db.example.com"
            parent = tmp_path / "db.com"
            root = tmp_path / "db.root"
            child.write_text('@ IN CDS 0 0 0 00\n@ IN CDNSKEY 0 3 0 AA==\nwww IN A 192.0.2.1\n', encoding="ascii")
            parent.write_text(
                "example.com. IN NS ns.example.com.\n"
                "example.com. IN DS 1 13 2 BAD\n"
                "example.com. 300 IN DS 1 13 2 BADTTL\n"
                "example.com. 300 DS 1 13 2 BADNOCLASS\n",
                encoding="ascii",
            )
            root.write_text('com. IN DS 1 13 2 OLD\n', encoding="ascii")

            z = adapter.ZoneFileBackendAdapter()
            with (
                mock.patch.object(adapter.ZoneFileBackendAdapter, "child_unsigned", new_callable=mock.PropertyMock, return_value=child),
                mock.patch.object(adapter.ZoneFileBackendAdapter, "parent_unsigned", new_callable=mock.PropertyMock, return_value=parent),
                mock.patch.object(adapter.ZoneFileBackendAdapter, "root_unsigned", new_callable=mock.PropertyMock, return_value=root),
                mock.patch("dnssec_lab.ds_from_ksk", side_effect=lambda name: f"{'example.com.' if name == 'example' else 'com.'} IN DS 123 13 2 GOOD"),
                mock.patch("dnssec_lab.sign_zone") as sign_zone,
                mock.patch("dnssec_lab.reset_keys") as reset_keys,
                mock.patch("dnssec_lab.write_zone_files") as write_zone_files,
            ):
                plan = repair.RepairPlan(
                    backend="powerdns",
                    scenario="wild-grok",
                    zone="example.com.",
                    parent_zone="com.",
                    instructions=(
                        repair.RepairInstruction(
                            backend="powerdns",
                            scenario="wild-grok",
                            code="DIGEST_INVALID",
                            family="ds_rrset_repair",
                            executor="parent-side repair",
                            required_permission="parent",
                            action="fix ds",
                            demo_action="controlled",
                            note="",
                        ),
                        repair.RepairInstruction(
                            backend="powerdns",
                            scenario="wild-grok",
                            code="MULTIPLE_CDS",
                            family="cds_cdnskey_multi_signal",
                            executor="child-zone repair",
                            required_permission="child",
                            action="fix cds",
                            demo_action="controlled",
                            note="",
                        ),
                    ),
                )
                result = z.execute_plan(plan)

                self.assertNotIn("CDS", child.read_text(encoding="ascii"))
                self.assertIn("www IN A 192.0.2.1", child.read_text(encoding="ascii"))
                self.assertIn("example.com. IN DS 123 13 2 GOOD", parent.read_text(encoding="ascii"))
                self.assertNotIn("BAD", parent.read_text(encoding="ascii"))
                self.assertEqual(sign_zone.call_count, 3)
                reset_keys.assert_not_called()
                write_zone_files.assert_not_called()
                self.assertIn("replace parent DS", " ".join(result.actions))


if __name__ == "__main__":
    unittest.main()
