import json
import tempfile
import unittest
from pathlib import Path

import dnsviz_grok_adapter as adapter


class TestDNSVizGrokAdapter(unittest.TestCase):
    def test_diagnose_minimal_ds_error_grok(self):
        data = {
            "com.": {"zone": {"status": "SECURE"}},
            "example.com.": {
                "zone": {
                    "status": "INVALID",
                    "servers": {"ns.example.com.": {"auth": ["192.0.2.53"]}},
                },
                "delegation": {
                    "errors": [{"code": "NO_SEP", "description": "no sep"}],
                    "ds": [
                        {
                            "id": "13/12345/2",
                            "key_tag": 12345,
                            "algorithm": 13,
                            "digest_type": 2,
                            "status": "INVALID_DIGEST",
                            "errors": [{"code": "DIGEST_INVALID", "description": "bad digest"}],
                        }
                    ],
                },
                "dnskey": [
                    {
                        "id": "13/12345",
                        "key_tag": 12345,
                        "algorithm": 13,
                        "flags": 257,
                        "key_length": 512,
                        "status": "SECURE",
                    }
                ],
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "grok.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            diagnosis = adapter.diagnose_grok(path, "powerdns")

        self.assertEqual(diagnosis.zone, "example.com.")
        self.assertEqual(diagnosis.parent_zone, "com.")
        self.assertEqual(diagnosis.error_codes, ("NO_SEP", "DIGEST_INVALID"))
        self.assertEqual(diagnosis.ds_records[0].status, "INVALID_DIGEST")
        self.assertEqual(diagnosis.dnskeys[0].key_tag, 12345)
        self.assertEqual(diagnosis.auth_servers[0].addresses, ("192.0.2.53",))

    def test_plan_from_existing_bad_ds_grok_if_present(self):
        path = Path("work/out/bad-ds.before.grok.json")
        if not path.exists():
            self.skipTest("bad-ds grok fixture is not present")
        plan = adapter.plan_from_grok(path, "powerdns")
        self.assertEqual(plan.backend, "powerdns")
        self.assertEqual(plan.scenario, "wild-grok")
        self.assertIn("DIGEST_INVALID", plan.codes)
        self.assertIn("NO_SEP", plan.codes)
        families = {instruction.family for instruction in plan.instructions}
        self.assertIn("ds_rrset_repair", families)
        self.assertIn("key_chain_repair", families)


if __name__ == "__main__":
    unittest.main()
