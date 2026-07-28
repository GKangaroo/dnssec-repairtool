import json
import tempfile
import unittest
from pathlib import Path

import realcase_chain_importer as importer


class TestRealcaseChainImporter(unittest.TestCase):
    def _write_grok(self, root: Path) -> Path:
        data = {
            "example.": {"zone": {"status": "SECURE"}},
            "broken.example.": {
                "zone": {
                    "status": "INVALID",
                    "servers": {"ns.broken.example.": {"auth": ["192.0.2.53"]}},
                },
                "delegation": {
                    "ds": [
                        {
                            "key_tag": 12345,
                            "algorithm": 13,
                            "digest_type": 2,
                            "digest": "abc123",
                            "ttl": 300,
                            "status": "INVALID_DIGEST",
                            "errors": [{"code": "DIGEST_INVALID"}],
                        }
                    ],
                    "errors": [{"code": "NO_SEP"}],
                },
                "dnskey": [
                    {
                        "flags": 257,
                        "protocol": 3,
                        "algorithm": 13,
                        "key": "AA BB",
                        "ttl": 300,
                        "status": "BOGUS",
                    }
                ],
                "queries": {
                    "broken.example./IN/DNSKEY": {
                        "answer": [
                            {
                                "name": "broken.example.",
                                "ttl": 300,
                                "type": "DNSKEY",
                                "rdata": ["257 3 13 AA BB"],
                                "status": "BOGUS",
                                "rrsig": [
                                    {
                                        "signer": "broken.example.",
                                        "algorithm": 13,
                                        "key_tag": 12345,
                                        "original_ttl": 300,
                                        "labels": 2,
                                        "inception": "2026-07-22 05:48:27 UTC",
                                        "expiration": "2027-07-06 00:00:00 UTC",
                                        "signature": "SIG==",
                                        "ttl": 300,
                                        "status": "VALID",
                                    }
                                ],
                            }
                        ]
                    },
                    "www.broken.example./IN/A": {
                        "answer": [
                            {
                                "name": "www.broken.example.",
                                "ttl": 300,
                                "type": "A",
                                "rdata": ["192.0.2.10"],
                                "status": "BOGUS",
                            }
                        ]
                    },
                },
            },
        }
        path = root / "grok.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_extract_and_clone_records_from_grok(self):
        with tempfile.TemporaryDirectory() as tmp:
            grok = self._write_grok(Path(tmp))
            records = importer.extract_records_from_grok(grok)
            lines = {record.to_zone_line() for record in records}

        self.assertIn("broken.example. 300 IN DS 12345 13 2 abc123", lines)
        self.assertIn("broken.example. 300 IN DNSKEY 257 3 13 AABB", lines)
        self.assertIn("www.broken.example. 300 IN A 192.0.2.10", lines)
        self.assertTrue(any(" IN RRSIG DNSKEY 13 2 300 20270706000000 20260722054827 12345 broken.example." in line for line in lines))

        cloned = importer.clone_records_for_lab(records, "broken.example.", "com.")
        cloned_lines = {record.to_zone_line() for record in cloned}
        self.assertIn("example.com. 300 IN DS 12345 13 2 abc123", cloned_lines)
        self.assertIn("www.example.com. 300 IN A 192.0.2.10", cloned_lines)

    def test_import_realcase_writes_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            grok = self._write_grok(root)
            out_dir = root / "out"
            result = importer.import_realcase(grok, backend="bind9", out_dir=out_dir)

            self.assertEqual(result.zone, "broken.example.")
            self.assertEqual(result.parent_zone, "example.")
            self.assertIn("DIGEST_INVALID", result.plan["codes"])
            self.assertTrue((out_dir / "before-records.zone").exists())
            self.assertTrue((out_dir / "lab-clone-before.zone").exists())
            self.assertTrue((out_dir / "repair-plan.json").exists())
            summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["zone"], "broken.example.")


if __name__ == "__main__":
    unittest.main()
