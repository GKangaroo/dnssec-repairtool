import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import controlled_zone_repair as controlled


def write_minimal_grok(path: Path) -> None:
    data = {
        "com.": {"zone": {"status": "SECURE"}},
        "example.com.": {
            "zone": {"status": "INVALID", "servers": {"ns.example.com.": {"auth": ["127.10.0.3"]}}},
            "delegation": {
                "errors": [{"code": "NO_SEP"}],
                "ds": [
                    {
                        "id": "13/12345/2",
                        "key_tag": 12345,
                        "algorithm": 13,
                        "digest_type": 2,
                        "status": "INVALID_DIGEST",
                        "errors": [{"code": "DIGEST_INVALID"}],
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
    path.write_text(json.dumps(data), encoding="utf-8")


class TestControlledZoneRepair(unittest.TestCase):
    def test_bind9_controlled_repair_wiring(self):
        with tempfile.TemporaryDirectory() as tmp:
            grok = Path(tmp) / "grok.json"
            write_minimal_grok(grok)
            adapter = mock.Mock()
            adapter.actions = ["replace parent DS", "resign zones", "restart bind9"]
            adapter.execute_plan.return_value = mock.Mock(actions=tuple(adapter.actions[:2]))
            with mock.patch("zone_backend_adapter.adapter_for_backend", return_value=adapter) as adapter_factory:
                result = controlled.repair_lab_from_grok("bind9", grok)

        self.assertEqual(result.backend, "bind9")
        self.assertEqual(result.zone, "example.com.")
        self.assertEqual(result.parent_zone, "com.")
        self.assertEqual(result.codes, ("NO_SEP", "DIGEST_INVALID"))
        self.assertFalse(result.rotate_keys)
        adapter_factory.assert_called_once_with("bind9", rotate_keys=False)
        adapter.execute_plan.assert_called_once()
        adapter.refresh.assert_called_once()
        self.assertEqual(result.actions, tuple(adapter.actions))

    def test_powerdns_controlled_repair_wiring_rotate_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            grok = Path(tmp) / "grok.json"
            write_minimal_grok(grok)
            adapter = mock.Mock()
            adapter.actions = ["rotate keys", "replace parent DS", "refresh powerdns"]
            adapter.execute_plan.return_value = mock.Mock(actions=tuple(adapter.actions[:2]))
            with mock.patch("zone_backend_adapter.adapter_for_backend", return_value=adapter) as adapter_factory:
                result = controlled.repair_lab_from_grok("powerdns", grok, rotate_keys=True)

        self.assertEqual(result.backend, "powerdns")
        self.assertTrue(result.rotate_keys)
        adapter_factory.assert_called_once_with("powerdns", rotate_keys=True)
        adapter.execute_plan.assert_called_once()
        adapter.refresh.assert_called_once()


if __name__ == "__main__":
    unittest.main()
