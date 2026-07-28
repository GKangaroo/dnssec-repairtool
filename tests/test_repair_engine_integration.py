import unittest

from tests.repair_case_helper import maybe_run_integration_demo


class TestRepairEngineIntegration(unittest.TestCase):
    def test_bind9_bad_ds_demo(self):
        maybe_run_integration_demo(self, "bind9", "bad-ds")

    def test_powerdns_bad_ds_demo(self):
        maybe_run_integration_demo(self, "powerdns", "bad-ds")

    def test_powerdns_dnskey_bad_length_gost_demo(self):
        maybe_run_integration_demo(self, "powerdns", "dnskey-bad-length-gost")


if __name__ == "__main__":
    unittest.main()
