import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from dnssec_scenarios import get as get_scenario

import dnssec_repair_engine as repair


ROOT = Path(__file__).resolve().parents[1]


def check_planner_for_scenario(testcase: unittest.TestCase, scenario: str) -> None:
    config = get_scenario(scenario)
    testcase.assertIsNotNone(config, scenario)

    for backend in ("bind9", "powerdns"):
        plan = repair.plan_scenario(backend, scenario)
        testcase.assertEqual(plan.backend, backend)
        testcase.assertEqual(plan.scenario, scenario)
        testcase.assertEqual(set(plan.codes), set(config.expected_codes))
        testcase.assertEqual(len(plan.instructions), len(config.expected_codes))
        for instruction in plan.instructions:
            testcase.assertEqual(instruction.backend, backend)
            testcase.assertEqual(instruction.scenario, scenario)
            testcase.assertIn(instruction.code, config.expected_codes)
            testcase.assertTrue(instruction.family)
            testcase.assertTrue(instruction.action)
            testcase.assertTrue(instruction.demo_action)


def check_executor_wiring_for_scenario(testcase: unittest.TestCase, scenario: str) -> None:
    with mock.patch("dnssec_lab.apply_scenario_fix") as bind_fix:
        repair.execute_scenario_repair("bind9", scenario)
        bind_fix.assert_called_once_with(scenario)

    with mock.patch("powerdns_lab.apply_scenario_fix") as pdns_fix:
        repair.execute_scenario_repair("powerdns", scenario)
        pdns_fix.assert_called_once_with(scenario)


def maybe_run_integration_demo(testcase: unittest.TestCase, backend: str, scenario: str, timeout: int = 160) -> None:
    env_name = "DNSSEC_REPAIR_RUN_INTEGRATION"
    if os.environ.get(env_name) != "1":
        testcase.skipTest(f"set {env_name}=1 to run DNS service integration tests")

    script = "dnssec_lab.py" if backend == "bind9" else "powerdns_lab.py"
    proc = subprocess.run(
        [sys.executable, script, "demo", scenario],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        check=False,
    )
    testcase.assertEqual(proc.returncode, 0, proc.stdout)
    testcase.assertIn('"instructions"', proc.stdout)
    testcase.assertIn("DNSViz error codes: <none>", proc.stdout)
