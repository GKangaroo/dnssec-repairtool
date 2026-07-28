import unittest
from pathlib import Path
from unittest import mock

import dnssec_repair_engine as repair
import iterative_controlled_repair as iterative


class TestIterativeControlledRepair(unittest.TestCase):
    def test_topological_pick_prefers_root_cause_over_dependent_code(self):
        code = repair.pick_topological_code(("NO_SEP", "DIGEST_INVALID"))
        self.assertEqual(code, "DIGEST_INVALID")

    def test_iterative_loop_converges_after_one_repair(self):
        fake_before = Path("before.grok.json")
        fake_after = Path("after.grok.json")

        with (
            mock.patch("iterative_controlled_repair.run_diagnose", side_effect=[fake_before, fake_after]) as diagnose,
            mock.patch("iterative_controlled_repair.current_codes", side_effect=[("NO_SEP", "DIGEST_INVALID"), ()]),
            mock.patch("iterative_controlled_repair.execute_one_topological_repair") as execute,
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
                ),
            )
            repair_result = mock.Mock(actions=("repair parent DS",))
            execute.return_value = (plan, repair_result)

            result = iterative.iterative_repair("powerdns", max_iterations=3, prefix="unit")

        self.assertTrue(result.converged)
        self.assertEqual(result.final_codes, ())
        self.assertEqual(len(result.iterations), 1)
        self.assertEqual(result.iterations[0].selected_code, "DIGEST_INVALID")
        self.assertEqual(result.iterations[0].repair_family, "ds_rrset_repair")
        self.assertEqual(diagnose.call_count, 2)


if __name__ == "__main__":
    unittest.main()
