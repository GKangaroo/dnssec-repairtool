import unittest

from tests.repair_case_helper import check_executor_wiring_for_scenario
from tests.repair_case_helper import check_planner_for_scenario


SCENARIO = "nonzero-nsec3-iteration-count"


class TestRepairCaseNonzeroNsec3IterationCount(unittest.TestCase):
    def test_planner(self):
        check_planner_for_scenario(self, SCENARIO)

    def test_executor_wiring(self):
        check_executor_wiring_for_scenario(self, SCENARIO)


if __name__ == "__main__":
    unittest.main()
