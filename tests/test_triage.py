import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import unittest

from triage import assess_case


class TestTriage(unittest.TestCase):

    def make_case(
        self,
        rules,
        severities=None,
        missing=None,
    ):
        severities = severities or ["low"]
        missing = missing or []

        return {
            "case_id": "CASE-001",
            "rules_triggered": rules,
            "events": [
                {"severity": severity}
                for severity in severities
            ],
            "missing_information": missing,
        }

    def test_failed_then_successful_login_is_high(self):
        case = self.make_case(
            ["failed_then_successful_login"]
        )

        result = assess_case(case)

        self.assertEqual(result["priority"], "HIGH")
        self.assertEqual(result["scenario"], "Authentication")
        self.assertTrue(result["rationale"])
        self.assertTrue(result["items_to_verify"])
        self.assertTrue(result["recommended_actions"])

    def test_email_network_sequence_is_high(self):
        case = self.make_case(
            ["email_click_then_unusual_network"]
        )

        result = assess_case(case)

        self.assertEqual(result["priority"], "HIGH")
        self.assertEqual(result["scenario"], "Possible phishing")

    def test_high_severity_without_high_priority_rule_is_medium(self):
        case = self.make_case(
            ["deduplication"],
            severities=["high"],
        )

        result = assess_case(case)

        self.assertEqual(result["priority"], "MEDIUM")

    def test_low_severity_deduplication_is_low(self):
        case = self.make_case(["deduplication"])

        result = assess_case(case)

        self.assertEqual(result["priority"], "LOW")
        self.assertEqual(result["scenario"], "Repeated alerts")

    def test_missing_information_is_reported(self):
        case = self.make_case(
            ["failed_then_successful_login"],
            missing=["Indirizzo IP non disponibile"],
        )

        result = assess_case(case)

        self.assertEqual(result["priority"], "HIGH")
        self.assertIn(
            "Indirizzo IP non disponibile",
            result["items_to_verify"],
        )
        self.assertTrue(
            any("missing" in reason.lower()
                for reason in result["rationale"])
        )

    def test_every_result_has_explanation_and_action(self):
        case = self.make_case(["deduplication"])

        result = assess_case(case)

        self.assertIn(
            result["priority"],
            {"HIGH", "MEDIUM", "LOW"},
        )
        self.assertTrue(result["rationale"])
        self.assertTrue(result["items_to_verify"])
        self.assertTrue(result["recommended_actions"])


if __name__ == "__main__":
    unittest.main()
