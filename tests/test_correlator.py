
import unittest

from src.correlator import correlate_alerts


def make_alert(
    alert_id,
    timestamp,
    event_type="test_event",
    username="alice",
    source_ip="192.0.2.10",
    hostname="pc-01",
    description="Test event",
    severity="low",
):
    return {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip,
        "username": username,
        "hostname": hostname,
        "description": description,
        "source": "test",
    }


class TestAlertCorrelator(unittest.TestCase):


    
    
    def test_repeated_login_failures_are_not_deduplicated(self):
        from src.correlator import _deduplicate

        alerts = [
            make_alert(
                "ALT-001",
                "2026-10-24T08:00:00Z",
                event_type="failed_login",
            ),
            make_alert(
                "ALT-002",
                "2026-10-24T08:01:00Z",
                event_type="failed_login",
            ),
            make_alert(
                "ALT-003",
                "2026-10-24T08:02:00Z",
                event_type="failed_login",
            ),
        ]

        candidates = _deduplicate(alerts)
        self.assertEqual(candidates, [])




    def test_duplicate_alerts_are_grouped(self):
        alerts = [
            make_alert("ALT-001", "2026-10-24T08:00:00Z"),
            make_alert("ALT-002", "2026-10-24T08:01:00Z"),
        ]

        report = correlate_alerts(alerts)

        self.assertEqual(len(report["cases"]), 1)
        self.assertEqual(
            set(report["cases"][0]["event_ids"]),
            {"ALT-001", "ALT-002"},
        )
        self.assertEqual(report["unmatched_alerts"], [])


    def test_similar_alerts_outside_dedup_window_are_not_grouped(self):
        alerts = [
            make_alert("ALT-001", "2026-10-24T08:00:00Z"),
            make_alert("ALT-002", "2026-10-24T08:03:00Z"),
        ]

        report = correlate_alerts(alerts)

        self.assertEqual(len(report["cases"]), 0)
        self.assertEqual(
            {a["alert_id"] for a in report["unmatched_alerts"]},
            {"ALT-001", "ALT-002"},
        )


    def test_unrelated_alert_remains_unmatched(self):
        alerts = [
            make_alert("ALT-001", "2026-10-24T08:00:00Z"),
            make_alert(
                "ALT-002",
                "2026-10-24T08:01:00Z",
                event_type="routine_login",
            ),
        ]

        report = correlate_alerts(alerts)

        self.assertEqual(len(report["cases"]), 0)
        self.assertEqual(
            [a["alert_id"] for a in report["unmatched_alerts"]],
            ["ALT-001", "ALT-002"],
        )

    def test_failed_login_followed_by_success_is_correlated(self):
        alerts = [
            make_alert(
                "ALT-001",
                "2026-10-24T08:00:00Z",
                event_type="failed_login",
            ),
            make_alert(
                "ALT-002",
                "2026-10-24T08:05:00Z",
                event_type="successful_login",
            ),
        ]

        report = correlate_alerts(alerts)

        self.assertEqual(len(report["cases"]), 1)
        self.assertIn(
            "failed_then_successful_login",
            report["cases"][0]["rules_triggered"],
        )
        self.assertEqual(report["unmatched_alerts"], [])

    def test_same_event_is_not_in_multiple_cases(self):
        alerts = [
            make_alert(
                "ALT-001",
                "2026-10-24T08:00:00Z",
                event_type="failed_login",
            ),
            make_alert(
                "ALT-002",
                "2026-10-24T08:01:00Z",
                event_type="failed_login",
            ),
            make_alert(
                "ALT-003",
                "2026-10-24T08:02:00Z",
                event_type="successful_login",
            ),
        ]

        report = correlate_alerts(alerts)
        all_ids = [
            event_id
            for case in report["cases"]
            for event_id in case["event_ids"]
        ]

        self.assertEqual(len(all_ids), len(set(all_ids)))

    def test_repeated_failed_logins_for_same_user_are_correlated(self):
        alerts = [
            make_alert(
                f"ALT-{i:03d}",
                f"2026-10-24T08:{i:02d}:00Z",
                event_type="failed_login",
            )
            for i in range(5)
        ]

        report = correlate_alerts(alerts)

        matching_cases = [
            case for case in report["cases"]
            if "repeated_failed_logins" in case["rules_triggered"]
        ]

        self.assertEqual(len(matching_cases), 1)
        self.assertEqual(len(matching_cases[0]["event_ids"]), 5)
        self.assertEqual(report["unmatched_alerts"], [])

    def test_password_spraying_is_correlated(self):
        alerts = [
            make_alert(
                f"ALT-{i:03d}",
                f"2026-10-24T08:{i:02d}:00Z",
                event_type="failed_login",
                username=f"user{i}",
            )
            for i in range(5)
        ]

        report = correlate_alerts(alerts)

        matching_cases = [
            case for case in report["cases"]
            if "repeated_failed_logins" in case["rules_triggered"]
        ]

        self.assertEqual(len(matching_cases), 1)
        self.assertEqual(len(matching_cases[0]["event_ids"]), 5)
        self.assertEqual(report["unmatched_alerts"], [])

    def test_independent_alert_groups_remain_separate(self):
        alerts = [
            make_alert(
                "ALT-001",
                "2026-10-24T08:00:00Z",
                source_ip="192.0.2.10",
            ),
            make_alert(
                "ALT-002",
                "2026-10-24T08:01:00Z",
                source_ip="192.0.2.10",
            ),
            make_alert(
                "ALT-003",
                "2026-10-24T08:10:00Z",
                source_ip="192.0.2.20",
            ),
            make_alert(
                "ALT-004",
                "2026-10-24T08:11:00Z",
                source_ip="192.0.2.20",
            ),
        ]

        report = correlate_alerts(alerts)

        self.assertEqual(len(report["cases"]), 2)
        self.assertEqual(
            {
                frozenset(case["event_ids"])
                for case in report["cases"]
            },
            {
                frozenset({"ALT-001", "ALT-002"}),
                frozenset({"ALT-003", "ALT-004"}),
            },
        )

    def test_four_failed_logins_do_not_trigger_burst_rule(self):
        alerts = [
            make_alert(
                f"ALT-{i:03d}",
                f"2026-10-24T08:0{i}:00Z",
                event_type="failed_login",
            )
            for i in range(4)
        ]

        report = correlate_alerts(alerts)

        self.assertFalse(
            any(
                "repeated_failed_logins" in case["rules_triggered"]
                for case in report["cases"]
            )
        )

    def test_failed_logins_outside_window_do_not_trigger_burst_rule(self):
        minutes = [0, 3, 6, 9, 12]
        alerts = [
            make_alert(
                f"ALT-{i:03d}",
                f"2026-10-24T08:{minute:02d}:00Z",
                event_type="failed_login",
            )
            for i, minute in enumerate(minutes)
        ]

        report = correlate_alerts(alerts)

        self.assertFalse(
            any(
                "repeated_failed_logins" in case["rules_triggered"]
                for case in report["cases"]
            )
        )

if __name__ == "__main__":
    unittest.main()
