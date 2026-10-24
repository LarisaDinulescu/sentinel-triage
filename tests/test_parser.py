
import json
import tempfile
import unittest
from pathlib import Path

from src.parser import load_alerts


def make_alert(**overrides):
    """Crea un alert valido da usare nei test."""
    alert = {
        "alert_id": "ALT-TEST-0001",
        "timestamp": "2026-10-24T09:15:00Z",
        "event_type": "failed_login",
        "severity": "medium",
        "source_ip": "192.0.2.25",
        "username": "user_demo",
        "hostname": "pc-demo-01",
        "description": "Synthetic test event",
        "source": "synthetic",
    }
    alert.update(overrides)
    return alert


class TestAlertParser(unittest.TestCase):

    def load_test_data(self, events):
        """Scrive gli eventi in un JSON temporaneo e li carica."""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "alerts.json"
            path.write_text(
                json.dumps(events),
                encoding="utf-8",
            )
            return load_alerts(path)

    def test_valid_alert_is_accepted(self):
        accepted, errors = self.load_test_data([make_alert()])

        self.assertEqual(len(accepted), 1)
        self.assertEqual(errors, [])

    def test_invalid_timestamp_is_rejected(self):
        alert = make_alert(timestamp="ieri mattina")

        accepted, errors = self.load_test_data([alert])

        self.assertEqual(len(accepted), 0)
        self.assertTrue(
            any("timestamp non valido" in error for error in errors)
        )

    def test_invalid_severity_is_rejected(self):
        alert = make_alert(severity="urgent")

        accepted, errors = self.load_test_data([alert])

        self.assertEqual(len(accepted), 0)
        self.assertTrue(
            any("severità non riconosciuta" in error for error in errors)
        )

    def test_missing_username_is_rejected(self):
        alert = make_alert()
        del alert["username"]

        accepted, errors = self.load_test_data([alert])

        self.assertEqual(len(accepted), 0)
        self.assertTrue(
            any("manca il campo username" in error for error in errors)
        )

    def test_valid_event_survives_malformed_event(self):
        valid = make_alert()
        invalid = make_alert(
            alert_id="ALT-TEST-0002",
            timestamp="data sbagliata",
        )

        accepted, errors = self.load_test_data([invalid, valid])

        self.assertEqual(len(accepted), 1)
        self.assertEqual(accepted[0]["alert_id"], "ALT-TEST-0001")
        self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
