"""
Integration tests executing compiled test programs via GDBConnector.
"""

import json
import os
import tempfile
import unittest
from overseer.connector import GDBConnector


class TestGDBIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.connector = GDBConnector()
        cls.test_dir = os.path.join(os.path.dirname(__file__), "test_programs")

    def test_consecutive_dup_integration(self):
        bin_path = os.path.join(self.test_dir, "consecutive_dup")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            json_path = tf.name

        try:
            config = {
                "start_at": "main",
                "json_path": json_path,
                "quiet": True,
            }
            ret = self.connector.run_target(bin_path, config=config)
            self.assertEqual(ret, 0)

            with open(json_path, "r") as f:
                data = json.load(f)

            self.assertGreaterEqual(data["total_syscalls"], 5)
            self.assertGreaterEqual(data["findings_count"], 3)

            # Check that getpid and close were flagged
            kinds = [f["current_event"]["name"] for f in data["findings"]]
            self.assertIn("getpid", kinds)
            self.assertIn("close", kinds)

            # Check double close error was caught
            close_findings = [f for f in data["findings"] if f["current_event"]["name"] == "close"]
            self.assertTrue(any(f["severity"] == "error" for f in close_findings))

        finally:
            if os.path.exists(json_path):
                os.remove(json_path)

    def test_windowed_dup_integration(self):
        bin_path = os.path.join(self.test_dir, "windowed_dup")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            json_path = tf.name

        try:
            config = {
                "start_at": "main",
                "window_size": 10,
                "json_path": json_path,
                "quiet": True,
            }
            ret = self.connector.run_target(bin_path, config=config)
            self.assertEqual(ret, 0)

            with open(json_path, "r") as f:
                data = json.load(f)

            self.assertGreaterEqual(data["findings_count"], 1)
            f = data["findings"][0]
            self.assertEqual(f["kind"], "idempotent_query")
            self.assertIn("hosts", f["current_event"]["decoded_args"].get("path", ""))

        finally:
            if os.path.exists(json_path):
                os.remove(json_path)

    def test_failing_dup_integration(self):
        bin_path = os.path.join(self.test_dir, "failing_dup")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            json_path = tf.name

        try:
            config = {
                "start_at": "main",
                "json_path": json_path,
                "quiet": True,
            }
            ret = self.connector.run_target(bin_path, config=config)
            self.assertEqual(ret, 0)

            with open(json_path, "r") as f:
                data = json.load(f)

            self.assertEqual(data["findings_count"], 3)
            for f in data["findings"]:
                self.assertEqual(f["severity"], "error")
                self.assertEqual(f["current_event"]["errno_name"], "ENOENT")

        finally:
            if os.path.exists(json_path):
                os.remove(json_path)

    def test_ttyname_ioctl_duplicate(self):
        """
        Reproduce two identical ioctl(0, TCGETS) syscalls when the only
        content of main is calling ttyname(0) in a pseudo-terminal.
        """
        bin_path = os.path.join(self.test_dir, "ttyname_dup")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            json_path = tf.name

        try:
            config = {
                "start_at": "main",
                "json_path": json_path,
                "quiet": True,
                "pty": True,
                "window_size": 15,
            }
            ret = self.connector.run_target(bin_path, config=config)
            self.assertEqual(ret, 0)

            with open(json_path, "r") as f:
                data = json.load(f)

            ioctl_findings = [
                f for f in data["findings"]
                if f["current_event"]["name"] == "ioctl"
            ]
            self.assertEqual(len(ioctl_findings), 1)

            finding = ioctl_findings[0]
            self.assertEqual(finding["kind"], "windowed")
            self.assertEqual(finding["current_event"]["decoded_args"].get("request"), "TCGETS")
            self.assertEqual(finding["current_event"]["decoded_args"].get("fd"), 0)
            self.assertEqual(finding["previous_event"]["decoded_args"].get("request"), "TCGETS")
            self.assertEqual(finding["previous_event"]["decoded_args"].get("fd"), 0)
            self.assertEqual(data["duplicate_counts"].get("ioctl"), 1)

        finally:
            if os.path.exists(json_path):
                os.remove(json_path)


if __name__ == "__main__":
    unittest.main()
