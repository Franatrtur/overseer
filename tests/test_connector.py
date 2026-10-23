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
            self.assertIn(f["kind"], ("idempotent_query", "stateful_redundant_query"))
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


    def test_stateful_resource_tracking_integration(self):
        """
        Verify end-to-end GDB execution of stateful resource invalidation:
        - fstat -> fstat (wasteful, flagged)
        - fstat -> write -> fstat (justified, NOT flagged)
        - lseek -> lseek (wasteful, flagged)
        - lseek -> read -> lseek (justified, NOT flagged)
        - double close (error, flagged)
        """
        bin_path = os.path.join(self.test_dir, "stateful_io")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            json_path = tf.name

        try:
            config = {
                "start_at": "main",
                "json_path": json_path,
                "quiet": True,
                "window_size": 15,
            }
            ret = self.connector.run_target(bin_path, config=config)
            self.assertEqual(ret, 0)

            with open(json_path, "r") as f:
                data = json.load(f)

            findings = data["findings"]
            self.assertEqual(len(findings), 3)

            # Check 1: Redundant fstat
            fstat_f = [f for f in findings if f["current_event"]["name"] == "fstat"]
            self.assertEqual(len(fstat_f), 1)
            self.assertEqual(fstat_f[0]["kind"], "stateful_redundant_query")
            self.assertEqual(fstat_f[0]["severity"], "warning")

            # Check 2: Redundant lseek
            lseek_f = [f for f in findings if f["current_event"]["name"] == "lseek"]
            self.assertEqual(len(lseek_f), 1)
            self.assertEqual(lseek_f[0]["kind"], "stateful_redundant_seek")
            self.assertEqual(lseek_f[0]["severity"], "warning")

            # Check 3: Double close
            close_f = [f for f in findings if f["current_event"]["name"] == "close"]
            self.assertEqual(len(close_f), 1)
            self.assertEqual(close_f[0]["kind"], "use_after_close")
            self.assertEqual(close_f[0]["severity"], "error")

        finally:
            if os.path.exists(json_path):
                os.remove(json_path)

    def test_suspicious_mmap_dump_integration(self):
        """
        Verify end-to-end detection of suspicious executable memory mappings
        and verify that the memory region containing shellcode is dumped to disk.
        """
        bin_path = os.path.join(self.test_dir, "suspicious_mmap")
        with tempfile.TemporaryDirectory() as dump_tmp:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
                json_path = tf.name

            try:
                config = {
                    "start_at": "main",
                    "json_path": json_path,
                    "quiet": True,
                    "dump_dir": dump_tmp,
                    "dump_executable_memory": True,
                }
                ret = self.connector.run_target(bin_path, config=config)
                self.assertEqual(ret, 0)

                with open(json_path, "r") as f:
                    data = json.load(f)

                sec_findings = [f for f in data["findings"] if f["kind"] == "malicious_executable_memory"]
                self.assertGreaterEqual(len(sec_findings), 2)

                # Check that dump files were created in dump_tmp
                dump_files = [f for f in os.listdir(dump_tmp) if f.endswith(".bin")]
                self.assertGreaterEqual(len(dump_files), 1)

                # Verify dumped memory contains the shellcode signature
                found_sig = False
                for df in dump_files:
                    with open(os.path.join(dump_tmp, df), "rb") as dump_f:
                        content = dump_f.read()
                        if b"OVERSEER_SHELLCODE_SIGNATURE" in content:
                            found_sig = True
                            break
                self.assertTrue(found_sig, "Shellcode signature not found in dumped memory files")

            finally:
                if os.path.exists(json_path):
                    os.remove(json_path)

    def test_antidebug_ptrace_neutralization_integration(self):
        """
        Verify that ptrace(PTRACE_TRACEME) anti-debugging check is detected
        and actively neutralized (spoofed to 0), allowing inferior to exit with 0.
        """
        bin_path = os.path.join(self.test_dir, "antidebug_ptrace")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            json_path = tf.name

        try:
            config = {
                "start_at": "main",
                "json_path": json_path,
                "quiet": True,
                "neutralize_anti_debug": True,
            }
            # Target returns 42 if ptrace fails; returns 0 if ptrace succeeds (neutralized)
            ret = self.connector.run_target(bin_path, config=config)
            self.assertEqual(ret, 0)

            with open(json_path, "r") as f:
                data = json.load(f)

            ptrace_findings = [f for f in data["findings"] if f["kind"] == "malicious_anti_debug"]
            self.assertEqual(len(ptrace_findings), 1)
            pf = ptrace_findings[0]
            self.assertEqual(pf["severity"], "critical")
            self.assertTrue(pf["details"].get("neutralized"))
            self.assertEqual(pf["current_event"]["ret_val"], 0)

        finally:
            if os.path.exists(json_path):
                os.remove(json_path)


if __name__ == "__main__":
    unittest.main()
