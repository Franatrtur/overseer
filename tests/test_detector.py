"""
Unit tests for SyscallDetector logic.
"""

import unittest
from overseer.detector import SyscallDetector
from overseer.models import (
    FindingKind,
    Severity,
    SyscallCategory,
    SyscallEvent,
)


class TestSyscallDetector(unittest.TestCase):
    def setUp(self):
        self.detector = SyscallDetector(window_size=5, consecutive_only=False)

    def _make_event(self, seq, name, decoded_args=None, ret_val=0, ret_str="0", is_err=False, tid=1, idempotent=False):
        return SyscallEvent(
            sequence=seq,
            thread_id=tid,
            syscall_nr=1,
            name=name,
            args=[0, 0, 0],
            decoded_args=decoded_args or {},
            ret_val=ret_val,
            ret_str=ret_str,
            is_error=is_err,
            category=SyscallCategory.FILE_IO,
            is_idempotent=idempotent,
        )

    def test_consecutive_duplicate_flagging(self):
        e1 = self._make_event(1, "getpid", {}, ret_val=1000, ret_str="1000", idempotent=True)
        e2 = self._make_event(2, "getpid", {}, ret_val=1000, ret_str="1000", idempotent=True)

        f1 = self.detector.feed(e1)
        self.assertEqual(len(f1), 0)

        f2 = self.detector.feed(e2)
        self.assertEqual(len(f2), 1)
        self.assertEqual(f2[0].kind, FindingKind.CONSECUTIVE)
        self.assertEqual(f2[0].severity, Severity.WARNING)

    def test_consecutive_failing_calls(self):
        # Double close on fd 3
        e1 = self._make_event(1, "close", {"fd": 3}, ret_val=0, ret_str="0", is_err=False)
        e2 = self._make_event(2, "close", {"fd": 3}, ret_val=-9, ret_str="-9 (EBADF)", is_err=True)

        self.detector.feed(e1)
        f = self.detector.feed(e2)
        self.assertEqual(len(f), 1)
        self.assertIn(f[0].kind, (FindingKind.CONSECUTIVE, FindingKind.USE_AFTER_CLOSE))
        self.assertEqual(f[0].severity, Severity.ERROR)

    def test_windowed_duplicate(self):
        e1 = self._make_event(1, "stat", {"path": "/etc/hosts"}, idempotent=True)
        e2 = self._make_event(2, "getpid", {}, idempotent=True)
        e3 = self._make_event(3, "getuid", {}, idempotent=True)
        e4 = self._make_event(4, "stat", {"path": "/etc/hosts"}, idempotent=True)

        self.detector.feed(e1)
        self.detector.feed(e2)
        self.detector.feed(e3)
        f4 = self.detector.feed(e4)

        self.assertEqual(len(f4), 1)
        self.assertIn(f4[0].kind, (FindingKind.IDEMPOTENT_QUERY, FindingKind.STATEFUL_REDUNDANT_QUERY))
        self.assertEqual(f4[0].severity, Severity.WARNING)

    def test_consecutive_only_mode(self):
        detector = SyscallDetector(consecutive_only=True)
        e1 = self._make_event(1, "stat", {"path": "/etc/hosts"}, idempotent=True)
        e2 = self._make_event(2, "getpid", {}, idempotent=True)
        e3 = self._make_event(3, "stat", {"path": "/etc/hosts"}, idempotent=True)

        detector.feed(e1)
        detector.feed(e2)
        f3 = detector.feed(e3)
        self.assertEqual(len(f3), 0)

    def test_thread_isolation(self):
        # Event on thread 1
        e1 = self._make_event(1, "getpid", {}, tid=1, idempotent=True)
        # Event on thread 2
        e2 = self._make_event(2, "getpid", {}, tid=2, idempotent=True)

        f1 = self.detector.feed(e1)
        f2 = self.detector.feed(e2)

        # Thread 2 should not be flagged as consecutive duplicate of thread 1
        self.assertEqual(len(f1), 0)
        self.assertEqual(len(f2), 0)


if __name__ == "__main__":
    unittest.main()
