"""
Unit tests for stateful resource invalidation tracking.
Verifies that:
- fstat -> fstat is flagged as wasteful, but fstat -> write -> fstat is not.
- lseek -> lseek is flagged as wasteful, but lseek -> read -> lseek is not.
- stat -> stat is flagged as wasteful, but stat -> unlink/truncate -> stat is not.
- Double close is flagged as use-after-close error.
"""

import unittest
from overseer.detector import SyscallDetector
from overseer.models import FindingKind, Severity, SyscallCategory, SyscallEvent


class TestStatefulDetector(unittest.TestCase):
    def setUp(self):
        self.detector = SyscallDetector(window_size=15, consecutive_only=False)

    def _make_event(
        self,
        seq: int,
        name: str,
        decoded_args=None,
        ret_val: int = 0,
        ret_str: str = "0",
        is_err: bool = False,
        tid: int = 1,
    ) -> SyscallEvent:
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
        )

    def test_fstat_redundant_vs_fstat_write_fstat_justified(self):
        # 1. Open fd 3
        e_open = self._make_event(1, "openat", {"dirfd": "AT_FDCWD", "path": "/tmp/test.txt"}, ret_val=3)
        self.detector.feed(e_open)

        # 2. First fstat(3)
        e_stat1 = self._make_event(2, "fstat", {"fd": 3})
        findings1 = self.detector.feed(e_stat1)
        self.assertEqual(len(findings1), 0)

        # 3. Second fstat(3) without mutation -> wasteful!
        e_stat2 = self._make_event(3, "fstat", {"fd": 3})
        findings2 = self.detector.feed(e_stat2)
        self.assertEqual(len(findings2), 1)
        self.assertEqual(findings2[0].kind, FindingKind.STATEFUL_REDUNDANT_QUERY)
        self.assertEqual(findings2[0].severity, Severity.WARNING)

        # 4. Write to fd 3 -> state mutated!
        e_write = self._make_event(4, "write", {"fd": 3, "count": 10}, ret_val=10)
        self.detector.feed(e_write)

        # 5. Third fstat(3) -> state was mutated, so this query is justified!
        e_stat3 = self._make_event(5, "fstat", {"fd": 3})
        findings3 = self.detector.feed(e_stat3)
        # Should NOT be flagged as redundant because dirty_generation > last_stat_generation
        self.assertEqual(len(findings3), 0)

    def test_lseek_redundant_vs_lseek_read_lseek_justified(self):
        # Open fd 4
        self.detector.feed(self._make_event(1, "open", {"path": "/tmp/data"}, ret_val=4))

        # 1. Seek to 0
        e_seek1 = self._make_event(2, "lseek", {"fd": 4, "offset": 0, "whence": "SEEK_SET"}, ret_val=0)
        f1 = self.detector.feed(e_seek1)
        self.assertEqual(len(f1), 0)

        # 2. Seek to 0 again without reading/writing -> wasteful!
        e_seek2 = self._make_event(3, "lseek", {"fd": 4, "offset": 0, "whence": "SEEK_SET"}, ret_val=0)
        f2 = self.detector.feed(e_seek2)
        self.assertEqual(len(f2), 1)
        self.assertEqual(f2[0].kind, FindingKind.STATEFUL_REDUNDANT_SEEK)

        # 3. Read 50 bytes -> offset moves to 50
        e_read = self._make_event(4, "read", {"fd": 4, "count": 50}, ret_val=50)
        self.detector.feed(e_read)

        # 4. Seek back to 0 -> offset changed, so this seek is justified!
        e_seek3 = self._make_event(5, "lseek", {"fd": 4, "offset": 0, "whence": "SEEK_SET"}, ret_val=0)
        f3 = self.detector.feed(e_seek3)
        self.assertEqual(len(f3), 0)

    def test_stat_path_mutation(self):
        # 1. stat /tmp/config.json
        e_stat1 = self._make_event(1, "stat", {"path": "/tmp/config.json"})
        self.assertEqual(len(self.detector.feed(e_stat1)), 0)

        # 2. stat /tmp/config.json again without mutation -> wasteful!
        e_stat2 = self._make_event(2, "stat", {"path": "/tmp/config.json"})
        f2 = self.detector.feed(e_stat2)
        self.assertEqual(len(f2), 1)
        self.assertEqual(f2[0].kind, FindingKind.STATEFUL_REDUNDANT_QUERY)

        # 3. Truncate path -> state modified
        e_trunc = self._make_event(3, "truncate", {"path": "/tmp/config.json", "length": 0})
        self.detector.feed(e_trunc)

        # 4. stat /tmp/config.json -> justified!
        e_stat3 = self._make_event(4, "stat", {"path": "/tmp/config.json"})
        f3 = self.detector.feed(e_stat3)
        self.assertEqual(len(f3), 0)

    def test_double_close_flagged(self):
        # Open fd 5
        self.detector.feed(self._make_event(1, "open", {"path": "/tmp/foo"}, ret_val=5))

        # Close fd 5
        e_c1 = self._make_event(2, "close", {"fd": 5}, ret_val=0)
        f1 = self.detector.feed(e_c1)
        self.assertEqual(len(f1), 0)

        # Close fd 5 again -> double close error!
        e_c2 = self._make_event(3, "close", {"fd": 5}, ret_val=-9, ret_str="-9 (EBADF)", is_err=True)
        f2 = self.detector.feed(e_c2)
        self.assertEqual(len(f2), 1)
        self.assertEqual(f2[0].kind, FindingKind.USE_AFTER_CLOSE)
        self.assertEqual(f2[0].severity, Severity.ERROR)


if __name__ == "__main__":
    unittest.main()
