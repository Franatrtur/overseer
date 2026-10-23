"""
Unit tests for the SecurityEngine:
Verifies malicious signature detection, active memory dumping,
and anti-debugging neutralization.
"""

import os
import tempfile
import unittest
from unittest.mock import MagicMock

from overseer.arch import ARCH_SPECS
from overseer.detector import SyscallDetector
from overseer.models import DuplicateFinding, FindingKind, Severity, SyscallCategory, SyscallEvent
from overseer.security import SecurityEngine


class TestSecurityEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.engine = SecurityEngine(
            enabled=True,
            dump_executable_memory=True,
            dump_dir=self.temp_dir.name,
            neutralize_anti_debug=True,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def _make_event(
        self,
        seq: int,
        name: str,
        raw_args=None,
        decoded_args=None,
        ret_val: int = 0,
        ret_str: str = "0",
    ) -> SyscallEvent:
        return SyscallEvent(
            sequence=seq,
            thread_id=1,
            syscall_nr=1,
            name=name,
            args=raw_args or [0, 0, 0, 0],
            decoded_args=decoded_args or {},
            ret_val=ret_val,
            ret_str=ret_str,
            is_error=ret_val < 0,
            category=SyscallCategory.MEMORY,
        )

    def test_suspicious_mmap_rwx_flagged(self):
        # mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
        # prot = 1 | 2 | 4 = 7
        # flags = 0x2 | 0x20 = 0x22
        e = self._make_event(
            1,
            "mmap",
            raw_args=[0, 4096, 7, 0x22, -1, 0],
            decoded_args={
                "addr": "0x0",
                "length": 4096,
                "prot": "PROT_READ|PROT_WRITE|PROT_EXEC",
                "flags": "MAP_PRIVATE|MAP_ANONYMOUS",
            },
            ret_val=0x7FFF0000,
        )
        findings = self.engine.analyze_event(e)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, FindingKind.MALICIOUS_EXECUTABLE_MEMORY)
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertIn("W^X", f.message)
        self.assertTrue(f.details.get("dump_requested"))
        self.assertEqual(f.details.get("memory_addr"), 0x7FFF0000)

    def test_suspicious_mmap_anonymous_exec(self):
        # mmap(0, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
        # prot = 1 | 4 = 5
        # flags = 0x2 | 0x20 = 0x22
        e = self._make_event(
            1,
            "mmap",
            raw_args=[0, 4096, 5, 0x22, -1, 0],
            decoded_args={
                "length": 4096,
                "prot": "PROT_READ|PROT_EXEC",
                "flags": "MAP_PRIVATE|MAP_ANONYMOUS",
            },
            ret_val=0x7FFF1000,
        )
        findings = self.engine.analyze_event(e)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, FindingKind.MALICIOUS_EXECUTABLE_MEMORY)
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertIn("anonymous executable", f.message)

    def test_mprotect_exec_flagged(self):
        # mprotect(0x7FFF2000, 4096, PROT_READ|PROT_EXEC)
        e = self._make_event(
            2,
            "mprotect",
            raw_args=[0x7FFF2000, 4096, 5],
            decoded_args={"addr": "0x7FFF2000", "length": 4096, "prot": "PROT_READ|PROT_EXEC"},
            ret_val=0,
        )
        findings = self.engine.analyze_event(e)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, FindingKind.MALICIOUS_EXECUTABLE_MEMORY)
        self.assertEqual(f.severity, Severity.WARNING)
        self.assertTrue(f.details.get("dump_requested"))
        self.assertEqual(f.details.get("memory_addr"), 0x7FFF2000)

    def test_mprotect_rwx_flagged_critical(self):
        # mprotect(0x7FFF2000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC)
        e = self._make_event(
            2,
            "mprotect",
            raw_args=[0x7FFF2000, 4096, 7],
            decoded_args={"addr": "0x7FFF2000", "length": 4096, "prot": "PROT_READ|PROT_WRITE|PROT_EXEC"},
            ret_val=0,
        )
        findings = self.engine.analyze_event(e)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, FindingKind.MALICIOUS_EXECUTABLE_MEMORY)
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertIn("W^X violation", f.message)

    def test_anti_debug_ptrace_traceme(self):
        # ptrace(PTRACE_TRACEME, 0, 1, 0)
        e = self._make_event(
            3,
            "ptrace",
            raw_args=[0, 0, 1, 0],
            decoded_args={"request": "PTRACE_TRACEME", "pid": 0},
            ret_val=-1,
            ret_str="-1 (EPERM)",
        )
        findings = self.engine.analyze_event(e)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, FindingKind.MALICIOUS_ANTI_DEBUG)
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertTrue(f.details.get("anti_debug"))
        self.assertTrue(f.details.get("should_neutralize"))

    def test_anti_debug_prctl_dumpable(self):
        # prctl(PR_SET_DUMPABLE, 0)
        e = self._make_event(
            4,
            "prctl",
            raw_args=[3, 0, 0, 0],
            decoded_args={"option": "PR_SET_DUMPABLE", "arg2": "0x0"},
            ret_val=0,
        )
        findings = self.engine.analyze_event(e)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, FindingKind.MALICIOUS_ANTI_DEBUG)
        self.assertEqual(f.severity, Severity.WARNING)
        self.assertTrue(f.details.get("should_neutralize"))

    def test_fileless_memfd_create(self):
        e = self._make_event(
            5,
            "memfd_create",
            raw_args=[0x1234, 1],
            decoded_args={"name": "payload.elf", "flags": "0x1"},
            ret_val=3,
        )
        findings = self.engine.analyze_event(e)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, FindingKind.MALICIOUS_FILELESS_EXEC)
        self.assertEqual(f.severity, Severity.WARNING)

    def test_tampering_proc_self_mem(self):
        e = self._make_event(
            6,
            "openat",
            raw_args=[-100, 0x1234, 2],
            decoded_args={"path": "/proc/self/mem", "flags": "O_RDWR"},
            ret_val=4,
        )
        findings = self.engine.analyze_event(e)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, FindingKind.MALICIOUS_TAMPERING)
        self.assertEqual(f.severity, Severity.CRITICAL)

    def test_tampering_self_unlink(self):
        e = self._make_event(
            7,
            "unlink",
            raw_args=[0x1234],
            decoded_args={"path": "/proc/self/exe"},
            ret_val=0,
        )
        findings = self.engine.analyze_event(e)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, FindingKind.MALICIOUS_TAMPERING)
        self.assertEqual(f.severity, Severity.CRITICAL)

    def test_memory_dumping_to_disk(self):
        # Mock inferior with read_memory
        mock_inf = MagicMock()
        mock_inf.read_memory.return_value = b"\x90\x90\x90\xcc\xc3payload"

        e = self._make_event(10, "mmap", ret_val=0x400000)
        dump_path = self.engine.dump_memory(mock_inf, 0x400000, 10, e)

        self.assertIsNotNone(dump_path)
        self.assertTrue(os.path.exists(dump_path))
        with open(dump_path, "rb") as f:
            data = f.read()
        self.assertEqual(data, b"\x90\x90\x90\xcc\xc3payload")

    def test_anti_debug_neutralization_spoofs_register(self):
        mock_gdb = MagicMock()
        mock_arch = ARCH_SPECS["x86_64"]

        e = self._make_event(11, "ptrace", ret_val=-1, ret_str="-1 (EPERM)")
        finding = DuplicateFinding(
            kind=FindingKind.MALICIOUS_ANTI_DEBUG,
            severity=Severity.CRITICAL,
            message="Anti-debugging evasion",
            current_event=e,
            previous_event=e,
            details={"should_neutralize": True, "neutralize_reg_val": 0},
        )

        ok = self.engine.neutralize_syscall(mock_gdb, mock_arch, e, finding)
        self.assertTrue(ok)
        mock_gdb.execute.assert_called_once_with("set $rax = 0")
        self.assertEqual(e.ret_val, 0)
        self.assertEqual(e.ret_str, "0 (NEUTRALIZED)")
        self.assertFalse(e.is_error)
        self.assertTrue(finding.details.get("neutralized"))


if __name__ == "__main__":
    unittest.main()
