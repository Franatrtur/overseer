"""
Unit tests for SyscallDatabase and architecture specifications.
"""

import unittest
from overseer.arch import detect_arch, ARCH_SPECS
from overseer.models import SyscallCategory
from overseer.syscall_db import SyscallDatabase, ERRNO_MAP, AT_FDCWD


class TestSyscallDB(unittest.TestCase):
    def setUp(self):
        self.db = SyscallDatabase(arch="x86_64")

    def test_arch_detection(self):
        self.assertEqual(detect_arch("i386:x86-64").name, "x86_64")
        self.assertEqual(detect_arch("i386").name, "i386")
        self.assertEqual(detect_arch("aarch64").name, "aarch64")
        self.assertEqual(detect_arch("arm").name, "arm")

    def test_syscall_name_and_nr(self):
        self.assertEqual(self.db.get_name(39), "getpid")
        self.assertEqual(self.db.get_name(3), "close")
        self.assertEqual(self.db.get_name(257), "openat")

    def test_category(self):
        self.assertEqual(self.db.get_category("read"), SyscallCategory.FILE_IO)
        self.assertEqual(self.db.get_category("getpid"), SyscallCategory.PROCESS)
        self.assertEqual(self.db.get_category("mmap"), SyscallCategory.MEMORY)
        self.assertEqual(self.db.get_category("connect"), SyscallCategory.NETWORK)

    def test_idempotent_queries(self):
        self.assertTrue(self.db.is_idempotent("getpid"))
        self.assertTrue(self.db.is_idempotent("stat"))
        self.assertTrue(self.db.is_idempotent("access"))
        self.assertFalse(self.db.is_idempotent("write"))
        self.assertFalse(self.db.is_idempotent("unlink"))

    def test_errno_formatting(self):
        # Successful return
        ret_str, is_err, errno_name = self.db.format_return_value(0)
        self.assertEqual(ret_str, "0")
        self.assertFalse(is_err)
        self.assertIsNone(errno_name)

        # Linux -EBADF (-9) in 64-bit unsigned representation
        ebadf_uint64 = 0xFFFFFFFFFFFFFFF7  # -9
        ret_str, is_err, errno_name = self.db.format_return_value(ebadf_uint64)
        self.assertEqual(ret_str, "-9 (EBADF)")
        self.assertTrue(is_err)
        self.assertEqual(errno_name, "EBADF")

        # Linux -ENOENT (-2)
        enoent_uint64 = (1 << 64) - 2
        ret_str, is_err, errno_name = self.db.format_return_value(enoent_uint64)
        self.assertEqual(ret_str, "-2 (ENOENT)")
        self.assertTrue(is_err)
        self.assertEqual(errno_name, "ENOENT")

    def test_decode_args_openat(self):
        def fake_mem(addr, maxlen):
            if addr == 0x1234:
                return "/etc/passwd"
            return None

        # openat(AT_FDCWD, "/etc/passwd", O_RDONLY, 0)
        # AT_FDCWD is -100 (in 32-bit unsigned: 0xFFFFFF9C)
        raw_args = [0xFFFFFF9C, 0x1234, 0, 0]
        decoded = self.db.decode_args("openat", raw_args, fake_mem)
        self.assertEqual(decoded.get("dirfd"), "AT_FDCWD")
        self.assertEqual(decoded.get("path"), "/etc/passwd")
        self.assertEqual(decoded.get("flags"), "O_RDONLY")

    def test_decode_args_zero_arg(self):
        decoded = self.db.decode_args("getpid", [1, 2, 3])
        self.assertEqual(decoded, {})


if __name__ == "__main__":
    unittest.main()
