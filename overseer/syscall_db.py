"""
Syscall database, argument decoders, errno mappings, and category definitions.
"""

import os
from typing import Any, Callable, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET

from overseer.models import SyscallCategory

# Common ioctl request codes on Linux
IOCTL_NAMES = {
    0x5401: "TCGETS",
    0x5402: "TCSETS",
    0x5403: "TCSETSW",
    0x5404: "TCSETSF",
    0x5413: "TIOCGWINSZ",
    0x5414: "TIOCSWINSZ",
    0x541B: "FIONREAD",
}

# Standard Linux errno definitions
ERRNO_MAP = {
    1: "EPERM",
    2: "ENOENT",
    3: "ESRCH",
    4: "EINTR",
    5: "EIO",
    6: "ENXIO",
    7: "E2BIG",
    8: "ENOEXEC",
    9: "EBADF",
    10: "ECHILD",
    11: "EAGAIN",
    12: "ENOMEM",
    13: "EACCES",
    14: "EFAULT",
    15: "ENOTBLK",
    16: "EBUSY",
    17: "EEXIST",
    18: "EXDEV",
    19: "ENODEV",
    20: "ENOTDIR",
    21: "EISDIR",
    22: "EINVAL",
    23: "ENFILE",
    24: "EMFILE",
    25: "ENOTTY",
    26: "ETXTBSY",
    27: "EFBIG",
    28: "ENOSPC",
    29: "ESPIPE",
    30: "EROFS",
    31: "EMLINK",
    32: "EPIPE",
    33: "EDOM",
    34: "ERANGE",
    35: "EDEADLK",
    36: "ENAMETOOLONG",
    37: "ENOLCK",
    38: "ENOSYS",
    39: "ENOTEMPTY",
    40: "ELOOP",
    88: "ENOTSOCK",
    104: "ECONNRESET",
    110: "ETIMEDOUT",
    111: "ECONNREFUSED",
    113: "EHOSTUNREACH",
}

# Open flags decoding
O_FLAGS = [
    (0x00000001, "O_WRONLY"),
    (0x00000002, "O_RDWR"),
    (0x00000040, "O_CREAT"),
    (0x00000080, "O_EXCL"),
    (0x00000100, "O_NOCTTY"),
    (0x00000200, "O_TRUNC"),
    (0x00000400, "O_APPEND"),
    (0x00000800, "O_NONBLOCK"),
    (0x00080000, "O_CLOEXEC"),
]

# lseek whence
WHENCE_MAP = {
    0: "SEEK_SET",
    1: "SEEK_CUR",
    2: "SEEK_END",
}

AT_FDCWD = -100

# Common syscall argument schemas: (arg_name, arg_type)
SYSCALL_SIGNATURES: Dict[str, List[Tuple[str, str]]] = {
    "open": [("path", "path"), ("flags", "flags"), ("mode", "mode")],
    "openat": [("dirfd", "fd"), ("path", "path"), ("flags", "flags"), ("mode", "mode")],
    "creat": [("path", "path"), ("mode", "mode")],
    "close": [("fd", "fd")],
    "read": [("fd", "fd"), ("buf", "ptr"), ("count", "int")],
    "write": [("fd", "fd"), ("buf", "ptr"), ("count", "int")],
    "pread64": [("fd", "fd"), ("buf", "ptr"), ("count", "int"), ("offset", "int")],
    "pwrite64": [("fd", "fd"), ("buf", "ptr"), ("count", "int"), ("offset", "int")],
    "stat": [("path", "path"), ("statbuf", "ptr")],
    "lstat": [("path", "path"), ("statbuf", "ptr")],
    "fstat": [("fd", "fd"), ("statbuf", "ptr")],
    "newfstatat": [("dirfd", "fd"), ("path", "path"), ("statbuf", "ptr"), ("flags", "hex")],
    "statx": [("dirfd", "fd"), ("path", "path"), ("flags", "hex"), ("mask", "hex"), ("statxbuf", "ptr")],
    "access": [("path", "path"), ("mode", "int")],
    "faccessat": [("dirfd", "fd"), ("path", "path"), ("mode", "int"), ("flags", "hex")],
    "unlink": [("path", "path")],
    "unlinkat": [("dirfd", "fd"), ("path", "path"), ("flags", "hex")],
    "rename": [("oldpath", "path"), ("newpath", "path")],
    "renameat": [("olddirfd", "fd"), ("oldpath", "path"), ("newdirfd", "fd"), ("newpath", "path")],
    "mkdir": [("path", "path"), ("mode", "mode")],
    "mkdirat": [("dirfd", "fd"), ("path", "path"), ("mode", "mode")],
    "rmdir": [("path", "path")],
    "readlink": [("path", "path"), ("buf", "ptr"), ("bufsiz", "int")],
    "readlinkat": [("dirfd", "fd"), ("path", "path"), ("buf", "ptr"), ("bufsiz", "int")],
    "lseek": [("fd", "fd"), ("offset", "int"), ("whence", "whence")],
    "mmap": [("addr", "hex"), ("length", "int"), ("prot", "hex"), ("flags", "hex"), ("fd", "fd"), ("offset", "int")],
    "mprotect": [("addr", "hex"), ("length", "int"), ("prot", "hex")],
    "munmap": [("addr", "hex"), ("length", "int")],
    "brk": [("addr", "hex")],
    "ioctl": [("fd", "fd"), ("request", "ioctl_req"), ("arg", "ptr")],
    "fcntl": [("fd", "fd"), ("cmd", "int"), ("arg", "hex")],
    "dup": [("oldfd", "fd")],
    "dup2": [("oldfd", "fd"), ("newfd", "fd")],
    "dup3": [("oldfd", "fd"), ("newfd", "fd"), ("flags", "hex")],
    "socket": [("domain", "int"), ("type", "int"), ("protocol", "int")],
    "connect": [("sockfd", "fd"), ("addr", "ptr"), ("addrlen", "int")],
    "bind": [("sockfd", "fd"), ("addr", "ptr"), ("addrlen", "int")],
    "listen": [("sockfd", "fd"), ("backlog", "int")],
    "accept": [("sockfd", "fd"), ("addr", "ptr"), ("addrlen", "ptr")],
    "accept4": [("sockfd", "fd"), ("addr", "ptr"), ("addrlen", "ptr"), ("flags", "hex")],
    "getpid": [],
    "getppid": [],
    "getuid": [],
    "geteuid": [],
    "getgid": [],
    "getegid": [],
    "gettid": [],
    "nanosleep": [("req", "ptr"), ("rem", "ptr")],
    "clock_gettime": [("clk_id", "int"), ("tp", "ptr")],
    "gettimeofday": [("tv", "ptr"), ("tz", "ptr")],
    "kill": [("pid", "int"), ("sig", "int")],
    "tgkill": [("tgid", "int"), ("tid", "int"), ("sig", "int")],
    "chdir": [("path", "path")],
    "fchdir": [("fd", "fd")],
    "getcwd": [("buf", "ptr"), ("size", "int")],
    "poll": [("fds", "ptr"), ("nfds", "int"), ("timeout", "int")],
    "epoll_create": [("size", "int")],
    "epoll_create1": [("flags", "hex")],
    "epoll_ctl": [("epfd", "fd"), ("op", "int"), ("fd", "fd"), ("event", "ptr")],
    "execve": [("filename", "path"), ("argv", "ptr"), ("envp", "ptr")],
}

IDEMPOTENT_QUERIES = {
    "getpid", "getppid", "getuid", "geteuid", "getgid", "getegid", "gettid",
    "stat", "fstat", "lstat", "newfstatat", "statx", "access", "faccessat",
    "readlink", "readlinkat", "getcwd", "uname", "gettimeofday", "time",
}

SYSCALL_CATEGORIES: Dict[str, SyscallCategory] = {
    # File IO
    "read": SyscallCategory.FILE_IO,
    "write": SyscallCategory.FILE_IO,
    "open": SyscallCategory.FILE_IO,
    "openat": SyscallCategory.FILE_IO,
    "close": SyscallCategory.FILE_IO,
    "stat": SyscallCategory.FILE_IO,
    "fstat": SyscallCategory.FILE_IO,
    "lstat": SyscallCategory.FILE_IO,
    "newfstatat": SyscallCategory.FILE_IO,
    "statx": SyscallCategory.FILE_IO,
    "lseek": SyscallCategory.FILE_IO,
    "access": SyscallCategory.FILE_IO,
    "faccessat": SyscallCategory.FILE_IO,
    "unlink": SyscallCategory.FILE_IO,
    "unlinkat": SyscallCategory.FILE_IO,
    "rename": SyscallCategory.FILE_IO,
    "renameat": SyscallCategory.FILE_IO,
    "mkdir": SyscallCategory.FILE_IO,
    "mkdirat": SyscallCategory.FILE_IO,
    "rmdir": SyscallCategory.FILE_IO,
    "readlink": SyscallCategory.FILE_IO,
    "readlinkat": SyscallCategory.FILE_IO,
    "fcntl": SyscallCategory.FILE_IO,
    "ioctl": SyscallCategory.FILE_IO,
    "dup": SyscallCategory.FILE_IO,
    "dup2": SyscallCategory.FILE_IO,
    "dup3": SyscallCategory.FILE_IO,
    "poll": SyscallCategory.FILE_IO,
    "select": SyscallCategory.FILE_IO,
    "epoll_create": SyscallCategory.FILE_IO,
    "epoll_create1": SyscallCategory.FILE_IO,
    "epoll_ctl": SyscallCategory.FILE_IO,
    "epoll_wait": SyscallCategory.FILE_IO,
    # Memory
    "mmap": SyscallCategory.MEMORY,
    "mprotect": SyscallCategory.MEMORY,
    "munmap": SyscallCategory.MEMORY,
    "brk": SyscallCategory.MEMORY,
    "madvise": SyscallCategory.MEMORY,
    # Process
    "clone": SyscallCategory.PROCESS,
    "clone3": SyscallCategory.PROCESS,
    "fork": SyscallCategory.PROCESS,
    "vfork": SyscallCategory.PROCESS,
    "execve": SyscallCategory.PROCESS,
    "exit": SyscallCategory.PROCESS,
    "exit_group": SyscallCategory.PROCESS,
    "wait4": SyscallCategory.PROCESS,
    "waitid": SyscallCategory.PROCESS,
    "getpid": SyscallCategory.PROCESS,
    "getppid": SyscallCategory.PROCESS,
    "gettid": SyscallCategory.PROCESS,
    "getuid": SyscallCategory.PROCESS,
    "geteuid": SyscallCategory.PROCESS,
    "getgid": SyscallCategory.PROCESS,
    "getegid": SyscallCategory.PROCESS,
    "prlimit64": SyscallCategory.PROCESS,
    "arch_prctl": SyscallCategory.PROCESS,
    "set_tid_address": SyscallCategory.PROCESS,
    "set_robust_list": SyscallCategory.PROCESS,
    "rseq": SyscallCategory.PROCESS,
    # Network
    "socket": SyscallCategory.NETWORK,
    "connect": SyscallCategory.NETWORK,
    "accept": SyscallCategory.NETWORK,
    "accept4": SyscallCategory.NETWORK,
    "bind": SyscallCategory.NETWORK,
    "listen": SyscallCategory.NETWORK,
    "sendto": SyscallCategory.NETWORK,
    "recvfrom": SyscallCategory.NETWORK,
    "sendmsg": SyscallCategory.NETWORK,
    "recvmsg": SyscallCategory.NETWORK,
    # Time
    "nanosleep": SyscallCategory.TIME,
    "clock_gettime": SyscallCategory.TIME,
    "gettimeofday": SyscallCategory.TIME,
    "time": SyscallCategory.TIME,
    # Signal
    "rt_sigaction": SyscallCategory.SIGNAL,
    "rt_sigprocmask": SyscallCategory.SIGNAL,
    "rt_sigreturn": SyscallCategory.SIGNAL,
    "kill": SyscallCategory.SIGNAL,
    "tgkill": SyscallCategory.SIGNAL,
}

# Static x86_64 mapping fallback
X86_64_SYSCALLS = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    15: "rt_sigreturn",
    16: "ioctl",
    17: "pread64",
    18: "pwrite64",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    23: "select",
    24: "sched_yield",
    32: "dup",
    33: "dup2",
    39: "getpid",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    49: "bind",
    50: "listen",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    62: "kill",
    72: "fcntl",
    79: "getcwd",
    80: "chdir",
    81: "fchdir",
    82: "rename",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    89: "readlink",
    96: "gettimeofday",
    102: "getuid",
    104: "getgid",
    105: "setuid",
    106: "setgid",
    107: "geteuid",
    108: "getegid",
    110: "getppid",
    158: "arch_prctl",
    186: "gettid",
    201: "time",
    202: "futex",
    218: "set_tid_address",
    228: "clock_gettime",
    230: "clock_nanosleep",
    231: "exit_group",
    232: "epoll_wait",
    233: "epoll_ctl",
    257: "openat",
    258: "mkdirat",
    262: "newfstatat",
    263: "unlinkat",
    264: "renameat",
    267: "readlinkat",
    269: "faccessat",
    273: "set_robust_list",
    291: "epoll_create1",
    292: "dup3",
    293: "pipe2",
    302: "prlimit64",
    332: "statx",
    334: "rseq",
    435: "clone3",
    439: "faccessat2",
}


class SyscallDatabase:
    """Manages syscall lookups, signatures, argument formatting, and error decoding."""

    def __init__(self, arch: str = "x86_64"):
        self.arch = arch
        self.nr_to_name: Dict[int, str] = {}
        self.name_to_nr: Dict[str, int] = {}
        self.load_syscall_tables(arch)

    def load_syscall_tables(self, arch: str):
        # 1. Try loading from GDB XML syscall files
        xml_path = None
        candidates = [
            f"/usr/share/gdb/syscalls/{arch}-linux.xml",
            f"/usr/share/gdb/syscalls/{'amd64' if arch == 'x86_64' else arch}-linux.xml",
        ]
        for c in candidates:
            if os.path.exists(c):
                xml_path = c
                break

        if xml_path and os.path.isfile(xml_path):
            try:
                tree = ET.parse(xml_path)
                for sc in tree.getroot().findall("syscall"):
                    nr = int(sc.get("number"))
                    name = sc.get("name")
                    self.nr_to_name[nr] = name
                    self.name_to_nr[name] = nr
                return
            except Exception:
                pass

        # 2. Fallback to built-in x86_64 map
        self.nr_to_name = dict(X86_64_SYSCALLS)
        self.name_to_nr = {v: k for k, v in self.nr_to_name.items()}

    def get_name(self, syscall_nr: int) -> str:
        return self.nr_to_name.get(syscall_nr, f"sys_{syscall_nr}")

    def get_number(self, name: str) -> Optional[int]:
        return self.name_to_nr.get(name)

    def get_category(self, name: str) -> SyscallCategory:
        return SYSCALL_CATEGORIES.get(name, SyscallCategory.UNKNOWN)

    def is_idempotent(self, name: str) -> bool:
        return name in IDEMPOTENT_QUERIES

    def format_return_value(self, ret: int) -> Tuple[str, bool, Optional[str]]:
        """
        Returns (formatted_str, is_error, errno_name).
        On Linux, negative returns in range [-4095, -1] indicate -errno.
        """
        # Convert signed 64-bit int if needed
        if ret > 0x7FFFFFFFFFFFFFFF:
            ret_signed = ret - (1 << 64)
        else:
            ret_signed = ret

        if -4095 <= ret_signed < 0:
            errno_val = -ret_signed
            errno_name = ERRNO_MAP.get(errno_val, f"errno_{errno_val}")
            return f"-{errno_val} ({errno_name})", True, errno_name

        return str(ret_signed), False, None

    def decode_args(
        self,
        name: str,
        raw_args: List[int],
        memory_reader: Optional[Callable[[int, int], Optional[str]]] = None,
    ) -> Dict[str, Any]:
        """Decodes raw registers into structured name-value pairs based on syscall signature."""
        sig = SYSCALL_SIGNATURES.get(name)
        decoded: Dict[str, Any] = {}

        if sig is None:
            # Generic decoding for unknown syscalls
            for i, val in enumerate(raw_args[:4]):
                decoded[f"arg{i}"] = hex(val) if val > 0xFFFF else val
            return decoded

        # Zero arguments syscall
        if len(sig) == 0:
            return {}

        for i, (arg_name, arg_type) in enumerate(sig):
            if i >= len(raw_args):
                break
            raw_val = raw_args[i]

            if arg_type == "path":
                if memory_reader and raw_val != 0:
                    s = memory_reader(raw_val, 256)
                    decoded[arg_name] = s if s is not None else hex(raw_val)
                else:
                    decoded[arg_name] = hex(raw_val)

            elif arg_type == "fd":
                # Convert 32-bit unsigned to signed for negative values like AT_FDCWD
                if raw_val > 0x7FFFFFFF:
                    signed_fd = raw_val - 0x100000000
                else:
                    signed_fd = raw_val
                if signed_fd == AT_FDCWD:
                    decoded[arg_name] = "AT_FDCWD"
                else:
                    decoded[arg_name] = signed_fd

            elif arg_type == "flags":
                flag_names = []
                # Check known flags
                for bit, bit_name in O_FLAGS:
                    if (raw_val & bit) == bit:
                        flag_names.append(bit_name)
                if raw_val & 3 == 0:
                    flag_names.insert(0, "O_RDONLY")
                elif raw_val & 3 == 1:
                    flag_names.insert(0, "O_WRONLY")
                elif raw_val & 3 == 2:
                    flag_names.insert(0, "O_RDWR")
                decoded[arg_name] = "|".join(flag_names) if flag_names else hex(raw_val)

            elif arg_type == "ioctl_req":
                decoded[arg_name] = IOCTL_NAMES.get(raw_val, hex(raw_val))

            elif arg_type == "mode":
                decoded[arg_name] = oct(raw_val & 0o7777)

            elif arg_type == "whence":
                decoded[arg_name] = WHENCE_MAP.get(raw_val, hex(raw_val))

            elif arg_type == "hex" or arg_type == "ptr":
                decoded[arg_name] = hex(raw_val)

            elif arg_type == "int":
                decoded[arg_name] = raw_val

            else:
                decoded[arg_name] = raw_val

        return decoded
