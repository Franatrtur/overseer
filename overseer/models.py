"""
Data models and classes representing syscall events and duplicate findings.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class SyscallCategory(str, Enum):
    FILE_IO = "file_io"
    PROCESS = "process"
    MEMORY = "memory"
    NETWORK = "network"
    TIME = "time"
    SIGNAL = "signal"
    IPC = "ipc"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class FindingKind(str, Enum):
    CONSECUTIVE = "consecutive"
    WINDOWED = "windowed"
    FAILING = "failing"
    IDEMPOTENT_QUERY = "idempotent_query"
    HIGH_FREQUENCY = "high_frequency"
    STATEFUL_REDUNDANT_QUERY = "stateful_redundant_query"
    STATEFUL_REDUNDANT_SEEK = "stateful_redundant_seek"
    USE_AFTER_CLOSE = "use_after_close"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class StackFrame:
    function: str
    filename: Optional[str] = None
    line: Optional[int] = None
    address: Optional[int] = None

    def __str__(self) -> str:
        loc = f"{self.filename or '??'}:{self.line or '?'}"
        return f"{self.function} ({loc})"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function": self.function,
            "filename": self.filename,
            "line": self.line,
            "address": hex(self.address) if self.address else None,
        }


@dataclass
class SyscallEvent:
    sequence: int
    thread_id: int
    syscall_nr: int
    name: str
    args: List[int]
    decoded_args: Dict[str, Any] = field(default_factory=dict)
    ret_val: Optional[int] = None
    ret_str: Optional[str] = None
    is_error: bool = False
    errno_name: Optional[str] = None
    location: Optional[str] = None
    stack_trace: List[StackFrame] = field(default_factory=list)
    timestamp: float = 0.0
    category: SyscallCategory = SyscallCategory.UNKNOWN
    is_idempotent: bool = False

    @property
    def signature_key(self) -> Tuple[str, Tuple[Tuple[str, str], ...]]:
        """A canonical hashable signature of (syscall_name, decoded_args) for equality checks."""
        # Fields that represent transient caller output buffer pointers
        # These shouldn't make two logically identical syscall queries differ
        out_param_keys = {
            "statbuf", "statxbuf", "buf", "tp", "tv", "rem", "pipefd",
            "statx", "addrlen",
        }
        # For ioctl query requests (e.g. TCGETS), arg is an output pointer to struct termios
        if self.name == "ioctl" and self.decoded_args.get("request") in ("TCGETS", "TIOCGWINSZ", "FIONREAD", "0x5401"):
            out_param_keys.add("arg")

        norm_args = []
        for k, v in sorted(self.decoded_args.items()):
            if k in out_param_keys:
                continue
            norm_args.append((str(k), str(v)))

        if not norm_args and self.name not in (
            "getpid", "getppid", "getuid", "geteuid", "getgid", "getegid",
            "gettid", "sched_yield", "pause", "sync"
        ):
            # Fallback to raw args for unknown syscalls
            norm_args = [(f"arg{i}", hex(val)) for i, val in enumerate(self.args[:3])]

        return (self.name, tuple(norm_args))

    def format_call(self) -> str:
        """Format syscall like name(arg1="val", arg2=42) or name()."""
        # If decoded_args has items, format key=value
        if self.decoded_args:
            items = []
            for k, v in self.decoded_args.items():
                if isinstance(v, str):
                    items.append(f'{k}="{v}"')
                else:
                    items.append(f"{k}={v}")
            return f"{self.name}({', '.join(items)})"

        # If zero-arg syscall
        if self.name in (
            "getpid", "getppid", "getuid", "geteuid", "getgid", "getegid",
            "gettid", "sched_yield", "pause", "sync"
        ):
            return f"{self.name}()"

        arg_strs = [hex(a) for a in self.args[:4]]
        return f"{self.name}({', '.join(arg_strs)})"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence": self.sequence,
            "thread_id": self.thread_id,
            "syscall_nr": self.syscall_nr,
            "name": self.name,
            "args": [hex(a) for a in self.args],
            "decoded_args": self.decoded_args,
            "ret_val": self.ret_val,
            "ret_str": self.ret_str,
            "is_error": self.is_error,
            "errno_name": self.errno_name,
            "location": self.location,
            "stack_trace": [f.to_dict() for f in self.stack_trace],
            "timestamp": self.timestamp,
            "category": self.category.value,
            "is_idempotent": self.is_idempotent,
        }


@dataclass
class DuplicateFinding:
    kind: FindingKind
    severity: Severity
    message: str
    current_event: SyscallEvent
    previous_event: SyscallEvent
    window_distance: int = 1
    repeat_count: int = 2
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "severity": self.severity.value,
            "message": self.message,
            "current_event": self.current_event.to_dict(),
            "previous_event": self.previous_event.to_dict(),
            "window_distance": self.window_distance,
            "repeat_count": self.repeat_count,
            "details": self.details,
        }


@dataclass
class SyscallReport:
    target: str
    total_syscalls: int
    unique_syscalls: int
    findings: List[DuplicateFinding]
    syscall_counts: Dict[str, int]
    duplicate_counts: Dict[str, int]
    error_counts: Dict[str, int]
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "total_syscalls": self.total_syscalls,
            "unique_syscalls": self.unique_syscalls,
            "findings_count": len(self.findings),
            "duration_seconds": self.duration_seconds,
            "findings": [f.to_dict() for f in self.findings],
            "syscall_counts": self.syscall_counts,
            "duplicate_counts": self.duplicate_counts,
            "error_counts": self.error_counts,
        }
