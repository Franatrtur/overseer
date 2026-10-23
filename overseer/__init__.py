"""
Overseer: A GDB-powered dynamic syscall duplicate detector and profiler.
Connects to GDB to track syscall execution and flag redundant, consecutive,
failing, and duplicate syscalls with full source code backtraces.
"""

__version__ = "1.0.0"
__author__ = "Overseer Team"

from overseer.models import SyscallEvent, DuplicateFinding, SyscallCategory
from overseer.detector import SyscallDetector
from overseer.connector import GDBConnector

__all__ = [
    "SyscallEvent",
    "DuplicateFinding",
    "SyscallCategory",
    "SyscallDetector",
    "GDBConnector",
]
