"""
Stateful resource tracking for file descriptors, paths, and offsets.
Maintains an invalidation model to distinguish truly redundant queries from
legitimate queries following state mutations.
"""

from dataclasses import dataclass, field
import os
from typing import Dict, List, Optional, Set

from overseer.models import (
    DuplicateFinding,
    FindingKind,
    Severity,
    SyscallEvent,
)


@dataclass
class FDState:
    fd: int
    path: Optional[str] = None
    is_open: bool = True
    offset: Optional[int] = None
    dirty_generation: int = 0
    last_stat_generation: Optional[int] = None
    last_stat_event: Optional[SyscallEvent] = None
    last_seek_event: Optional[SyscallEvent] = None
    last_close_event: Optional[SyscallEvent] = None


@dataclass
class PathState:
    path: str
    dirty_generation: int = 0
    last_stat_generation: Optional[int] = None
    last_stat_event: Optional[SyscallEvent] = None


class StateManager:
    """
    Maintains abstract state of open file descriptors, file offsets,
    and path mutations across process execution.
    """

    def __init__(self):
        self.fds: Dict[int, FDState] = {}
        self.paths: Dict[str, PathState] = {}
        # Pre-seed standard descriptors
        self.fds[0] = FDState(fd=0, is_open=True)
        self.fds[1] = FDState(fd=1, is_open=True)
        self.fds[2] = FDState(fd=2, is_open=True)

    def _normalize_path(self, path: Optional[str]) -> Optional[str]:
        if not path or not isinstance(path, str):
            return None
        return os.path.normpath(path)

    def get_or_create_fd(self, fd: int, path: Optional[str] = None) -> FDState:
        if fd not in self.fds:
            self.fds[fd] = FDState(fd=fd, path=self._normalize_path(path), is_open=True)
        elif path and not self.fds[fd].path:
            self.fds[fd].path = self._normalize_path(path)
        return self.fds[fd]

    def get_or_create_path(self, path: str) -> PathState:
        norm = self._normalize_path(path) or path
        if norm not in self.paths:
            self.paths[norm] = PathState(path=norm)
        return self.paths[norm]

    def process_event(self, event: SyscallEvent) -> tuple[List[DuplicateFinding], bool]:
        """
        Update state machine based on syscall event and return:
        (findings, is_state_handled)
        is_state_handled indicates that this syscall is a resource-level query/operation
        whose validity has been evaluated by the state machine (suppressing naive sliding-window flags).
        """
        findings: List[DuplicateFinding] = []
        is_state_handled = False
        name = event.name
        args = event.decoded_args

        # 1. Opening resources (open, openat, creat)
        if name in ("open", "openat", "creat"):
            if not event.is_error and event.ret_val is not None and event.ret_val >= 0:
                new_fd = event.ret_val
                path = self._normalize_path(args.get("path"))
                fd_state = self.get_or_create_fd(new_fd, path)
                fd_state.is_open = True
                fd_state.offset = 0
                fd_state.dirty_generation = 0
                fd_state.last_stat_generation = None
                fd_state.last_stat_event = None
                fd_state.last_seek_event = None
                fd_state.last_close_event = None

                if path:
                    flags_str = str(args.get("flags", ""))
                    if "O_TRUNC" in flags_str or "O_CREAT" in flags_str:
                        p_state = self.get_or_create_path(path)
                        p_state.dirty_generation += 1

        # 2. Closing resources
        elif name == "close":
            fd_val = args.get("fd")
            if isinstance(fd_val, int):
                fd_state = self.get_or_create_fd(fd_val)
                if not fd_state.is_open and fd_state.last_close_event:
                    findings.append(
                        DuplicateFinding(
                            kind=FindingKind.USE_AFTER_CLOSE,
                            severity=Severity.ERROR,
                            message=f"Double close on descriptor fd={fd_val} (already closed at #{fd_state.last_close_event.sequence})",
                            current_event=event,
                            previous_event=fd_state.last_close_event,
                        )
                    )
                    is_state_handled = True
                fd_state.is_open = False
                fd_state.last_close_event = event

        # 3. fstat / fstat64
        elif name in ("fstat", "fstat64"):
            fd_val = args.get("fd")
            if isinstance(fd_val, int) and not event.is_error:
                is_state_handled = True
                fd_state = self.get_or_create_fd(fd_val)
                if (
                    fd_state.last_stat_generation is not None
                    and fd_state.dirty_generation == fd_state.last_stat_generation
                    and fd_state.last_stat_event is not None
                ):
                    # Unchanged descriptor statted again without intervening mutation
                    findings.append(
                        DuplicateFinding(
                            kind=FindingKind.STATEFUL_REDUNDANT_QUERY,
                            severity=Severity.WARNING,
                            message=(
                                f"Redundant fstat on unchanged fd={fd_val} "
                                f"(no write/truncate since #{fd_state.last_stat_event.sequence})"
                            ),
                            current_event=event,
                            previous_event=fd_state.last_stat_event,
                        )
                    )
                fd_state.last_stat_generation = fd_state.dirty_generation
                fd_state.last_stat_event = event

        # 4. Path queries (stat, lstat, newfstatat, access)
        elif name in ("stat", "lstat", "newfstatat", "statx", "access", "faccessat"):
            path = self._normalize_path(args.get("path"))
            if path and not event.is_error:
                is_state_handled = True
                p_state = self.get_or_create_path(path)
                if (
                    p_state.last_stat_generation is not None
                    and p_state.dirty_generation == p_state.last_stat_generation
                    and p_state.last_stat_event is not None
                ):
                    findings.append(
                        DuplicateFinding(
                            kind=FindingKind.STATEFUL_REDUNDANT_QUERY,
                            severity=Severity.WARNING,
                            message=(
                                f"Redundant {name} on unchanged path '{path}' "
                                f"(no modifying operation since #{p_state.last_stat_event.sequence})"
                            ),
                            current_event=event,
                            previous_event=p_state.last_stat_event,
                        )
                    )
                p_state.last_stat_generation = p_state.dirty_generation
                p_state.last_stat_event = event

        # 5. Writing / Mutating file contents (write, pwrite64, ftruncate)
        elif name in ("write", "pwrite64", "writev", "ftruncate", "fallocate"):
            fd_val = args.get("fd")
            if isinstance(fd_val, int) and not event.is_error:
                fd_state = self.get_or_create_fd(fd_val)
                fd_state.dirty_generation += 1

                # If fd is bound to a path, also bump path generation
                if fd_state.path:
                    p_state = self.get_or_create_path(fd_state.path)
                    p_state.dirty_generation += 1

                # Update offset on sequential write
                if name in ("write", "writev") and event.ret_val is not None and event.ret_val > 0:
                    if fd_state.offset is not None:
                        fd_state.offset += event.ret_val

        # 6. Reading file contents (updates offset)
        elif name in ("read", "readv"):
            fd_val = args.get("fd")
            if isinstance(fd_val, int) and not event.is_error:
                fd_state = self.get_or_create_fd(fd_val)
                if event.ret_val is not None and event.ret_val > 0:
                    if fd_state.offset is not None:
                        fd_state.offset += event.ret_val

        # 7. Seeking (lseek)
        elif name == "lseek":
            fd_val = args.get("fd")
            offset = args.get("offset")
            whence = args.get("whence")
            if isinstance(fd_val, int) and not event.is_error:
                is_state_handled = True
                fd_state = self.get_or_create_fd(fd_val)
                if whence == "SEEK_SET" and isinstance(offset, int):
                    if (
                        fd_state.offset is not None
                        and fd_state.offset == offset
                        and fd_state.last_seek_event is not None
                    ):
                        findings.append(
                            DuplicateFinding(
                                kind=FindingKind.STATEFUL_REDUNDANT_SEEK,
                                severity=Severity.WARNING,
                                message=(
                                    f"Redundant lseek on fd={fd_val}: file offset is already {offset} "
                                    f"(set at #{fd_state.last_seek_event.sequence})"
                                ),
                                current_event=event,
                                previous_event=fd_state.last_seek_event,
                            )
                        )
                elif whence == "SEEK_CUR" and offset == 0:
                    if (
                        fd_state.last_seek_event is not None
                        and fd_state.last_seek_event.decoded_args.get("whence") == "SEEK_CUR"
                        and fd_state.last_seek_event.decoded_args.get("offset") == 0
                        and fd_state.last_seek_event.sequence == event.sequence - 1
                    ):
                        findings.append(
                            DuplicateFinding(
                                kind=FindingKind.STATEFUL_REDUNDANT_SEEK,
                                severity=Severity.WARNING,
                                message=(
                                    f"Redundant tell/lseek(SEEK_CUR, 0) on fd={fd_val} "
                                    f"(already queried at #{fd_state.last_seek_event.sequence})"
                                ),
                                current_event=event,
                                previous_event=fd_state.last_seek_event,
                            )
                        )

                # Update current offset from return value
                if event.ret_val is not None and event.ret_val >= 0:
                    fd_state.offset = event.ret_val
                fd_state.last_seek_event = event

        # 8. Path mutations (unlink, unlinkat, rename, renameat, truncate)
        elif name in ("unlink", "unlinkat", "rename", "renameat", "truncate"):
            if not event.is_error:
                path = self._normalize_path(args.get("path")) or self._normalize_path(args.get("oldpath"))
                if path:
                    p_state = self.get_or_create_path(path)
                    p_state.dirty_generation += 1
                new_path = self._normalize_path(args.get("newpath"))
                if new_path:
                    p_state = self.get_or_create_path(new_path)
                    p_state.dirty_generation += 1

        return findings, is_state_handled
