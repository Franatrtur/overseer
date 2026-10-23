"""
Core GDB tracer engine.
Runs within GDB's embedded Python interpreter to intercept syscalls,
extract registers, dereference userspace pointers, map stack frames,
and feed events to the SyscallDetector.
"""

import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import gdb
except ImportError:
    gdb = None

from overseer.arch import ArchSpec, detect_arch
from overseer.detector import SyscallDetector
from overseer.models import StackFrame, SyscallEvent
from overseer.reporter import Reporter
from overseer.syscall_db import SyscallDatabase


def read_inferior_string(inferior: Any, addr: int, max_len: int = 256) -> Optional[str]:
    """Safely dereference a null-terminated string from inferior memory."""
    if not addr or addr == 0 or addr > 0x7FFFFFFFFFFF:
        return None
    try:
        mem = inferior.read_memory(addr, max_len)
        raw = bytes(mem)
        idx = raw.find(b"\x00")
        if idx != -1:
            raw = raw[:idx]
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def extract_stack_frames(frame: Any) -> Tuple[Optional[str], List[StackFrame]]:
    """Walk frames upward to extract call stack and identify primary user location."""
    frames: List[StackFrame] = []
    user_location: Optional[str] = None

    curr = frame
    depth = 0
    while curr and depth < 20:
        name = curr.name() or "??"
        sal = curr.find_sal()
        filename = sal.symtab.filename if (sal and sal.symtab) else None
        line = sal.line if sal else None
        pc = int(curr.pc()) if hasattr(curr, "pc") else None

        frame_info = StackFrame(
            function=name,
            filename=filename,
            line=line,
            address=pc,
        )
        frames.append(frame_info)

        # Check if this frame is in user source code
        if (
            filename
            and not filename.startswith("..")
            and not filename.startswith("/build")
            and not filename.startswith("/lib")
            and not filename.startswith("/usr")
            and not user_location
        ):
            user_location = f"{name} ({filename}:{line})"

        curr = curr.older()
        depth += 1

    # Fallback to older frame or newest frame if no explicit user file found
    if not user_location and len(frames) > 1:
        f = frames[1]
        user_location = f"{f.function} ({f.filename or '??'}:{f.line or '?'})"
    elif not user_location and frames:
        f = frames[0]
        user_location = f"{f.function} ({f.filename or '??'}:{f.line or '?'})"

    return user_location, frames


class GDBTracker:
    """Manages syscall interception loop inside GDB."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.target = config.get("target", "unknown")
        self.start_at = config.get("start_at", "main")
        self.from_start = config.get("from_start", False)
        self.quiet = config.get("quiet", False)
        self.verbose = config.get("verbose", False)
        self.json_path = config.get("json_path")

        filter_sc = config.get("filter_syscalls")
        exclude_sc = config.get("exclude_syscalls")

        self.detector = SyscallDetector(
            consecutive_only=config.get("consecutive_only", False),
            window_size=config.get("window_size", 15),
            min_repeats=config.get("min_repeats", 2),
            filter_syscalls=set(filter_sc) if filter_sc else None,
            exclude_syscalls=set(exclude_sc) if exclude_sc else None,
            per_thread=config.get("per_thread", True),
            ignore_loader_noise=config.get("ignore_loader_noise", True),
        )

        self.reporter = Reporter(
            quiet=self.quiet,
            verbose=self.verbose,
        )

        self.db: Optional[SyscallDatabase] = None
        self.arch: Optional[ArchSpec] = None
        self.pending_entries: Dict[int, Dict[str, Any]] = {}
        self.sequence = 0
        self.start_time = 0.0
        self.tracking_active = self.from_start

    def initialize_gdb(self):
        """Set up GDB options and catchpoints before starting inferior."""
        gdb.execute("set pagination off")
        gdb.execute("set print thread-events off")

        # Configure inferior tty if provided (e.g. for pty terminals)
        inferior_tty = self.config.get("inferior_tty")
        if inferior_tty:
            try:
                gdb.execute(f"set inferior-tty {inferior_tty}", to_string=True)
            except gdb.error:
                pass

        # Set catchpoint first so no syscalls are missed
        gdb.execute("catch syscall", to_string=True)
        for bp in gdb.breakpoints():
            if bp.type == gdb.BP_CATCHPOINT:
                bp.silent = True

        # If start_at is requested and not from_start, break at symbol
        if self.start_at and not self.from_start:
            try:
                gdb.execute(f"break {self.start_at}", to_string=True)
                for bp in gdb.breakpoints():
                    if bp.type != gdb.BP_CATCHPOINT:
                        bp.silent = True
            except gdb.error:
                # Symbol not found, track from start
                self.tracking_active = True

        # Start execution
        run_args = self.config.get("args", [])
        run_cmd = f"run {' '.join(run_args)}".strip()
        gdb.execute(run_cmd, to_string=True)

    def run(self):
        """Main syscall tracing loop."""
        if not gdb:
            raise RuntimeError("GDBTracker must be executed inside GDB.")

        self.start_time = time.time()
        self.initialize_gdb()

        inf = gdb.selected_inferior()
        if not inf or not inf.is_valid():
            return

        # Detect arch from current frame
        try:
            arch_name = gdb.selected_frame().architecture().name()
        except Exception:
            arch_name = "x86_64"

        self.arch = detect_arch(arch_name)
        self.db = SyscallDatabase(arch=self.arch.name)

        while True:
            if not inf or not inf.is_valid() or not inf.threads():
                break

            thread = gdb.selected_thread()
            if not thread or not thread.is_stopped():
                # Try to continue if possible
                try:
                    gdb.execute("continue", to_string=True)
                except gdb.error:
                    break
                continue

            tid = thread.num
            frame = gdb.selected_frame()

            # Check if we should activate tracking (e.g. hit start_at symbol)
            if not self.tracking_active:
                f_check = frame
                depth = 0
                while f_check and depth < 5:
                    if f_check.name() == self.start_at:
                        self.tracking_active = True
                        break
                    f_check = f_check.older()
                    depth += 1

            # Read syscall return/indicator register
            try:
                ret_reg_val = int(frame.read_register(self.arch.ret_reg))
            except Exception:
                try:
                    gdb.execute("continue", to_string=True)
                except gdb.error:
                    break
                continue

            # Convert to signed int
            if ret_reg_val > 0x7FFFFFFFFFFFFFFF:
                ret_signed = ret_reg_val - (1 << 64)
            else:
                ret_signed = ret_reg_val

            # Determine whether this is an entry or return
            is_entry = (ret_signed == self.arch.entry_indicator_val)

            if self.tracking_active:
                if is_entry:
                    self._handle_syscall_entry(inf, frame, tid)
                else:
                    self._handle_syscall_return(frame, tid, ret_reg_val)

            try:
                # Continue execution until next catchpoint stop
                gdb.execute("continue", to_string=True)
            except gdb.error:
                break

        duration = time.time() - self.start_time
        report = self.detector.generate_report(self.target, duration=duration)

        if not self.quiet:
            self.reporter.print_summary(report)

        if self.json_path:
            self.reporter.export_json(report, self.json_path)

    def _handle_syscall_entry(self, inf: Any, frame: Any, tid: int):
        # Determine syscall number
        orig_reg = self.arch.orig_syscall_reg or self.arch.syscall_reg
        try:
            syscall_nr = int(frame.read_register(orig_reg))
        except Exception:
            return

        name = self.db.get_name(syscall_nr)

        # Read argument registers
        raw_args = []
        for reg_name in self.arch.arg_regs:
            try:
                val = int(frame.read_register(reg_name))
            except Exception:
                val = 0
            raw_args.append(val)

        # Dereference string pointers where appropriate
        def mem_reader(addr: int, maxlen: int) -> Optional[str]:
            return read_inferior_string(inf, addr, maxlen)

        decoded_args = self.db.decode_args(name, raw_args, mem_reader)
        loc, frames = extract_stack_frames(frame)

        self.sequence += 1
        self.pending_entries[tid] = {
            "sequence": self.sequence,
            "syscall_nr": syscall_nr,
            "name": name,
            "args": raw_args,
            "decoded_args": decoded_args,
            "location": loc,
            "stack_trace": frames,
            "timestamp": time.time(),
        }

    def _handle_syscall_return(self, frame: Any, tid: int, ret_val: int):
        entry = self.pending_entries.pop(tid, None)
        if not entry:
            return

        name = entry["name"]
        ret_str, is_err, errno_name = self.db.format_return_value(ret_val)

        event = SyscallEvent(
            sequence=entry["sequence"],
            thread_id=tid,
            syscall_nr=entry["syscall_nr"],
            name=name,
            args=entry["args"],
            decoded_args=entry["decoded_args"],
            ret_val=ret_val,
            ret_str=ret_str,
            is_error=is_err,
            errno_name=errno_name,
            location=entry["location"],
            stack_trace=entry["stack_trace"],
            timestamp=entry["timestamp"],
            category=self.db.get_category(name),
            is_idempotent=self.db.is_idempotent(name),
        )

        # Feed to detector
        new_findings = self.detector.feed(event)

        # Live reporting
        if self.verbose:
            self.reporter.log_syscall(event)

        if not self.quiet:
            for finding in new_findings:
                self.reporter.log_finding(finding)


def run_from_env():
    """Entrypoint when invoked inside GDB."""
    raw_cfg = os.environ.get("OVERSEER_CONFIG", "{}")
    try:
        config = json.loads(raw_cfg)
    except Exception:
        config = {}
    tracker = GDBTracker(config)
    tracker.run()


if __name__ == "__main__" or (gdb and hasattr(gdb, "execute")):
    if os.environ.get("OVERSEER_CONFIG"):
        run_from_env()
