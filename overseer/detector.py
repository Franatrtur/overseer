"""
Duplicate syscall detection engine.
Analyzes syscall streams in real-time or batch to flag redundant,
consecutive, windowed, and failing syscall patterns.
"""

from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Set, Tuple

from overseer.models import (
    DuplicateFinding,
    FindingKind,
    Severity,
    SyscallEvent,
    SyscallReport,
)
from overseer.security import SecurityEngine
from overseer.state import StateManager


class SyscallDetector:
    """
    Stateful detector analyzing a stream of SyscallEvent objects.
    """

    def __init__(
        self,
        consecutive_only: bool = False,
        window_size: int = 15,
        min_repeats: int = 2,
        filter_syscalls: Optional[Set[str]] = None,
        exclude_syscalls: Optional[Set[str]] = None,
        per_thread: bool = True,
        ignore_loader_noise: bool = False,
        enable_security: bool = True,
        dump_executable_memory: bool = True,
        dump_dir: str = "overseer_dumps",
        neutralize_anti_debug: bool = True,
    ):
        self.consecutive_only = consecutive_only
        self.window_size = max(2, window_size)
        self.min_repeats = min_repeats
        self.filter_syscalls = filter_syscalls
        self.exclude_syscalls = exclude_syscalls or set()
        self.per_thread = per_thread
        self.ignore_loader_noise = ignore_loader_noise

        # Noise syscalls from ld.so when starting from _start
        self.loader_noise = {
            "arch_prctl", "set_tid_address", "set_robust_list", "rseq",
            "prlimit64"
        }

        # Tracking state
        self.events: List[SyscallEvent] = []
        self.findings: List[DuplicateFinding] = []
        self.state_manager = StateManager()
        self.security_engine = SecurityEngine(
            enabled=enable_security,
            dump_executable_memory=dump_executable_memory,
            dump_dir=dump_dir,
            neutralize_anti_debug=neutralize_anti_debug,
        )

        # Last event per thread (or global thread 0 if not per_thread)
        self.last_events: Dict[int, SyscallEvent] = {}

        # Sliding window of recent events per thread
        self.sliding_windows: Dict[int, Deque[SyscallEvent]] = defaultdict(
            lambda: deque(maxlen=self.window_size)
        )

        # Global counters
        self.syscall_counts: Dict[str, int] = defaultdict(int)
        self.duplicate_counts: Dict[str, int] = defaultdict(int)
        self.error_counts: Dict[str, int] = defaultdict(int)

        # Failure tracker: (thread_id, signature_key) -> count
        self.failing_streaks: Dict[Tuple[int, Any], int] = defaultdict(int)

        # Global signature history: signature_key -> list of event sequences
        self.signature_history: Dict[Any, List[int]] = defaultdict(list)

    def should_analyze(self, event: SyscallEvent) -> bool:
        """Check if an event matches filter and exclude criteria."""
        if self.filter_syscalls and event.name not in self.filter_syscalls:
            return False
        if event.name in self.exclude_syscalls:
            return False
        if self.ignore_loader_noise and event.name in self.loader_noise:
            return False
        return True

    def feed(self, event: SyscallEvent) -> List[DuplicateFinding]:
        """
        Process a new completed SyscallEvent and return any new duplicate findings.
        """
        self.events.append(event)
        self.syscall_counts[event.name] += 1
        if event.is_error:
            self.error_counts[event.name] += 1

        if not self.should_analyze(event):
            return []

        tid = event.thread_id if self.per_thread else 0
        window = self.sliding_windows[tid]
        last_event = self.last_events.get(tid)
        sig_key = event.signature_key

        new_findings: List[DuplicateFinding] = []

        # 1. Malicious signature and evasion detection
        sec_findings = self.security_engine.analyze_event(event)
        for sf in sec_findings:
            new_findings.append(sf)
            self.duplicate_counts[event.name] += 1

        # 2. Stateful resource tracking
        state_findings, is_state_handled = self.state_manager.process_event(event)

        for sf in state_findings:
            if self.consecutive_only and sf.kind in (
                FindingKind.STATEFUL_REDUNDANT_QUERY,
                FindingKind.STATEFUL_REDUNDANT_SEEK,
            ):
                # If consecutive_only mode, only flag if it was an immediate repetition
                if not (last_event and last_event.signature_key == sig_key):
                    continue
            new_findings.append(sf)
            self.duplicate_counts[event.name] += 1

        already_state_flagged = len(new_findings) > 0

        # Check Consecutive Duplicate
        is_consecutive = False
        if last_event and last_event.signature_key == sig_key and not is_state_handled and not already_state_flagged:
            is_consecutive = True
            self.duplicate_counts[event.name] += 1

            # Determine severity and message
            if event.is_error and last_event.is_error:
                severity = Severity.ERROR
                msg = (
                    f"Consecutive FAILING call to {event.name}: "
                    f"both failed with {event.ret_str} at {event.location or 'unknown'}"
                )
            elif event.name == "close" and event.is_error:
                severity = Severity.ERROR
                msg = (
                    f"Duplicate close({event.decoded_args.get('fd', '?')}): "
                    f"second call failed with {event.ret_str} (possible double close bug)"
                )
            elif event.is_idempotent:
                severity = Severity.WARNING
                msg = (
                    f"Consecutive redundant query {event.name}: "
                    f"identical return value {event.ret_str} (consider caching)"
                )
            else:
                severity = Severity.WARNING
                msg = f"Consecutive identical syscall: {event.format_call()}"

            finding = DuplicateFinding(
                kind=FindingKind.CONSECUTIVE,
                severity=severity,
                message=msg,
                current_event=event,
                previous_event=last_event,
                window_distance=1,
                repeat_count=2,
            )
            new_findings.append(finding)

        # Check Failing Streak
        fail_key = (tid, sig_key)
        if event.is_error:
            self.failing_streaks[fail_key] += 1
            fail_count = self.failing_streaks[fail_key]
            # Flag if failed repeatedly and not just reported as consecutive
            if fail_count >= 3 and not is_consecutive:
                finding = DuplicateFinding(
                    kind=FindingKind.FAILING,
                    severity=Severity.ERROR,
                    message=(
                        f"Syscall {event.name} has failed {fail_count} times in a row "
                        f"with {event.ret_str} for args: {event.format_call()}"
                    ),
                    current_event=event,
                    previous_event=last_event or event,
                    repeat_count=fail_count,
                )
                new_findings.append(finding)
        else:
            self.failing_streaks[fail_key] = 0

        # Check Windowed Duplicate (if not consecutive and not consecutive_only)
        if not is_consecutive and not self.consecutive_only and not is_state_handled and not already_state_flagged:
            # Look back in sliding window
            match_event = None
            dist = 0
            for i, prev in enumerate(reversed(window)):
                if prev.signature_key == sig_key:
                    match_event = prev
                    dist = i + 1
                    break

            if match_event is not None:
                self.duplicate_counts[event.name] += 1
                if event.is_idempotent:
                    severity = Severity.WARNING
                    msg = (
                        f"Redundant query {event.name} within window (dist={dist}): "
                        f"{event.format_call()} returned {event.ret_str}"
                    )
                    kind = FindingKind.IDEMPOTENT_QUERY
                else:
                    severity = Severity.INFO
                    msg = (
                        f"Duplicate syscall within window (dist={dist}): "
                        f"{event.format_call()}"
                    )
                    kind = FindingKind.WINDOWED

                finding = DuplicateFinding(
                    kind=kind,
                    severity=severity,
                    message=msg,
                    current_event=event,
                    previous_event=match_event,
                    window_distance=dist,
                    repeat_count=2,
                )
                new_findings.append(finding)

        # Update sliding window and state
        window.append(event)
        self.last_events[tid] = event
        self.signature_history[sig_key].append(event.sequence)
        self.findings.extend(new_findings)

        return new_findings

    def generate_report(self, target_binary: str, duration: float = 0.0) -> SyscallReport:
        """Create a final aggregated SyscallReport."""
        return SyscallReport(
            target=target_binary,
            total_syscalls=len(self.events),
            unique_syscalls=len(self.syscall_counts),
            findings=self.findings,
            syscall_counts=dict(self.syscall_counts),
            duplicate_counts=dict(self.duplicate_counts),
            error_counts=dict(self.error_counts),
            duration_seconds=duration,
        )
