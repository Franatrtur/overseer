"""
Interactive GDB extension commands.
Allows users inside an active GDB session to run:
    (gdb) source /path/to/overseer/gdb_extension.py
    (gdb) flag-dup-syscalls
"""

import sys

try:
    import gdb
except ImportError:
    gdb = None

if gdb:
    from overseer.tracker import GDBTracker

    _active_tracker = None

    class FlagDupSyscallsCommand(gdb.Command):
        """Enable Overseer duplicated syscall flagging in the current session.
        Usage: flag-dup-syscalls [--window N] [--consecutive-only] [--verbose]
        """

        def __init__(self):
            super().__init__("flag-dup-syscalls", gdb.COMMAND_USER)

        def invoke(self, arg, from_tty):
            global _active_tracker
            args = arg.split()
            consecutive = "--consecutive-only" in args
            verbose = "--verbose" in args or "-v" in args
            window = 15
            for i, a in enumerate(args):
                if a == "--window" and i + 1 < len(args):
                    try:
                        window = int(args[i + 1])
                    except ValueError:
                        pass

            config = {
                "target": "interactive",
                "consecutive_only": consecutive,
                "window_size": window,
                "verbose": verbose,
                "from_start": True,
            }
            _active_tracker = GDBTracker(config)
            print(f"[Overseer] Duplicate syscall detection activated (window={window}, consecutive_only={consecutive}).")
            _active_tracker.run()

    class DupSyscallsReportCommand(gdb.Command):
        """Display the summary report of duplicated syscalls captured so far."""

        def __init__(self):
            super().__init__("dup-syscalls-report", gdb.COMMAND_USER)

        def invoke(self, arg, from_tty):
            global _active_tracker
            if not _active_tracker:
                print("[Overseer] No active tracker session. Run 'flag-dup-syscalls' first.")
                return
            rep = _active_tracker.detector.generate_report("interactive")
            _active_tracker.reporter.print_summary(rep)

    FlagDupSyscallsCommand()
    DupSyscallsReportCommand()
