"""
Command-line interface for Overseer.
"""

import argparse
import os
import sys
from typing import List, Optional

from overseer.connector import GDBConnector


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="overseer",
        description="Overseer: Connect to GDB and flag duplicated, redundant, and failing syscalls.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run and trace a program starting from main()
  overseer run ./my_binary --arg1 --arg2

  # Trace starting from binary entry point (_start) including dynamic loader
  overseer run --from-start ./my_binary

  # Flag only immediate consecutive duplicate syscalls
  overseer run --consecutive-only ./my_binary

  # Trace with a larger duplicate detection window
  overseer run --window 30 ./my_binary

  # Filter specific syscalls and output JSON report
  overseer run --filter openat,close,statx --json report.json ./my_binary

  # Attach to an already running process
  overseer attach 12345

  # Connect to a remote gdbserver
  overseer connect localhost:1234 --binary ./my_binary
        """,
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Overseer mode of operation")

    # Run subcommand
    run_p = subparsers.add_parser("run", help="Run a program under GDB and monitor syscalls")
    _add_common_tracing_args(run_p)
    run_p.add_argument("binary", help="Target executable path")
    run_p.add_argument("args", nargs=argparse.REMAINDER, help="Arguments passed to the target executable")

    # Attach subcommand
    attach_p = subparsers.add_parser("attach", help="Attach to a running process PID")
    _add_common_tracing_args(attach_p)
    attach_p.add_argument("pid", type=int, help="Target process PID")

    # Connect subcommand
    conn_p = subparsers.add_parser("connect", help="Connect to a remote gdbserver")
    _add_common_tracing_args(conn_p)
    conn_p.add_argument("host_port", help="Remote gdbserver host:port (e.g. localhost:1234)")
    conn_p.add_argument("--binary", "-b", help="Target binary path for symbol resolution")

    return parser


def _add_common_tracing_args(p: argparse.ArgumentParser):
    p.add_argument(
        "--consecutive-only",
        action="store_true",
        help="Only flag immediate back-to-back duplicate syscalls",
    )
    p.add_argument(
        "--window",
        type=int,
        default=15,
        help="Sliding window size for detecting repeated syscalls (default: 15)",
    )
    p.add_argument(
        "--min-repeats",
        type=int,
        default=2,
        help="Minimum repeat count required to flag (default: 2)",
    )
    p.add_argument(
        "--start-at",
        default="main",
        help="Symbol to start tracing at (default: 'main')",
    )
    p.add_argument(
        "--from-start",
        action="store_true",
        help="Trace from binary entry point (_start), capturing ld.so calls",
    )
    p.add_argument(
        "--filter",
        help="Comma-separated syscall names to include (e.g. openat,read,close)",
    )
    p.add_argument(
        "--exclude",
        help="Comma-separated syscall names to ignore",
    )
    p.add_argument(
        "--json",
        dest="json_path",
        help="Save report to JSON file",
    )
    p.add_argument(
        "--no-threads",
        action="store_true",
        help="Aggregate syscall tracking globally instead of per thread",
    )
    p.add_argument(
        "--pty",
        action="store_true",
        help="Run target process with a pseudo-terminal (PTY) attached to stdin/stdout",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print every intercepted syscall in real time",
    )
    p.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Quiet mode: do not print live alerts, only print final summary",
    )
    p.add_argument(
        "--gdb-path",
        help="Path to gdb executable (default: search PATH)",
    )
    p.add_argument(
        "--no-security",
        action="store_true",
        help="Disable malicious syscall signature detection",
    )
    p.add_argument(
        "--dump-dir",
        default="overseer_dumps",
        help="Directory to dump suspicious executable memory regions (default: 'overseer_dumps')",
    )
    p.add_argument(
        "--no-dump",
        action="store_true",
        help="Disable dumping of suspicious executable memory regions",
    )
    p.add_argument(
        "--no-neutralize",
        action="store_true",
        help="Disable active neutralization/spoofing of anti-debugging traps (e.g. ptrace TRACEME)",
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args_list = argv if argv is not None else sys.argv[1:]

    # Convenience shortcut: if first arg is an existing executable or starts with ./ or /, treat as 'run'
    if args_list and args_list[0] not in ("run", "attach", "connect", "-h", "--help"):
        if not args_list[0].startswith("-"):
            args_list = ["run"] + args_list

    parsed = parser.parse_args(args_list)

    if not parsed.subcommand:
        parser.print_help()
        return 1

    try:
        connector = GDBConnector(gdb_path=parsed.gdb_path)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    filter_sc = [x.strip() for x in parsed.filter.split(",")] if parsed.filter else None
    exclude_sc = [x.strip() for x in parsed.exclude.split(",")] if parsed.exclude else None

    config = {
        "consecutive_only": parsed.consecutive_only,
        "window_size": parsed.window,
        "min_repeats": parsed.min_repeats,
        "start_at": parsed.start_at,
        "from_start": parsed.from_start,
        "filter_syscalls": filter_sc,
        "exclude_syscalls": exclude_sc,
        "per_thread": not parsed.no_threads,
        "pty": parsed.pty,
        "verbose": parsed.verbose,
        "quiet": parsed.quiet,
        "json_path": parsed.json_path,
        "detect_malware": not parsed.no_security,
        "dump_executable_memory": not parsed.no_dump,
        "dump_dir": parsed.dump_dir,
        "neutralize_anti_debug": not parsed.no_neutralize,
    }

    if parsed.subcommand == "run":
        target_args = parsed.args
        # Strip leading '--' if passed
        if target_args and target_args[0] == "--":
            target_args = target_args[1:]
        return connector.run_target(parsed.binary, target_args, config)

    elif parsed.subcommand == "attach":
        return connector.attach_pid(parsed.pid, config)

    elif parsed.subcommand == "connect":
        return connector.connect_remote(parsed.host_port, parsed.binary, config)

    return 0


if __name__ == "__main__":
    sys.exit(main())
