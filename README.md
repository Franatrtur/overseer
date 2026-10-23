# Overseer: GDB-Powered Duplicate Syscall Detector

**Overseer** is a dynamic binary analysis and profiling tool written in Python that connects to **GDB** (GNU Debugger) to trace syscall execution and automatically flag duplicated, redundant, and failing syscalls with full source code backtraces.

---

## Key Features

- **GDB Integration**:
  - Connects to targets by spawning them (`run`), attaching to running processes (`attach <PID>`), or connecting to remote debuggers (`connect host:port`).
  - Seamlessly works as an external Python CLI, a standalone library, or as an interactive extension inside active GDB sessions (`(gdb) flag-dup-syscalls`).
- **Comprehensive Duplicate Syscall Flagging**:
  - **Consecutive Duplicates**: Flags immediate back-to-back repetitions of identical syscalls (e.g., redundant `getpid()`, repeated `mprotect()`).
  - **Dangerous / Buggy Duplicates**: Flags fatal patterns like consecutive `close(fd)` calls that fail with `-EBADF` (double-close bugs).
  - **Idempotent Query Redundancy**: Identifies repeated read-only queries (`stat`, `access`, `readlink`, `getcwd`, `uname`) on unchanged targets within a sliding window.
  - **Failing Streaks**: Detects repeated failing calls (e.g. loops querying nonexistent resources returning `-ENOENT` or `-EACCES`).
  - **Sliding-Window Matching**: Configurable window distance tracking for non-consecutive duplicates.
- **Deep Context Extraction**:
  - Dereferences user memory for file paths (e.g. `openat`, `stat`, `unlink`, `rename`), handles file descriptors (including `AT_FDCWD`), flags, modes, and offsets.
  - Walks the GDB call stack to report the exact function name, source file, and line number in your application.
  - Formats Linux errno return values (e.g. `-2 (ENOENT)`, `-9 (EBADF)`).
- **Multi-Threaded Support**:
  - Tracks syscall entries and returns independently per thread (LWP), correctly isolating thread-specific streaks while enabling cross-thread analysis.
- **Multi-Architecture**:
  - Supports `x86_64`, `i386`, `aarch64`, `arm`, and `riscv64` calling conventions.
- **Rich Terminal UI & JSON Export**:
  - Real-time colored panel alerts for critical issues.
  - Full aggregate summary table with duplicate frequency rates.
  - Structured JSON export for CI/CD regression tests and security audits.

---

## Installation

Overseer requires Python 3.8+ and standard GDB with Python support (`gdb`).

```bash
git clone https://github.com/Chaos/overseer.git # or local folder
cd overseer
pip install -e .
```

Dependencies:
- `rich` (for terminal formatting; falls back to standard text if absent)

---

## Usage

### 1. Tracing a Local Program

Run a target binary starting from `main()`:
```bash
./overseer.py run ./my_program
# or
python3 -m overseer run ./my_program --arg1 foo --arg2 bar
```

### 2. Flagging Immediate Consecutive Duplicates Only

```bash
./overseer.py run --consecutive-only ./my_program
```

### 3. Adjusting Duplicate Sliding Window

Monitor for duplicate syscalls occurring within a 30-syscall window:
```bash
./overseer.py run --window 30 ./my_program
```

### 4. Full Startup Tracing (Dynamic Linker & Libc)

By default, Overseer skips dynamic linker initialization and begins tracking at `main()`. To trace everything from `_start`:
```bash
./overseer.py run --from-start ./my_program
```

### 5. Filtering Specific Syscalls

Include only specific syscalls:
```bash
./overseer.py run --filter openat,close,stat,access ./my_program
```

Exclude noisy syscalls:
```bash
./overseer.py run --exclude rt_sigaction,rt_sigprocmask ./my_program
```

### 6. Attaching to a Running Process

```bash
./overseer.py attach <PID>
```

### 7. Connecting to Remote GDBServer

```bash
# In target machine: gdbserver :1234 ./my_program
# In host:
./overseer.py connect localhost:1234 --binary ./my_program
```

### 8. Exporting Structured JSON Reports

```bash
./overseer.py run --json report.json ./my_program
```

The output JSON includes complete call sequences, argument key-values, return codes, stack traces, and duplicate breakdown statistics.

---

## Interactive GDB Extension

You can also use Overseer directly inside an existing GDB session:

```bash
gdb ./my_program
(gdb) source /path/to/overseer/overseer/gdb_extension.py
(gdb) flag-dup-syscalls --window 15
(gdb) dup-syscalls-report
```

---

## Programmatic Python API

You can integrate Overseer into your own Python scripts:

```python
from overseer.connector import GDBConnector
from overseer.detector import SyscallDetector

connector = GDBConnector()
config = {
    "start_at": "main",
    "window_size": 20,
    "consecutive_only": False,
    "json_path": "report.json",
}
exit_code = connector.run_target("./my_program", args=["--demo"], config=config)
```

---

## CLI Options Reference

| Option | Description | Default |
|---|---|---|
| `run <bin> [args...]` | Run binary under GDB | - |
| `attach <pid>` | Attach to existing PID | - |
| `connect <host:port>` | Connect to remote gdbserver | - |
| `--consecutive-only` | Flag only consecutive duplicates | `False` |
| `--window <N>` | Sliding window distance | `15` |
| `--min-repeats <N>` | Repeat count threshold | `2` |
| `--start-at <SYM>` | Symbol to start tracing at | `main` |
| `--from-start` | Trace from binary entry (`_start`) | `False` |
| `--filter <list>` | Comma-separated syscalls to include | None |
| `--exclude <list>` | Comma-separated syscalls to ignore | None |
| `--pty` | Run target with a pseudo-terminal (PTY) attached | `False` |
| `--json <path>` | Write JSON report to path | None |
| `--verbose`, `-v` | Real-time live log of every syscall | `False` |
| `--quiet`, `-q` | Suppress live alerts, show summary | `False` |
| `--no-threads` | Aggregate tracking across all threads | Per-thread |

---

## Running Tests

Overseer includes a full automated test suite with real compiled test binaries:

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```
