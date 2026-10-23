# Overseer

Dynamic binary analysis and profiling tool that connects to **GDB** to detect redundant syscalls, stateful I/O inefficiencies, anti-debugging evasion, and suspicious memory modifications with full source stack traces.

---

## Features

- **Syscall Deduplication & Profiling**: Flags consecutive duplicates, failing streaks (e.g. repeated `-ENOENT`), windowed repetitions, and redundant queries with exact source file and line numbers.
- **Stateful Resource Tracking**: Tracks file descriptor offsets and path mutations to distinguish truly wasteful queries (`fstat -> fstat`, redundant `lseek`) from justified cache-invalidating calls (`fstat -> write -> fstat`, `lseek -> read -> lseek`). Catches double-close bugs.
- **Malicious Signature Detection & Active Defense**:
  - **Memory Dumping**: Detects W^X violations (`PROT_WRITE | PROT_EXEC`) in `mmap`/`mprotect` and anonymous executable allocations, automatically dumping suspicious memory regions to disk (`overseer_dumps/`).
  - **Anti-Debug Neutralization**: Intercepts `ptrace(PTRACE_TRACEME)` and `prctl(PR_SET_DUMPABLE)` evasion; neutralizes detection by spoofing return registers in GDB to `0` (Success).
  - **Tampering & Fileless Execution**: Detects `memfd_create`, `/proc/self/mem` access, and self-unlinking (`/proc/self/exe`).
- **Multi-Architecture**: Supports `x86_64`, `i386`, `aarch64`, `arm`, and `riscv64`.
- **Reporting & Export**: Rich colored terminal tables and structured JSON reports.

---

## Installation

Requires Python 3.8+ and standard GDB with Python support (`gdb`).

```bash
git clone https://github.com/Chaos/overseer.git
cd overseer
pip install -e .
```

---

## Quick Start

```bash
# Trace target binary starting at main()
overseer run ./my_binary

# Flag immediate consecutive duplicates only
overseer run --consecutive-only ./my_binary

# Custom sliding window (default: 15)
overseer run --window 25 ./my_binary

# Filter or exclude specific syscalls
overseer run --filter openat,read,write,close ./my_binary

# Export structured JSON report
overseer run --json report.json ./my_binary

# Attach to running process or remote gdbserver
overseer attach 1234
overseer connect localhost:1234 --binary ./my_binary
```

Inside an active GDB session:
```gdb
(gdb) source /path/to/overseer/overseer/gdb_extension.py
(gdb) flag-dup-syscalls --window 15
(gdb) dup-syscalls-report
```

---

## CLI Options

| Option | Description | Default |
|---|---|---|
| `run <bin> [args...]` | Run binary under GDB | - |
| `attach <pid>` | Attach to existing PID | - |
| `connect <host:port>` | Connect to remote gdbserver | - |
| `--consecutive-only` | Flag only consecutive duplicates | `False` |
| `--window <N>` | Duplicate sliding window size | `15` |
| `--start-at <SYM>` | Start tracing at symbol | `main` |
| `--from-start` | Trace from `_start` (includes ld.so) | `False` |
| `--filter <list>` | Syscalls to include | All |
| `--exclude <list>` | Syscalls to ignore | None |
| `--dump-dir <DIR>` | Directory for executable memory dumps | `overseer_dumps` |
| `--no-dump` | Disable dumping of executable memory | `False` |
| `--no-neutralize` | Disable anti-debug return spoofing | `False` |
| `--no-security` | Disable malicious signature detection | `False` |
| `--json <path>` | Save report to JSON file | None |
| `-v, --verbose` | Stream every syscall in real time | `False` |
| `-q, --quiet` | Suppress live alerts, show summary only | `False` |

---

## Testing & CI/CD

Run test suite:
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

CI/CD workflows in `.github/workflows/`:
- **`sbom.yml`**: Generates CycloneDX and SPDX Software Bill of Materials via Anchore `syft` and scans dependencies with `grype`.
- **`ci.yml`**: Automated matrix testing across Python versions.
