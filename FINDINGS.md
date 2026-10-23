# PB152 Syscall Duplicate & Efficiency Analysis Report

This document summarizes the findings obtained by running **Overseer** (GDB-powered dynamic syscall duplicate detector) against representative programs from the **PB152 (Operating Systems)** coursework.

---

## Executive Summary

| Program | Syscall Pattern Flagged | Kind / Severity | Duplicate Rate | Root Cause / Note |
|---|---|---|---|---|
| [`01/p3_catfd.c`](pb152/01/p3_catfd.c) | `write(out_fd, buf, 0)` | `WINDOWED` (`INFO`) | 66.7% | `do..while` executes a redundant 0-byte write on EOF |
| [`04/p1_sum.c`](pb152/04/p1_sum.c) | `mmap(..., 0, ...)` &rarr; `-EINVAL` | `FAILING` / `SIGABRT` | N/A | Linux kernel rejects `length == 0` with `EINVAL`, aborting real execution |
| [`01/p1_count.c`](pb152/01/p1_count.c) | `read(..., 16)` | `CONSECUTIVE` (`WARNING`) | 90.9% read | 16-byte micro-buffering generates repeated tiny syscalls |
| [`01/p4_pick.c`](pb152/01/p4_pick.c) | `read(..., 1)` / `write(..., 1)` | `WINDOWED` (`INFO`) | 73.7% read / 80% write | 1-byte unbuffered I/O loops |
| [`08/p1_shell.c`](pb152/08/p1_shell.c) | `close(...) -> -9 (EBADF)` | `WINDOWED` / `FAILING` | 77.8% | Repeated closing of already-closed descriptors |
| [`06/p2_access.c`](pb152/06/p2_access.c) | `newfstatat(...)` | `IDEMPOTENT_QUERY` (`WARNING`) | 72.7% | Repeated inode stat queries on unchanged files across test assertions |

---

## Detailed Findings

### 1. `pb152/01/p3_catfd.c`: Redundant 0-byte `write()` on every EOF

#### Location
- Function: `catfd()` in [`pb152/01/p3_catfd.c`](pb152/01/p3_catfd.c)

#### Code Excerpt
```c
int bytes_read = 0;
do {
    bytes_read = read(fd_in, buffer, nbytes);
    if (bytes_read == -1) return -1;

    if (write(out_fd, buffer, bytes_read) == -1)
        return -1;
} while(bytes_read);
```

#### Overseer Finding
Overseer captured repetitive zero-byte write calls:
```text
#0048 INFO windowed read(fd=3, buf="...", count=256) -> 0
#0049 INFO windowed write(fd=4, buf="...", count=0)  -> 0 [catfd at p3_catfd.c:45]
#0052 INFO windowed read(fd=3, buf="...", count=256) -> 0
#0053 INFO windowed write(fd=4, buf="...", count=0)  -> 0 [catfd at p3_catfd.c:45]
```

#### Analysis & Fix
Because a `do ... while (bytes_read)` loop executes its body before testing the condition, when `read()` reaches EOF and returns `0`, the program immediately issues `write(out_fd, buffer, 0)` before breaking out of the loop.

While POSIX allows `write(fd, buf, 0)` as a no-op that validates the file descriptor, this incurs an unnecessary kernel transition on every file processed.

**Recommended Pattern:**
```c
while ((bytes_read = read(fd_in, buffer, nbytes)) > 0) {
    if (write(out_fd, buffer, bytes_read) == -1)
        return -1;
}
if (bytes_read == -1)
    return -1;
```

---

### 2. `pb152/04/p1_sum.c`: Real Linux Kernel Abort on `mmap(..., len = 0)`

#### Location
- Function: `sum()` in [`pb152/04/p1_sum.c`](pb152/04/p1_sum.c)

#### Code Excerpt
```c
ssize_t len = lseek(fd, 0, SEEK_END);
if ( len == -1 )
    return -1;

if ( len % row_size != 0 )
    return -2;

uint8_t *base = mmap( NULL, len, PROT_READ, MAP_PRIVATE, fd, 0 );
if ( base == MAP_FAILED )
    return -1;
```

#### Overseer Finding
When run as a native binary directly against the Linux kernel, the program crashed:
```text
p1_sum_real: pb152/04/p1_sum.c:148: main: Assertion `sum( fd, 1, sizes, res ) == 0' failed.
Program terminated with signal SIGABRT, Aborted.
```

#### Analysis & Fix
The test suite explicitly tests an empty table:
```c
/* An empty file is a valid input. */
assert( sum( fd, 1, sizes, res ) == 0 );
```
For an empty file, `len == 0`. The remainder check `0 % row_size == 0` succeeds, leading directly to:
```c
mmap( NULL, 0, PROT_READ, MAP_PRIVATE, fd, 0 );
```
According to POSIX and Linux kernel specifications, calling `mmap()` with `length == 0` must fail with `-EINVAL` (`MAP_FAILED`). As a result, `sum()` returns `-1` (error) instead of `0` (success), causing the assertion to abort.

The course's hooked emulation library (`pb152.cpp`) mocked `mmap` or tolerated zero-length requests, masking the real-world bug.

**Recommended Fix:**
```c
if ( len == 0 ) {
    for ( int c = 0; c < cols; c++ )
        results[ c ] = 0;
    return 0;
}
```

Once guarded, the test passes natively. Overseer then reveals that `lseek(..., SEEK_END)` has a **90% duplicate rate** and `mmap`/`munmap` an **87.5% duplicate rate** across query assertions.

---

### 3. `pb152/01/p1_count.c` & `p4_pick.c`: Micro-buffering & 1-byte Syscall Loops

#### Code Excerpts
In [`pb152/01/p1_count.c`](pb152/01/p1_count.c):
```c
enum { nbytes = 16 };
char buffer[ nbytes ];
...
bytes_read = read( fd, buffer, nbytes );
```

In [`pb152/01/p4_pick.c`](pb152/01/p4_pick.c):
```c
int toread = (unsigned)(len - i) >= sizeof(buffer) ? sizeof(buffer) : len - i;
bytes_read = read( fd_in, buffer, toread );
...
write( fd_out, buffer + copyfrom, copyto - copyfrom );
```

#### Overseer Finding
- `p1_count`: **90.9% duplicate `read` rate**.
- `p4_pick`: **73.7% duplicate `read` rate** and **80.0% duplicate `write` rate**, with consecutive alternating 1-byte read/write calls:
```text
#0009 INFO windowed read(fd=3, buf="...", count=1)  -> 1 [pick at p4_pick.c:53]
#0010 INFO windowed write(fd=4, buf="...", count=1) -> 1 [pick at p4_pick.c:72]
#0011 INFO windowed read(fd=3, buf="...", count=1)  -> 1 [pick at p4_pick.c:53]
#0012 INFO windowed write(fd=4, buf="...", count=1) -> 1 [pick at p4_pick.c:72]
```

#### Analysis & Fix
While micro-buffers comply with the assignment constraint requiring constant memory usage, processing streams in 1-byte or 16-byte chunks incurs massive overhead due to repeated user-kernel context switching.

Standard page-aligned chunks (e.g., 4096 or 8192 bytes) remain strictly $O(1)$ constant memory while reducing the syscall volume by ~95%.

---

### 4. `pb152/08/p1_shell.c`: Multiple `close()` Calls Failing with `-EBADF`

#### Location
- [`pb152/08/p1_shell.c`](pb152/08/p1_shell.c)

#### Overseer Finding
Overseer identified 9 distinct calls to `close()` that failed with `-EBADF` (**77.8% duplicate rate**):
```text
#0046 INFO windowed close(fd=...) -> -9 (EBADF)
#0047 INFO windowed close(fd=...) -> -9 (EBADF)
#0048 INFO windowed close(fd=...) -> -9 (EBADF)
#0084 INFO windowed close(fd=...) -> -9 (EBADF)
#0085 INFO windowed close(fd=...) -> -9 (EBADF)
#0086 INFO windowed close(fd=...) -> -9 (EBADF)
```

#### Analysis & Fix
In process execution workflows involving pipes and forks, file descriptors were repeatedly closed after they were already closed.

While often harmless in single-threaded toy scripts, double-closing file descriptors is a notorious bug in concurrent programs: a thread might allocate a new socket or file that receives the recently recycled descriptor, which is then prematurely closed by the redundant `close()` call.

---

### 5. `pb152/06/p2_access.c`: Uncached `newfstatat` Queries

#### Location
- Function: `check_access()` in [`pb152/06/p2_access.c`](pb152/06/p2_access.c)

#### Overseer Finding
Overseer reported a **72.7% duplicate rate on `newfstatat`**:
```text
#0035 WARNING idempotent_query newfstatat(dirfd="AT_FDCWD", path="zt.p2_a", ...) -> 0
#0036 WARNING idempotent_query newfstatat(dirfd="AT_FDCWD", path="zt.p2_b", ...) -> 0
#0037 WARNING idempotent_query newfstatat(dirfd="AT_FDCWD", path="zt.p2_c", ...) -> 0
#0038 WARNING idempotent_query newfstatat(dirfd="AT_FDCWD", path="zt.p2_d", ...) -> 0
```

#### Analysis & Fix
When verifying file permissions across multiple checks on the same directory contents, `check_access()` issues fresh `fstatat` syscalls for each name in the linked list without caching. In workloads traversing larger directories, caching inode status structures in userspace avoids redundant kernel directory traversal.
