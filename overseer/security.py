"""
Security engine for detecting malicious syscall signatures and evasion techniques:
- Suspicious executable memory allocations/modifications (mmap/mprotect with PROT_EXEC and W^X violation)
  followed by automatic dumping of the memory region to disk for forensic inspection.
- Anti-debugging techniques (e.g. ptrace PTRACE_TRACEME, prctl PR_SET_DUMPABLE=0, /proc/self/status inspection)
  with active return code spoofing/neutralization so the target program continues execution.
- Fileless binary execution (memfd_create staging).
- Anti-forensics and process memory tampering (/proc/self/mem, self-deletion via /proc/self/exe).
"""

import os
from typing import Any, Dict, List, Optional

from overseer.models import (
    DuplicateFinding,
    FindingKind,
    Severity,
    SyscallEvent,
)


class SecurityEngine:
    """
    Evaluates syscall streams against malicious behavioral signatures,
    coordinates active defense actions (memory dumping, anti-debug neutralization),
    and logs detailed security findings.
    """

    def __init__(
        self,
        enabled: bool = True,
        dump_executable_memory: bool = True,
        dump_dir: str = "overseer_dumps",
        neutralize_anti_debug: bool = True,
    ):
        self.enabled = enabled
        self.dump_executable_memory = dump_executable_memory
        self.dump_dir = dump_dir
        self.neutralize_anti_debug = neutralize_anti_debug
        self.dumped_files: List[str] = []

    def analyze_event(self, event: SyscallEvent) -> List[DuplicateFinding]:
        """
        Analyze a completed syscall event for malicious or evasive behaviors.
        Returns a list of security findings.
        """
        if not self.enabled:
            return []

        findings: List[DuplicateFinding] = []
        name = event.name
        args = event.decoded_args
        raw_args = event.args

        # -------------------------------------------------------------
        # 1. Suspicious Executable Memory (mmap)
        # -------------------------------------------------------------
        if name in ("mmap", "mmap2"):
            prot_raw = raw_args[2] if len(raw_args) > 2 else 0
            flags_raw = raw_args[3] if len(raw_args) > 3 else 0
            length = args.get("length", raw_args[1] if len(raw_args) > 1 else 4096)
            prot_str = str(args.get("prot", ""))
            flags_str = str(args.get("flags", ""))

            # PROT_EXEC is bit 0x4
            is_exec = bool(prot_raw & 0x4) or ("PROT_EXEC" in prot_str)
            # PROT_WRITE is bit 0x2
            is_write = bool(prot_raw & 0x2) or ("PROT_WRITE" in prot_str)
            # MAP_ANONYMOUS is bit 0x20
            is_anon = bool(flags_raw & 0x20) or ("MAP_ANONYMOUS" in flags_str)

            if is_exec:
                # Target memory address is returned by mmap
                target_addr = event.ret_val if (event.ret_val is not None and event.ret_val > 0) else raw_args[0]
                if is_write:
                    # W^X Violation: RWX memory is a strong malware indicator
                    sev = Severity.CRITICAL
                    msg = (
                        f"Suspicious RWX memory allocation via mmap({args.get('addr', hex(raw_args[0]))}, "
                        f"len={length}, prot='{prot_str}'): violates W^X memory protection policy "
                        f"(classic shellcode / unpacker injection pattern)"
                    )
                elif is_anon:
                    sev = Severity.CRITICAL
                    msg = (
                        f"Suspicious anonymous executable memory allocation via mmap(len={length}, "
                        f"prot='{prot_str}', flags='{flags_str}'): anonymous executable region "
                        f"is frequently used for in-memory payload staging"
                    )
                else:
                    sev = Severity.WARNING
                    msg = f"Executable memory region mapped via mmap(len={length}, prot='{prot_str}')"

                finding = DuplicateFinding(
                    kind=FindingKind.MALICIOUS_EXECUTABLE_MEMORY,
                    severity=sev,
                    message=msg,
                    current_event=event,
                    previous_event=event,
                    details={
                        "security_alert": True,
                        "dump_requested": True,
                        "memory_addr": target_addr,
                        "memory_length": length,
                        "prot": prot_str,
                        "flags": flags_str,
                    },
                )
                findings.append(finding)

        # -------------------------------------------------------------
        # 2. Suspicious Executable Memory Transition (mprotect)
        # -------------------------------------------------------------
        elif name in ("mprotect", "pkey_mprotect"):
            prot_raw = raw_args[2] if len(raw_args) > 2 else 0
            length = args.get("length", raw_args[1] if len(raw_args) > 1 else 4096)
            prot_str = str(args.get("prot", ""))
            addr_val = raw_args[0] if len(raw_args) > 0 else 0

            is_exec = bool(prot_raw & 0x4) or ("PROT_EXEC" in prot_str)
            is_write = bool(prot_raw & 0x2) or ("PROT_WRITE" in prot_str)

            if is_exec:
                if is_write:
                    sev = Severity.CRITICAL
                    msg = (
                        f"Suspicious mprotect making memory region writable AND executable "
                        f"(addr={hex(addr_val)}, len={length}, prot='{prot_str}'): W^X violation"
                    )
                else:
                    sev = Severity.WARNING
                    msg = (
                        f"mprotect transitioning memory region to EXECUTABLE "
                        f"(addr={hex(addr_val)}, len={length}, prot='{prot_str}'): possible self-modifying code "
                        f"or decrypted payload execution"
                    )

                finding = DuplicateFinding(
                    kind=FindingKind.MALICIOUS_EXECUTABLE_MEMORY,
                    severity=sev,
                    message=msg,
                    current_event=event,
                    previous_event=event,
                    details={
                        "security_alert": True,
                        "dump_requested": True,
                        "memory_addr": addr_val,
                        "memory_length": length,
                        "prot": prot_str,
                    },
                )
                findings.append(finding)

        # -------------------------------------------------------------
        # 3. Anti-Debugging Evasion (ptrace PTRACE_TRACEME)
        # -------------------------------------------------------------
        elif name == "ptrace":
            req_raw = raw_args[0] if len(raw_args) > 0 else -1
            req_str = str(args.get("request", ""))

            # PTRACE_TRACEME is 0
            if req_raw == 0 or req_str == "PTRACE_TRACEME":
                finding = DuplicateFinding(
                    kind=FindingKind.MALICIOUS_ANTI_DEBUG,
                    severity=Severity.CRITICAL,
                    message=(
                        "Anti-debugging evasion detected: process invoked ptrace(PTRACE_TRACEME) "
                        "to detect debugger attachment"
                    ),
                    current_event=event,
                    previous_event=event,
                    details={
                        "security_alert": True,
                        "anti_debug": True,
                        "technique": "PTRACE_TRACEME",
                        "should_neutralize": True,
                        "neutralize_reg_val": 0,
                    },
                )
                findings.append(finding)

        # -------------------------------------------------------------
        # 4. Anti-Analysis / Anti-Dump (prctl PR_SET_DUMPABLE=0)
        # -------------------------------------------------------------
        elif name == "prctl":
            option_raw = raw_args[0] if len(raw_args) > 0 else -1
            option_str = str(args.get("option", ""))
            arg2_raw = raw_args[1] if len(raw_args) > 1 else -1

            # PR_SET_DUMPABLE is 3
            if (option_raw == 3 or option_str == "PR_SET_DUMPABLE") and arg2_raw == 0:
                finding = DuplicateFinding(
                    kind=FindingKind.MALICIOUS_ANTI_DEBUG,
                    severity=Severity.WARNING,
                    message=(
                        "Anti-analysis attempt: process invoked prctl(PR_SET_DUMPABLE, 0) "
                        "to prevent process memory dumping and debugger attachment"
                    ),
                    current_event=event,
                    previous_event=event,
                    details={
                        "security_alert": True,
                        "anti_debug": True,
                        "technique": "PR_SET_DUMPABLE",
                        "should_neutralize": True,
                        "neutralize_reg_val": 0,
                    },
                )
                findings.append(finding)

        # -------------------------------------------------------------
        # 5. In-Memory Fileless Binary Staging (memfd_create)
        # -------------------------------------------------------------
        elif name == "memfd_create":
            memfd_name = args.get("name", "unknown")
            finding = DuplicateFinding(
                kind=FindingKind.MALICIOUS_FILELESS_EXEC,
                severity=Severity.WARNING,
                message=(
                    f"In-memory anonymous file created via memfd_create('{memfd_name}'): "
                    f"common indicator of fileless ELF payload staging"
                ),
                current_event=event,
                previous_event=event,
                details={
                    "security_alert": True,
                    "fileless": True,
                    "memfd_name": memfd_name,
                },
            )
            findings.append(finding)

        # -------------------------------------------------------------
        # 6. Anti-Forensics & Process Memory Tampering
        # -------------------------------------------------------------
        elif name in ("open", "openat", "creat"):
            path = str(args.get("path", ""))
            if "/proc/self/mem" in path or "/proc/thread-self/mem" in path:
                finding = DuplicateFinding(
                    kind=FindingKind.MALICIOUS_TAMPERING,
                    severity=Severity.CRITICAL,
                    message=f"Process memory tampering detected: process opened '{path}'",
                    current_event=event,
                    previous_event=event,
                    details={"security_alert": True, "tampering": "proc_mem_access", "path": path},
                )
                findings.append(finding)
            elif "/proc/self/status" in path:
                finding = DuplicateFinding(
                    kind=FindingKind.MALICIOUS_ANTI_DEBUG,
                    severity=Severity.WARNING,
                    message=f"Process opened '{path}': likely inspecting TracerPid for debugger detection",
                    current_event=event,
                    previous_event=event,
                    details={"security_alert": True, "anti_debug": True, "technique": "proc_status_check"},
                )
                findings.append(finding)

        elif name in ("unlink", "unlinkat"):
            path = str(args.get("path", ""))
            if "/proc/self/exe" in path:
                finding = DuplicateFinding(
                    kind=FindingKind.MALICIOUS_TAMPERING,
                    severity=Severity.CRITICAL,
                    message="Anti-forensics self-deletion detected: attempted unlink on /proc/self/exe",
                    current_event=event,
                    previous_event=event,
                    details={"security_alert": True, "tampering": "self_delete", "path": path},
                )
                findings.append(finding)

        return findings

    def dump_memory(
        self,
        inferior: Any,
        addr: int,
        length: int,
        event: SyscallEvent,
    ) -> Optional[str]:
        """
        Safely dump memory region from inferior to a binary file on disk.
        Returns the absolute path of the dump file or None on error.
        """
        if not self.dump_executable_memory or not addr or addr == 0:
            return None

        # Sanity check address and limit dump size to 16MB max
        if addr > 0x7FFFFFFFFFFF:
            return None

        safe_len = min(length if length > 0 else 4096, 16 * 1024 * 1024)

        try:
            os.makedirs(self.dump_dir, exist_ok=True)
            mem = inferior.read_memory(addr, safe_len)
            mem_bytes = bytes(mem)

            filename = f"memdump_seq{event.sequence:04d}_{event.name}_0x{addr:x}_len{safe_len}.bin"
            dump_path = os.path.abspath(os.path.join(self.dump_dir, filename))

            with open(dump_path, "wb") as f:
                f.write(mem_bytes)

            self.dumped_files.append(dump_path)
            return dump_path
        except Exception:
            return None

    def neutralize_syscall(
        self,
        gdb_module: Any,
        arch: Any,
        event: SyscallEvent,
        finding: DuplicateFinding,
    ) -> bool:
        """
        Active defense: spoof the return value register in GDB so the target
        program receives a success code (e.g. 0) and cannot detect the debugger.
        """
        if not self.neutralize_anti_debug or not gdb_module or not arch:
            return False

        spoof_val = finding.details.get("neutralize_reg_val", 0)

        try:
            gdb_module.execute(f"set ${arch.ret_reg} = {spoof_val}")
            finding.details["neutralized"] = True
            finding.message += f" [Neutralized: return register (${arch.ret_reg}) spoofed to {spoof_val} (Success)]"

            # Update event to reflect neutralized state
            event.ret_val = spoof_val
            event.ret_str = f"{spoof_val} (NEUTRALIZED)"
            event.is_error = False
            event.errno_name = None
            return True
        except Exception:
            return False
