"""
Architecture definitions and register conventions for syscall tracing.
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class ArchSpec:
    name: str
    syscall_reg: str
    orig_syscall_reg: Optional[str]
    arg_regs: List[str]
    ret_reg: str
    pc_reg: str
    sp_reg: str
    ptr_size: int
    entry_indicator_val: int = -38  # -ENOSYS on Linux


ARCH_SPECS = {
    "x86_64": ArchSpec(
        name="x86_64",
        syscall_reg="rax",
        orig_syscall_reg="orig_rax",
        arg_regs=["rdi", "rsi", "rdx", "r10", "r8", "r9"],
        ret_reg="rax",
        pc_reg="rip",
        sp_reg="rsp",
        ptr_size=8,
        entry_indicator_val=-38,
    ),
    "i386": ArchSpec(
        name="i386",
        syscall_reg="eax",
        orig_syscall_reg="orig_eax",
        arg_regs=["ebx", "ecx", "edx", "esi", "edi", "ebp"],
        ret_reg="eax",
        pc_reg="eip",
        sp_reg="esp",
        ptr_size=4,
        entry_indicator_val=-38,
    ),
    "aarch64": ArchSpec(
        name="aarch64",
        syscall_reg="x8",
        orig_syscall_reg=None,
        arg_regs=["x0", "x1", "x2", "x3", "x4", "x5"],
        ret_reg="x0",
        pc_reg="pc",
        sp_reg="sp",
        ptr_size=8,
        entry_indicator_val=-38,
    ),
    "arm": ArchSpec(
        name="arm",
        syscall_reg="r7",
        orig_syscall_reg=None,
        arg_regs=["r0", "r1", "r2", "r3", "r4", "r5"],
        ret_reg="r0",
        pc_reg="pc",
        sp_reg="sp",
        ptr_size=4,
        entry_indicator_val=-38,
    ),
    "riscv64": ArchSpec(
        name="riscv64",
        syscall_reg="a7",
        orig_syscall_reg=None,
        arg_regs=["a0", "a1", "a2", "a3", "a4", "a5"],
        ret_reg="a0",
        pc_reg="pc",
        sp_reg="sp",
        ptr_size=8,
        entry_indicator_val=-38,
    ),
}


def detect_arch(arch_str: str) -> ArchSpec:
    """Normalize GDB architecture name to ArchSpec."""
    arch_str = arch_str.lower()
    if "x86-64" in arch_str or "x86_64" in arch_str or "amd64" in arch_str:
        return ARCH_SPECS["x86_64"]
    if "i386" in arch_str or "i686" in arch_str or "x86" in arch_str:
        return ARCH_SPECS["i386"]
    if "aarch64" in arch_str or "arm64" in arch_str:
        return ARCH_SPECS["aarch64"]
    if "arm" in arch_str:
        return ARCH_SPECS["arm"]
    if "riscv:rv64" in arch_str or "riscv64" in arch_str:
        return ARCH_SPECS["riscv64"]
    # Default fallback to x86_64
    return ARCH_SPECS["x86_64"]
