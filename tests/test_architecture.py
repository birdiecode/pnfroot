import ctypes

import ptrace_syscalls
from image_store import default_image_platform
from ptrace_common import (
    AArch64UserRegsStruct,
    fallback_syscall_names,
    load_syscall_names,
    normalize_architecture,
)


def test_normalizes_supported_architecture_names() -> None:
    assert normalize_architecture("amd64") == "x86_64"
    assert normalize_architecture("x86_64") == "x86_64"
    assert normalize_architecture("arm64") == "aarch64"
    assert normalize_architecture("aarch64") == "aarch64"
    assert normalize_architecture("arm64-v8a") == "aarch64"
    assert normalize_architecture("armv8l") == "aarch64"


def test_default_image_platform_follows_host_architecture() -> None:
    assert default_image_platform("x86_64") == "linux/amd64"
    assert default_image_platform("aarch64") == "linux/arm64"
    assert default_image_platform("arm64-v8a") == "linux/arm64"
    assert default_image_platform("armv8l") == "linux/arm64"


def test_android_aarch64_is_supported(monkeypatch) -> None:
    monkeypatch.setattr(ptrace_syscalls.platform, "system", lambda: "Android")
    monkeypatch.setattr(ptrace_syscalls.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(ptrace_syscalls, "ARCHITECTURE", "aarch64")
    monkeypatch.setattr(ptrace_syscalls, "WORD_SIZE", 8)

    ptrace_syscalls.ensure_supported_architecture()


def test_aarch64_register_aliases_match_syscall_abi() -> None:
    regs = AArch64UserRegsStruct()
    regs.rdi = 10
    regs.rsi = 11
    regs.rdx = 12
    regs.r10 = 13
    regs.r8 = 14
    regs.r9 = 15
    regs.orig_rax = 221
    regs.rsp = 0x1234

    assert list(regs.regs[:6]) == [10, 11, 12, 13, 14, 15]
    assert regs.regs[8] == 221
    assert regs.orig_rax == 221
    assert regs.sp == 0x1234

    regs.rax = ctypes.c_ulonglong(-2).value
    assert regs.regs[0] == ctypes.c_ulonglong(-2).value


def test_aarch64_syscall_table_has_required_generic_aliases() -> None:
    names = load_syscall_names("aarch64")
    numbers = {name: number for number, name in names.items()}

    assert numbers["openat"] == 56
    assert numbers["newfstatat"] == 79
    assert numbers["fcntl"] == 25
    assert numbers["mmap"] == 222
    assert numbers["execve"] == 221
    assert numbers["getpid"] == 172


def test_aarch64_fallback_has_minimum_bootstrap_syscalls() -> None:
    names = fallback_syscall_names("aarch64")

    assert names[56] == "openat"
    assert names[63] == "read"
    assert names[64] == "write"
    assert names[172] == "getpid"
    assert names[221] == "execve"
