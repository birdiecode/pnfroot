"""Shared ptrace structures and tracee memory helpers."""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import platform
import re
import signal
import sys
from dataclasses import dataclass, field


PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_POKEDATA = 5
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_SYSCALL = 24
PTRACE_DETACH = 17
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETREGSET = 0x4204
PTRACE_SETREGSET = 0x4205

NT_PRSTATUS = 1
NT_ARM_SYSTEM_CALL = 0x404

PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_O_TRACEFORK = 0x00000002
PTRACE_O_TRACEVFORK = 0x00000004
PTRACE_O_TRACECLONE = 0x00000008
PTRACE_O_TRACEEXEC = 0x00000010
PTRACE_O_TRACEEXIT = 0x00000040
PTRACE_O_EXITKILL = 0x00100000

PTRACE_EVENT_FORK = 1
PTRACE_EVENT_VFORK = 2
PTRACE_EVENT_CLONE = 3
PTRACE_EVENT_EXEC = 4
PTRACE_EVENT_EXIT = 6

WAIT_ALL_TRACED = 0x40000000  # __WALL: wait for traced threads too.
SYSCALL_STOP = signal.SIGTRAP | 0x80
WORD_SIZE = ctypes.sizeof(ctypes.c_void_p)


def normalize_architecture(machine: str | None = None) -> str:
    machine = (machine or platform.machine()).lower().replace("-", "_")
    if machine in {"x86_64", "amd64", "x64"}:
        return "x86_64"
    if (
        machine in {"aarch64", "arm64", "arm64_v8a", "armv8l"}
        or machine.startswith("aarch64_")
        or machine.startswith("arm64_")
    ):
        return "aarch64"
    return machine


ARCHITECTURE = normalize_architecture()
SUPPORTED_ARCHITECTURES = {"x86_64", "aarch64"}
ARG_REGISTERS = ("rdi", "rsi", "rdx", "r10", "r8", "r9")

TRACE_OPTIONS = (
    PTRACE_O_TRACESYSGOOD
    | PTRACE_O_TRACEFORK
    | PTRACE_O_TRACEVFORK
    | PTRACE_O_TRACECLONE
    | PTRACE_O_TRACEEXEC
    | PTRACE_O_TRACEEXIT
    | PTRACE_O_EXITKILL
)


class X86_64UserRegsStruct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


class AArch64UserRegsStruct(ctypes.Structure):
    """Linux arm64 ``struct user_pt_regs`` with neutral ABI accessors."""

    _fields_ = [
        ("regs", ctypes.c_ulonglong * 31),
        ("sp", ctypes.c_ulonglong),
        ("pc", ctypes.c_ulonglong),
        ("pstate", ctypes.c_ulonglong),
    ]

    def _get_register(self, index: int) -> int:
        return int(self.regs[index])

    def _set_register(self, index: int, value: int) -> None:
        self.regs[index] = ctypes.c_ulonglong(value).value

    # These aliases let the architecture-independent rewriting code continue
    # to address syscall arguments 0..5 and the return value uniformly.
    rdi = property(
        lambda self: self._get_register(0),
        lambda self, value: self._set_register(0, value),
    )
    rsi = property(
        lambda self: self._get_register(1),
        lambda self, value: self._set_register(1, value),
    )
    rdx = property(
        lambda self: self._get_register(2),
        lambda self, value: self._set_register(2, value),
    )
    r10 = property(
        lambda self: self._get_register(3),
        lambda self, value: self._set_register(3, value),
    )
    r8 = property(
        lambda self: self._get_register(4),
        lambda self, value: self._set_register(4, value),
    )
    r9 = property(
        lambda self: self._get_register(5),
        lambda self, value: self._set_register(5, value),
    )
    rax = property(
        lambda self: self._get_register(0),
        lambda self, value: self._set_register(0, value),
    )
    rsp = property(
        lambda self: int(self.sp),
        lambda self, value: setattr(self, "sp", value),
    )

    @property
    def orig_rax(self) -> int:
        return int(getattr(self, "_syscall_number", self.regs[8]))

    @orig_rax.setter
    def orig_rax(self, value: int) -> None:
        self._syscall_number = int(value)
        self.regs[8] = ctypes.c_ulonglong(value).value


UserRegsStruct = (
    AArch64UserRegsStruct if ARCHITECTURE == "aarch64" else X86_64UserRegsStruct
)


class IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


@dataclass
class SyscallRecord:
    name: str
    number: int
    args: list[int]
    rendered_args: str
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class SyscallContext:
    pid: int
    event: str
    name: str
    number: int
    args: list[int]
    regs: UserRegsStruct
    rendered_args: str
    result: int | None = None

    @property
    def result_text(self) -> str:
        if self.result is None:
            return ""
        return format_return(self.result)

    def arg(self, index: int) -> int:
        return self.args[index]

    def string_arg(self, index: int, max_bytes: int = 4096) -> str:
        return read_c_string(self.pid, self.args[index], max_bytes=max_bytes)

    def string_array_arg(self, index: int, max_items: int = 8) -> str:
        return read_string_array(self.pid, self.args[index], max_items=max_items)


libc_name = ctypes.util.find_library("c")
if libc_name is None:
    raise SystemExit("Could not find libc")

libc = ctypes.CDLL(libc_name, use_errno=True)
libc.ptrace.restype = ctypes.c_long


def ptrace(request: int, pid: int, addr=0, data=0) -> int:
    if isinstance(addr, int):
        addr = ctypes.c_void_p(addr)
    if isinstance(data, int):
        data = ctypes.c_void_p(data)

    ctypes.set_errno(0)
    result = libc.ptrace(request, pid, addr, data)
    if result == -1:
        err = ctypes.get_errno()
        if err:
            raise OSError(err, os.strerror(err))
    return result


def ptrace_peek(pid: int, address: int) -> int:
    ctypes.set_errno(0)
    result = libc.ptrace(
        PTRACE_PEEKDATA, pid, ctypes.c_void_p(address), ctypes.c_void_p(0)
    )
    err = ctypes.get_errno()
    if result == -1 and err:
        raise OSError(err, os.strerror(err))
    return ctypes.c_ulonglong(result).value


def ptrace_poke(pid: int, address: int, value: int) -> None:
    ptrace(PTRACE_POKEDATA, pid, ctypes.c_void_p(address), ctypes.c_void_p(value))


def write_tracee_bytes(pid: int, address: int, data: bytes) -> None:
    for offset in range(0, len(data), WORD_SIZE):
        chunk = data[offset : offset + WORD_SIZE]
        if len(chunk) < WORD_SIZE:
            try:
                original = ptrace_peek(pid, address + offset).to_bytes(
                    WORD_SIZE, sys.byteorder
                )
            except OSError:
                original = b"\x00" * WORD_SIZE
            chunk = chunk + original[len(chunk) :]

        ptrace_poke(pid, address + offset, int.from_bytes(chunk, sys.byteorder))


def set_trace_options(pid: int) -> None:
    ptrace(PTRACE_SETOPTIONS, pid, 0, TRACE_OPTIONS)


def get_regs(pid: int) -> UserRegsStruct:
    regs = UserRegsStruct()
    if ARCHITECTURE == "aarch64":
        iov = IOVec(ctypes.addressof(regs), ctypes.sizeof(regs))
        ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, ctypes.byref(iov))
        syscall_number = ctypes.c_int()
        syscall_iov = IOVec(
            ctypes.addressof(syscall_number), ctypes.sizeof(syscall_number)
        )
        ptrace(
            PTRACE_GETREGSET,
            pid,
            NT_ARM_SYSTEM_CALL,
            ctypes.byref(syscall_iov),
        )
        regs.orig_rax = syscall_number.value
    else:
        ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs))
    return regs


def set_regs(pid: int, regs: UserRegsStruct) -> None:
    if ARCHITECTURE == "aarch64":
        iov = IOVec(ctypes.addressof(regs), ctypes.sizeof(regs))
        ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, ctypes.byref(iov))
        syscall_number = ctypes.c_int(int(regs.orig_rax))
        syscall_iov = IOVec(
            ctypes.addressof(syscall_number), ctypes.sizeof(syscall_number)
        )
        ptrace(
            PTRACE_SETREGSET,
            pid,
            NT_ARM_SYSTEM_CALL,
            ctypes.byref(syscall_iov),
        )
    else:
        ptrace(PTRACE_SETREGS, pid, 0, ctypes.byref(regs))


def get_event_msg(pid: int) -> int:
    msg = ctypes.c_ulong()
    ptrace(PTRACE_GETEVENTMSG, pid, 0, ctypes.byref(msg))
    return int(msg.value)


def fallback_syscall_names(architecture: str) -> dict[int, str]:
    if architecture == "aarch64":
        return {
            17: "getcwd",
            23: "dup",
            24: "dup3",
            25: "fcntl",
            29: "ioctl",
            33: "mknodat",
            34: "mkdirat",
            35: "unlinkat",
            36: "symlinkat",
            37: "linkat",
            38: "renameat",
            39: "umount2",
            40: "mount",
            45: "truncate",
            48: "faccessat",
            49: "chdir",
            54: "fchownat",
            55: "fchown",
            56: "openat",
            57: "close",
            63: "read",
            64: "write",
            78: "readlinkat",
            79: "newfstatat",
            80: "fstat",
            88: "utimensat",
            93: "exit",
            94: "exit_group",
            143: "setregid",
            144: "setgid",
            145: "setreuid",
            146: "setuid",
            147: "setresuid",
            148: "getresuid",
            149: "setresgid",
            150: "getresgid",
            151: "setfsuid",
            152: "setfsgid",
            158: "getgroups",
            159: "setgroups",
            172: "getpid",
            174: "getuid",
            175: "geteuid",
            176: "getgid",
            177: "getegid",
            198: "socket",
            199: "socketpair",
            200: "bind",
            201: "listen",
            202: "accept",
            203: "connect",
            204: "getsockname",
            205: "getpeername",
            206: "sendto",
            207: "recvfrom",
            208: "setsockopt",
            209: "getsockopt",
            210: "shutdown",
            211: "sendmsg",
            212: "recvmsg",
            220: "clone",
            221: "execve",
            222: "mmap",
            242: "accept4",
            276: "renameat2",
            281: "execveat",
            291: "statx",
            293: "rseq",
            436: "close_range",
            439: "faccessat2",
        }
    return {
        0: "read",
        1: "write",
        2: "open",
        3: "close",
        9: "mmap",
        10: "mprotect",
        11: "munmap",
        12: "brk",
        21: "access",
        39: "getpid",
        56: "clone",
        57: "fork",
        58: "vfork",
        59: "execve",
        60: "exit",
        61: "wait4",
        62: "kill",
        89: "readlink",
        231: "exit_group",
        257: "openat",
        262: "newfstatat",
    }


def load_syscall_names(architecture: str | None = None) -> dict[int, str]:
    architecture = architecture or ARCHITECTURE
    names: dict[int, str] = {}
    if architecture == "aarch64":
        header_paths = [
            "/usr/include/aarch64-linux-gnu/asm/unistd.h",
            "/usr/include/asm/unistd.h",
            "/usr/include/asm-generic/unistd.h",
        ]
    else:
        header_paths = [
            "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
            "/usr/include/asm/unistd_64.h",
        ]
    pattern = re.compile(
        r"^#define\s+__NR(3264)?_([A-Za-z0-9_]+)\s+(\d+)\b"
    )

    for path in header_paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as header:
                for line in header:
                    match = pattern.match(line)
                    if match:
                        prefix = "3264_" if match.group(1) else ""
                        names[int(match.group(3))] = prefix + match.group(2)
        except OSError:
            continue

        if names:
            break

    if architecture == "aarch64":
        generic_aliases = {
            "3264_fcntl": "fcntl",
            "3264_fstatat": "newfstatat",
            "3264_fstat": "fstat",
            "3264_lseek": "lseek",
            "3264_mmap": "mmap",
            "3264_statfs": "statfs",
            "3264_fstatfs": "fstatfs",
            "3264_truncate": "truncate",
            "3264_ftruncate": "ftruncate",
            "3264_sendfile": "sendfile",
            "3264_fadvise64": "fadvise64",
        }
        names = {
            number: generic_aliases.get(name, name)
            for number, name in names.items()
        }

    fallback = fallback_syscall_names(architecture)
    fallback.update(names)
    return fallback


SYSCALL_NAMES = load_syscall_names()
SYSCALL_NUMBERS = {name: number for number, name in SYSCALL_NAMES.items()}


def signal_name(sig: int) -> str:
    try:
        return signal.Signals(sig).name
    except ValueError:
        return f"SIG{sig}"


def signed64(value: int) -> int:
    if value >= 1 << 63:
        return value - (1 << 64)
    return value


def hex_or_null(value: int) -> str:
    return "NULL" if value == 0 else f"0x{value:x}"


def quote_bytes(data: bytes, limit: int = 160) -> str:
    truncated = len(data) > limit
    data = data[:limit]
    text = data.decode("utf-8", errors="backslashreplace")
    text = (
        text.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace('"', '\\"')
    )
    suffix = "..." if truncated else ""
    return f'"{text}{suffix}"'


def read_c_string_bytes(pid: int, address: int, max_bytes: int = 4096) -> bytes | None:
    if address == 0:
        return None

    data = bytearray()
    try:
        for offset in range(0, max_bytes, WORD_SIZE):
            word = ptrace_peek(pid, address + offset)
            chunk = word.to_bytes(WORD_SIZE, sys.byteorder)
            nul = chunk.find(b"\x00")
            if nul != -1:
                data.extend(chunk[:nul])
                return bytes(data)
            data.extend(chunk)
    except OSError:
        return None

    return bytes(data)


def read_c_string(pid: int, address: int, max_bytes: int = 4096) -> str:
    if address == 0:
        return "NULL"

    data = read_c_string_bytes(pid, address, max_bytes=max_bytes)
    if data is None:
        return hex_or_null(address)

    if len(data) >= max_bytes:
        return quote_bytes(data)[:-1] + '..."'
    return quote_bytes(data)


def read_pointer(pid: int, address: int) -> int:
    word = ptrace_peek(pid, address)
    mask = (1 << (WORD_SIZE * 8)) - 1
    return word & mask


def read_tracee_u32(pid: int, address: int) -> int:
    word = ptrace_peek(pid, address & ~(WORD_SIZE - 1))
    shift = (address % WORD_SIZE) * 8
    return (word >> shift) & 0xFFFFFFFF


def read_tracee_u32_array(pid: int, address: int, count: int) -> list[int]:
    return [read_tracee_u32(pid, address + index * 4) for index in range(count)]


def write_tracee_u32(pid: int, address: int, value: int) -> None:
    aligned = address & ~(WORD_SIZE - 1)
    shift = (address % WORD_SIZE) * 8
    mask = 0xFFFFFFFF << shift
    word = ptrace_peek(pid, aligned)
    word = (word & ~mask) | ((value & 0xFFFFFFFF) << shift)
    ptrace_poke(pid, aligned, word)


def write_tracee_u32_array(pid: int, address: int, values: list[int]) -> None:
    for index, value in enumerate(values):
        write_tracee_u32(pid, address + index * 4, value)


def read_string_array(pid: int, address: int, max_items: int = 8) -> str:
    if address == 0:
        return "NULL"

    items = []
    try:
        for index in range(max_items):
            item_address = read_pointer(pid, address + index * WORD_SIZE)
            if item_address == 0:
                return "[" + ", ".join(items) + "]"
            items.append(read_c_string(pid, item_address, max_bytes=512))

        return "[" + ", ".join(items) + ", ...]"
    except OSError:
        return hex_or_null(address)


def format_return(value: int) -> str:
    value = signed64(value)
    if -4095 <= value < 0:
        err_no = -value
        err_name = errno.errorcode.get(err_no, f"ERRNO_{err_no}")
        return f"-1 {err_name} (kernel returned {value})"
    return str(value)


def syscall_error(value: int) -> int | None:
    value = signed64(value)
    if -4095 <= value < 0:
        return -value
    return None


def set_syscall_result(context: SyscallContext, value: int) -> None:
    context.regs.rax = ctypes.c_ulonglong(value).value
    context.result = int(context.regs.rax)
    set_regs(context.pid, context.regs)
