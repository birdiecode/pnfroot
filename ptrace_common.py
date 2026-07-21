"""Shared ptrace structures and tracee memory helpers."""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
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


class UserRegsStruct(ctypes.Structure):
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
    ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs))
    return regs


def set_regs(pid: int, regs: UserRegsStruct) -> None:
    ptrace(PTRACE_SETREGS, pid, 0, ctypes.byref(regs))


def get_event_msg(pid: int) -> int:
    msg = ctypes.c_ulong()
    ptrace(PTRACE_GETEVENTMSG, pid, 0, ctypes.byref(msg))
    return int(msg.value)


def load_syscall_names() -> dict[int, str]:
    names: dict[int, str] = {}
    header_paths = [
        "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
        "/usr/include/asm/unistd_64.h",
        "/usr/include/asm-generic/unistd.h",
    ]
    pattern = re.compile(r"^#define\s+__NR_([A-Za-z0-9_]+)\s+(\d+)\b")

    for path in header_paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as header:
                for line in header:
                    match = pattern.match(line)
                    if match:
                        names[int(match.group(2))] = match.group(1)
        except OSError:
            continue

        if names:
            return names

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
