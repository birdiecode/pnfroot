#!/usr/bin/env python3
"""Small Linux syscall tracer based on ptrace.

Usage examples:
    ./ptrace_syscalls.py -- /bin/ls -la
    ./ptrace_syscalls.py --rootfs ./ubuntu_c --quiet -- /bin/bash
    ./ptrace_syscalls.py --rootfs ./ubuntu_c --uid 0 --gid 0 --quiet -- /bin/bash

This script is intentionally dependency-free. It currently supports Linux
x86_64, where syscall arguments live in rdi, rsi, rdx, r10, r8, r9.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import errno
import os
import platform
import posixpath
import re
import signal
import stat as stat_module
import sys
from collections.abc import Callable
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

PTRACE_EVENT_FORK = 1
PTRACE_EVENT_VFORK = 2
PTRACE_EVENT_CLONE = 3
PTRACE_EVENT_EXEC = 4
PTRACE_EVENT_EXIT = 6

WAIT_ALL_TRACED = 0x40000000  # __WALL: wait for traced threads too.
SYSCALL_STOP = signal.SIGTRAP | 0x80
WORD_SIZE = ctypes.sizeof(ctypes.c_void_p)
AT_FDCWD = -100
O_DIRECTORY = 0o200000
SCRATCH_STACK_GAP = 256
ARG_REGISTERS = ("rdi", "rsi", "rdx", "r10", "r8", "r9")
NO_ID = 0xFFFFFFFF
# Unprivileged rootfs extraction often loses owner 0 and setuid bits. Treat the
# usual privileged account-management helpers as virtual setuid-root executables.
DEFAULT_SETUID_ROOT_PATHS = {
    "/bin/passwd",
    "/bin/su",
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/bin/gpasswd",
    "/usr/bin/mount",
    "/usr/bin/newgrp",
    "/usr/bin/passwd",
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/sudoedit",
    "/usr/bin/umount",
}

TRACE_OPTIONS = (
    PTRACE_O_TRACESYSGOOD
    | PTRACE_O_TRACEFORK
    | PTRACE_O_TRACEVFORK
    | PTRACE_O_TRACECLONE
    | PTRACE_O_TRACEEXEC
    | PTRACE_O_TRACEEXIT
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


SyscallHandler = Callable[[SyscallContext], None]
SYSCALL_HANDLERS: dict[str, list[tuple[str, SyscallHandler]]] = {}
TRACE_LOGGING = True


def syscall_handler(*syscall_names: str, when: str = "both"):
    if when not in {"enter", "exit", "both"}:
        raise ValueError("when must be 'enter', 'exit', or 'both'")
    if not syscall_names:
        raise ValueError("pass at least one syscall name")

    def decorator(func: SyscallHandler) -> SyscallHandler:
        for syscall_name in syscall_names:
            SYSCALL_HANDLERS.setdefault(syscall_name, []).append((when, func))
        return func

    return decorator


def dispatch_syscall_handlers(context: SyscallContext) -> None:
    handlers = SYSCALL_HANDLERS.get("*", []) + SYSCALL_HANDLERS.get(context.name, [])

    for when, handler in handlers:
        if when not in {context.event, "both"}:
            continue
        try:
            handler(context)
        except Exception as exc:
            trace_log(
                f"[pid {context.pid}] handler {handler.__name__} failed: {exc}",
                file=sys.stderr,
            )


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

STRING_ARGS = {
    "open": {0},
    "creat": {0},
    "access": {0},
    "stat": {0},
    "lstat": {0},
    "newstat": {0},
    "newlstat": {0},
    "unlink": {0},
    "chdir": {0},
    "mkdir": {0},
    "rmdir": {0},
    "chmod": {0},
    "chown": {0},
    "readlink": {0},
    "symlink": {0, 1},
    "rename": {0, 1},
    "openat": {1},
    "mkdirat": {1},
    "mknodat": {1},
    "fchownat": {1},
    "futimesat": {1},
    "newfstatat": {1},
    "unlinkat": {1},
    "renameat": {1, 3},
    "renameat2": {1, 3},
    "readlinkat": {1},
    "symlinkat": {0, 2},
    "execveat": {1},
}


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


def format_arg(pid: int, syscall_name: str, index: int, value: int) -> str:
    if syscall_name in STRING_ARGS and index in STRING_ARGS[syscall_name]:
        return read_c_string(pid, value)
    return hex_or_null(value)


def format_syscall_args(pid: int, syscall_name: str, args: list[int]) -> str:
    if syscall_name == "execve":
        return (
            f"{read_c_string(pid, args[0])}, "
            f"{read_string_array(pid, args[1])}, "
            f"envp={hex_or_null(args[2])}"
        )
    if syscall_name == "execveat":
        return (
            f"{hex_or_null(args[0])}, "
            f"{read_c_string(pid, args[1])}, "
            f"{read_string_array(pid, args[2])}, "
            f"envp={hex_or_null(args[3])}, "
            f"flags={hex_or_null(args[4])}"
        )

    return ", ".join(
        format_arg(pid, syscall_name, index, value)
        for index, value in enumerate(args)
    )


def format_return(value: int) -> str:
    value = signed64(value)
    if -4095 <= value < 0:
        err_no = -value
        err_name = errno.errorcode.get(err_no, f"ERRNO_{err_no}")
        return f"-1 {err_name} (kernel returned {value})"
    return str(value)


def set_syscall_result(context: SyscallContext, value: int) -> None:
    context.regs.rax = ctypes.c_ulonglong(value).value
    context.result = int(context.regs.rax)
    set_regs(context.pid, context.regs)


@dataclass(frozen=True)
class PathArgSpec:
    path_index: int
    dirfd_index: int | None = None
    follow_final_symlink: bool = True


PATH_ARG_SPECS: dict[str, tuple[PathArgSpec, ...]] = {
    "open": (PathArgSpec(0),),
    "creat": (PathArgSpec(0, follow_final_symlink=False),),
    "access": (PathArgSpec(0),),
    "faccessat": (PathArgSpec(1, dirfd_index=0),),
    "faccessat2": (PathArgSpec(1, dirfd_index=0),),
    "stat": (PathArgSpec(0),),
    "lstat": (PathArgSpec(0, follow_final_symlink=False),),
    "newstat": (PathArgSpec(0),),
    "newlstat": (PathArgSpec(0, follow_final_symlink=False),),
    "statx": (PathArgSpec(1, dirfd_index=0),),
    "unlink": (PathArgSpec(0, follow_final_symlink=False),),
    "chdir": (PathArgSpec(0),),
    "mkdir": (PathArgSpec(0, follow_final_symlink=False),),
    "rmdir": (PathArgSpec(0, follow_final_symlink=False),),
    "chmod": (PathArgSpec(0),),
    "chown": (PathArgSpec(0),),
    "lchown": (PathArgSpec(0, follow_final_symlink=False),),
    "truncate": (PathArgSpec(0),),
    "utime": (PathArgSpec(0),),
    "readlink": (PathArgSpec(0, follow_final_symlink=False),),
    "link": (
        PathArgSpec(0, follow_final_symlink=False),
        PathArgSpec(1, follow_final_symlink=False),
    ),
    "symlink": (PathArgSpec(1, follow_final_symlink=False),),
    "rename": (
        PathArgSpec(0, follow_final_symlink=False),
        PathArgSpec(1, follow_final_symlink=False),
    ),
    "openat": (PathArgSpec(1, dirfd_index=0),),
    "mkdirat": (PathArgSpec(1, dirfd_index=0, follow_final_symlink=False),),
    "mknodat": (PathArgSpec(1, dirfd_index=0, follow_final_symlink=False),),
    "fchownat": (PathArgSpec(1, dirfd_index=0),),
    "futimesat": (PathArgSpec(1, dirfd_index=0),),
    "utimensat": (PathArgSpec(1, dirfd_index=0),),
    "newfstatat": (PathArgSpec(1, dirfd_index=0),),
    "unlinkat": (PathArgSpec(1, dirfd_index=0, follow_final_symlink=False),),
    "renameat": (
        PathArgSpec(1, dirfd_index=0, follow_final_symlink=False),
        PathArgSpec(3, dirfd_index=2, follow_final_symlink=False),
    ),
    "renameat2": (
        PathArgSpec(1, dirfd_index=0, follow_final_symlink=False),
        PathArgSpec(3, dirfd_index=2, follow_final_symlink=False),
    ),
    "linkat": (
        PathArgSpec(1, dirfd_index=0, follow_final_symlink=False),
        PathArgSpec(3, dirfd_index=2, follow_final_symlink=False),
    ),
    "readlinkat": (PathArgSpec(1, dirfd_index=0, follow_final_symlink=False),),
    "symlinkat": (PathArgSpec(2, dirfd_index=1, follow_final_symlink=False),),
    "execve": (PathArgSpec(0),),
    "execveat": (PathArgSpec(1, dirfd_index=0),),
}


def normalize_virtual_path(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    normalized = posixpath.normpath(path)
    return "/" if normalized == "." else normalized


def split_virtual_path(path: str) -> list[str]:
    return [part for part in path.split("/") if part and part != "."]


def syscall_error(value: int) -> int | None:
    value = signed64(value)
    if -4095 <= value < 0:
        return -value
    return None


class TraceeScratch:
    def __init__(self, pid: int, regs: UserRegsStruct):
        self.pid = pid
        self.cursor = int(regs.rsp) - SCRATCH_STACK_GAP

    def write_c_string(self, value: bytes) -> int:
        data = value + b"\x00"
        self.cursor = (self.cursor - len(data)) & ~(WORD_SIZE - 1)
        write_tracee_bytes(self.pid, self.cursor, data)
        return self.cursor


@dataclass
class VirtualCredentials:
    ruid: int
    euid: int
    suid: int
    fsuid: int
    rgid: int
    egid: int
    sgid: int
    fsgid: int

    @classmethod
    def from_ids(cls, uid: int, gid: int) -> VirtualCredentials:
        return cls(
            ruid=uid,
            euid=uid,
            suid=uid,
            fsuid=uid,
            rgid=gid,
            egid=gid,
            sgid=gid,
            fsgid=gid,
        )

    def copy(self) -> VirtualCredentials:
        return VirtualCredentials(
            ruid=self.ruid,
            euid=self.euid,
            suid=self.suid,
            fsuid=self.fsuid,
            rgid=self.rgid,
            egid=self.egid,
            sgid=self.sgid,
            fsgid=self.fsgid,
        )


@dataclass(frozen=True)
class ExecutableIds:
    mode: int
    uid: int
    gid: int


class VirtualIds:
    RESULT_SYSCALLS = {"getuid", "geteuid", "getgid", "getegid"}
    POINTER_GETTER_SYSCALLS = {"getresuid", "getresgid", "getgroups"}
    SETTER_SYSCALLS = {
        "setuid",
        "setreuid",
        "setresuid",
        "setfsuid",
        "setgid",
        "setregid",
        "setresgid",
        "setfsgid",
        "setgroups",
    }

    def __init__(self, uid: int, gid: int):
        self.initial = VirtualCredentials.from_ids(uid, gid)
        self.credentials_by_pid: dict[int, VirtualCredentials] = {}
        self.groups_by_pid: dict[int, list[int]] = {}
        self.host_uid = os.getuid()
        self.host_gid = os.getgid()
        self.noop_syscall_number = SYSCALL_NUMBERS.get("getpid", 39)

    def register_pid(self, pid: int) -> None:
        self.credentials_by_pid[pid] = self.initial.copy()
        self.groups_by_pid[pid] = [self.initial.egid]

    def inherit_pid(self, parent_pid: int, child_pid: int) -> None:
        parent_credentials = self.credentials_by_pid.get(parent_pid, self.initial)
        self.credentials_by_pid[child_pid] = parent_credentials.copy()
        self.groups_by_pid[child_pid] = list(
            self.groups_by_pid.get(parent_pid, [parent_credentials.egid])
        )

    def drop_pid(self, pid: int) -> None:
        self.credentials_by_pid.pop(pid, None)
        self.groups_by_pid.pop(pid, None)

    def credentials(self, pid: int) -> VirtualCredentials:
        if pid not in self.credentials_by_pid:
            self.register_pid(pid)
        return self.credentials_by_pid[pid]

    def neutralize_syscall(
        self, pid: int, name: str, regs: UserRegsStruct
    ) -> dict[str, object]:
        if name not in self.SETTER_SYSCALLS | self.POINTER_GETTER_SYSCALLS:
            return {}

        regs.orig_rax = self.noop_syscall_number
        set_regs(pid, regs)
        return {"virtual_ids_neutralized": True}

    def handle_syscall_exit(
        self, context: SyscallContext, record: SyscallRecord | None
    ) -> None:
        if record is None:
            return

        name = record.name
        if name == "getuid":
            set_syscall_result(context, self.credentials(context.pid).ruid)
        elif name == "geteuid":
            set_syscall_result(context, self.credentials(context.pid).euid)
        elif name == "getgid":
            set_syscall_result(context, self.credentials(context.pid).rgid)
        elif name == "getegid":
            set_syscall_result(context, self.credentials(context.pid).egid)
        elif name == "getresuid":
            self.handle_getresuid(context)
        elif name == "getresgid":
            self.handle_getresgid(context)
        elif name == "getgroups":
            self.handle_getgroups(context)
        elif name in {
            "setuid",
            "setreuid",
            "setresuid",
            "setfsuid",
        }:
            self.handle_uid_setter(context, record)
        elif name in {
            "setgid",
            "setregid",
            "setresgid",
            "setfsgid",
            "setgroups",
        }:
            self.handle_gid_setter(context, record)
        elif name in {"execve", "execveat"}:
            self.handle_exec(context, record)

    def handle_exec(self, context: SyscallContext, record: SyscallRecord) -> None:
        if syscall_error(context.result or 0) is not None:
            return

        executable = self.executable_ids(record)
        if executable is None:
            return

        credentials = self.credentials(context.pid)
        if executable.mode & stat_module.S_ISUID:
            credentials.euid = executable.uid
            credentials.suid = executable.uid
            credentials.fsuid = executable.uid

        if executable.mode & stat_module.S_ISGID:
            credentials.egid = executable.gid
            credentials.sgid = executable.gid
            credentials.fsgid = executable.gid

    def executable_ids(self, record: SyscallRecord) -> ExecutableIds | None:
        virtual_path = record.metadata.get("exec_virtual_path")
        host_path = record.metadata.get("exec_host_path")

        if not isinstance(host_path, str):
            return None

        try:
            st = os.stat(host_path)
        except OSError:
            return None

        mode = stat_module.S_IMODE(st.st_mode)
        uid = self.host_id_to_virtual_uid(st.st_uid)
        gid = self.host_id_to_virtual_gid(st.st_gid)

        if isinstance(virtual_path, str) and virtual_path in DEFAULT_SETUID_ROOT_PATHS:
            mode |= stat_module.S_ISUID
            uid = 0
            gid = 0

        return ExecutableIds(mode=mode, uid=uid, gid=gid)

    def host_id_to_virtual_uid(self, uid: int) -> int:
        if self.initial.ruid == 0 and uid == self.host_uid:
            return 0
        return uid

    def host_id_to_virtual_gid(self, gid: int) -> int:
        if self.initial.rgid == 0 and gid == self.host_gid:
            return 0
        return gid

    def handle_getresuid(self, context: SyscallContext) -> None:
        credentials = self.credentials(context.pid)
        result = self.write_id_pointers(
            context.pid,
            [context.args[0], context.args[1], context.args[2]],
            [credentials.ruid, credentials.euid, credentials.suid],
        )
        set_syscall_result(context, result)

    def handle_getresgid(self, context: SyscallContext) -> None:
        credentials = self.credentials(context.pid)
        result = self.write_id_pointers(
            context.pid,
            [context.args[0], context.args[1], context.args[2]],
            [credentials.rgid, credentials.egid, credentials.sgid],
        )
        set_syscall_result(context, result)

    def write_id_pointers(
        self, pid: int, addresses: list[int], values: list[int]
    ) -> int:
        try:
            for address, value in zip(addresses, values):
                if address == 0:
                    return -errno.EFAULT
                write_tracee_u32(pid, address, value)
        except OSError:
            return -errno.EFAULT
        return 0

    def handle_getgroups(self, context: SyscallContext) -> None:
        size = signed64(context.args[0])
        list_address = context.args[1]
        groups = self.groups_by_pid.get(
            context.pid, [self.credentials(context.pid).egid]
        )

        if size == 0:
            set_syscall_result(context, len(groups))
            return

        if size < 0 or size < len(groups):
            set_syscall_result(context, -errno.EINVAL)
            return

        if list_address == 0:
            set_syscall_result(context, -errno.EFAULT)
            return

        try:
            write_tracee_u32_array(context.pid, list_address, groups)
        except OSError:
            set_syscall_result(context, -errno.EFAULT)
            return

        set_syscall_result(context, len(groups))

    def handle_uid_setter(
        self, context: SyscallContext, record: SyscallRecord
    ) -> None:
        credentials = self.credentials(context.pid)
        name = record.name

        if name == "setuid":
            result = self.apply_setuid(credentials, self.id_arg(record.args[0]))
        elif name == "setreuid":
            result = self.apply_setreuid(
                credentials, self.id_arg(record.args[0]), self.id_arg(record.args[1])
            )
        elif name == "setresuid":
            result = self.apply_setresuid(
                credentials,
                self.id_arg(record.args[0]),
                self.id_arg(record.args[1]),
                self.id_arg(record.args[2]),
            )
        elif name == "setfsuid":
            result = credentials.fsuid
            uid = self.id_arg(record.args[0])
            if self.id_can_change(credentials, uid, "uid"):
                credentials.fsuid = uid
        else:
            result = -errno.ENOSYS

        set_syscall_result(context, result)

    def handle_gid_setter(
        self, context: SyscallContext, record: SyscallRecord
    ) -> None:
        credentials = self.credentials(context.pid)
        name = record.name

        if name == "setgid":
            result = self.apply_setgid(credentials, self.id_arg(record.args[0]))
        elif name == "setregid":
            result = self.apply_setregid(
                credentials, self.id_arg(record.args[0]), self.id_arg(record.args[1])
            )
        elif name == "setresgid":
            result = self.apply_setresgid(
                credentials,
                self.id_arg(record.args[0]),
                self.id_arg(record.args[1]),
                self.id_arg(record.args[2]),
            )
        elif name == "setfsgid":
            result = credentials.fsgid
            gid = self.id_arg(record.args[0])
            if self.id_can_change(credentials, gid, "gid"):
                credentials.fsgid = gid
        elif name == "setgroups":
            result = self.apply_setgroups(context.pid, credentials, record)
        else:
            result = -errno.ENOSYS

        set_syscall_result(context, result)

    def apply_setuid(self, credentials: VirtualCredentials, uid: int) -> int:
        if not self.valid_id(uid):
            return -errno.EINVAL

        if credentials.euid == 0:
            credentials.ruid = uid
            credentials.euid = uid
            credentials.suid = uid
            credentials.fsuid = uid
            return 0

        if uid in {credentials.ruid, credentials.euid, credentials.suid}:
            credentials.euid = uid
            credentials.fsuid = uid
            return 0

        return -errno.EPERM

    def apply_setreuid(
        self, credentials: VirtualCredentials, ruid: int, euid: int
    ) -> int:
        old = credentials.copy()
        if not self.id_arg_or_none_is_valid(ruid) or not self.id_arg_or_none_is_valid(
            euid
        ):
            return -errno.EINVAL

        for uid in (ruid, euid):
            if uid != NO_ID and not self.id_can_change(old, uid, "uid"):
                return -errno.EPERM

        if ruid != NO_ID:
            credentials.ruid = ruid
        if euid != NO_ID:
            credentials.euid = euid
            credentials.fsuid = euid
        if old.euid == 0 or ruid != NO_ID or (euid != NO_ID and euid != old.ruid):
            credentials.suid = credentials.euid

        return 0

    def apply_setresuid(
        self, credentials: VirtualCredentials, ruid: int, euid: int, suid: int
    ) -> int:
        old = credentials.copy()
        if not all(self.id_arg_or_none_is_valid(uid) for uid in (ruid, euid, suid)):
            return -errno.EINVAL

        for uid in (ruid, euid, suid):
            if uid != NO_ID and not self.id_can_change(old, uid, "uid"):
                return -errno.EPERM

        if ruid != NO_ID:
            credentials.ruid = ruid
        if euid != NO_ID:
            credentials.euid = euid
            credentials.fsuid = euid
        if suid != NO_ID:
            credentials.suid = suid

        return 0

    def apply_setgid(self, credentials: VirtualCredentials, gid: int) -> int:
        if not self.valid_id(gid):
            return -errno.EINVAL

        if credentials.euid == 0:
            credentials.rgid = gid
            credentials.egid = gid
            credentials.sgid = gid
            credentials.fsgid = gid
            return 0

        if gid in {credentials.rgid, credentials.egid, credentials.sgid}:
            credentials.egid = gid
            credentials.fsgid = gid
            return 0

        return -errno.EPERM

    def apply_setregid(
        self, credentials: VirtualCredentials, rgid: int, egid: int
    ) -> int:
        old = credentials.copy()
        if not self.id_arg_or_none_is_valid(rgid) or not self.id_arg_or_none_is_valid(
            egid
        ):
            return -errno.EINVAL

        for gid in (rgid, egid):
            if gid != NO_ID and not self.id_can_change(old, gid, "gid"):
                return -errno.EPERM

        if rgid != NO_ID:
            credentials.rgid = rgid
        if egid != NO_ID:
            credentials.egid = egid
            credentials.fsgid = egid
        if old.euid == 0 or rgid != NO_ID or (egid != NO_ID and egid != old.rgid):
            credentials.sgid = credentials.egid

        return 0

    def apply_setresgid(
        self, credentials: VirtualCredentials, rgid: int, egid: int, sgid: int
    ) -> int:
        old = credentials.copy()
        if not all(self.id_arg_or_none_is_valid(gid) for gid in (rgid, egid, sgid)):
            return -errno.EINVAL

        for gid in (rgid, egid, sgid):
            if gid != NO_ID and not self.id_can_change(old, gid, "gid"):
                return -errno.EPERM

        if rgid != NO_ID:
            credentials.rgid = rgid
        if egid != NO_ID:
            credentials.egid = egid
            credentials.fsgid = egid
        if sgid != NO_ID:
            credentials.sgid = sgid

        return 0

    def apply_setgroups(
        self, pid: int, credentials: VirtualCredentials, record: SyscallRecord
    ) -> int:
        size = signed64(record.args[0])
        list_address = record.args[1]

        if credentials.euid != 0:
            return -errno.EPERM
        if size < 0:
            return -errno.EINVAL
        if size > 0 and list_address == 0:
            return -errno.EFAULT

        try:
            groups = (
                read_tracee_u32_array(pid, list_address, size)
                if size > 0
                else []
            )
        except OSError:
            return -errno.EFAULT

        if any(not self.valid_id(group) for group in groups):
            return -errno.EINVAL

        self.groups_by_pid[pid] = groups
        return 0

    def id_can_change(
        self, credentials: VirtualCredentials, value: int, kind: str
    ) -> bool:
        if not self.valid_id(value):
            return False
        if credentials.euid == 0:
            return True
        if kind == "uid":
            return value in {credentials.ruid, credentials.euid, credentials.suid}
        return value in {credentials.rgid, credentials.egid, credentials.sgid}

    @staticmethod
    def id_arg(value: int) -> int:
        return value & NO_ID

    @staticmethod
    def valid_id(value: int) -> bool:
        return 0 <= value < NO_ID

    def id_arg_or_none_is_valid(self, value: int) -> bool:
        return value == NO_ID or self.valid_id(value)


class VirtualRoot:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.cwd_by_pid: dict[int, str] = {}
        self.fd_paths_by_pid: dict[int, dict[int, str]] = {}

    def register_pid(self, pid: int, cwd: str = "/") -> None:
        self.cwd_by_pid[pid] = normalize_virtual_path(cwd)
        self.fd_paths_by_pid.setdefault(pid, {})

    def inherit_pid(self, parent_pid: int, child_pid: int) -> None:
        self.cwd_by_pid[child_pid] = self.cwd_by_pid.get(parent_pid, "/")
        self.fd_paths_by_pid[child_pid] = dict(
            self.fd_paths_by_pid.get(parent_pid, {})
        )

    def drop_pid(self, pid: int) -> None:
        self.cwd_by_pid.pop(pid, None)
        self.fd_paths_by_pid.pop(pid, None)

    def raw_host_path(self, virtual_path: str) -> str:
        virtual_path = normalize_virtual_path(virtual_path)
        if virtual_path == "/":
            return self.root
        return os.path.join(self.root, virtual_path[1:])

    def host_path(
        self, virtual_path: str, *, follow_final_symlink: bool = True
    ) -> str:
        virtual_path = normalize_virtual_path(virtual_path)
        seen_links = 0

        while True:
            parts = split_virtual_path(virtual_path)
            resolved = "/"
            restarted = False

            for index, part in enumerate(parts):
                current = normalize_virtual_path(posixpath.join(resolved, part))
                is_final = index == len(parts) - 1
                host = self.raw_host_path(current)

                if os.path.islink(host) and (follow_final_symlink or not is_final):
                    seen_links += 1
                    if seen_links > 40:
                        return host

                    target = os.readlink(host)
                    rest = parts[index + 1 :]
                    if target.startswith("/"):
                        virtual_path = posixpath.join(target, *rest)
                    else:
                        virtual_path = posixpath.join(
                            posixpath.dirname(current), target, *rest
                        )
                    virtual_path = normalize_virtual_path(virtual_path)
                    restarted = True
                    break

                resolved = current

            if not restarted:
                return self.raw_host_path(resolved)

    def virtual_path(
        self, pid: int, path: str, dirfd: int | None = None
    ) -> str | None:
        if path.startswith("/"):
            return normalize_virtual_path(path)

        base = self.cwd_by_pid.get(pid, "/")
        if dirfd is not None and signed64(dirfd) != AT_FDCWD:
            base = self.fd_paths_by_pid.get(pid, {}).get(signed64(dirfd))
            if base is None:
                return None

        return normalize_virtual_path(posixpath.join(base, path))

    def rewrite_syscall_entry(
        self, pid: int, name: str, args: list[int], regs: UserRegsStruct
    ) -> dict[str, object]:
        specs = PATH_ARG_SPECS.get(name)
        metadata: dict[str, object] = {}
        if not specs:
            return metadata

        scratch = TraceeScratch(pid, regs)
        changed = False
        rewritten_paths: list[dict[str, str | int]] = []

        for spec in specs:
            path_address = args[spec.path_index]
            raw_path = read_c_string_bytes(pid, path_address)
            if not raw_path:
                continue

            path = os.fsdecode(raw_path)
            dirfd = args[spec.dirfd_index] if spec.dirfd_index is not None else None
            virtual_path = self.virtual_path(pid, path, dirfd)
            if virtual_path is None:
                continue

            host_path = self.host_path(
                virtual_path, follow_final_symlink=spec.follow_final_symlink
            )
            host_address = scratch.write_c_string(os.fsencode(host_path))
            setattr(regs, ARG_REGISTERS[spec.path_index], host_address)
            changed = True
            rewritten_paths.append(
                {
                    "arg": spec.path_index,
                    "virtual": virtual_path,
                    "host": host_path,
                    "address": host_address,
                }
            )

            if name == "chdir" and spec.path_index == 0:
                metadata["chdir_virtual_path"] = virtual_path

            if name in {"open", "openat"}:
                flags_index = 1 if name == "open" else 2
                flags = signed64(args[flags_index])
                if flags & O_DIRECTORY or os.path.isdir(host_path):
                    metadata["opened_dir_virtual_path"] = virtual_path

            if name in {"execve", "execveat"} and spec.path_index in {0, 1}:
                metadata["exec_virtual_path"] = virtual_path
                metadata["exec_host_path"] = host_path

        if changed:
            set_regs(pid, regs)
            metadata["rewritten_paths"] = rewritten_paths

        return metadata

    def rewrite_getcwd_result(self, context: SyscallContext) -> None:
        if syscall_error(context.result or 0) is not None:
            return

        virtual_cwd = self.cwd_by_pid.get(context.pid, "/")
        data = os.fsencode(virtual_cwd) + b"\x00"
        buffer_address = context.args[0]
        buffer_size = context.args[1]
        regs = context.regs

        if len(data) > buffer_size:
            regs.rax = ctypes.c_ulonglong(-errno.ERANGE).value
            context.result = int(regs.rax)
        else:
            write_tracee_bytes(context.pid, buffer_address, data)
            regs.rax = len(data)
            context.result = int(regs.rax)

        set_regs(context.pid, regs)

    def handle_syscall_exit(
        self, context: SyscallContext, record: SyscallRecord | None
    ) -> None:
        if record is None:
            return

        if record.name == "getcwd":
            self.rewrite_getcwd_result(context)
            return

        if syscall_error(context.result or 0) is not None:
            return

        result = signed64(context.result or 0)
        metadata = record.metadata

        if record.name == "chdir":
            virtual_path = metadata.get("chdir_virtual_path")
            if isinstance(virtual_path, str):
                self.cwd_by_pid[context.pid] = virtual_path
            return

        if record.name in {"open", "openat"}:
            virtual_path = metadata.get("opened_dir_virtual_path")
            if isinstance(virtual_path, str):
                self.fd_paths_by_pid.setdefault(context.pid, {})[result] = virtual_path
            return

        if record.name == "close":
            self.fd_paths_by_pid.setdefault(context.pid, {}).pop(
                signed64(record.args[0]), None
            )
            return

        if record.name == "dup":
            old_fd = signed64(record.args[0])
            virtual_path = self.fd_paths_by_pid.setdefault(context.pid, {}).get(old_fd)
            if virtual_path is not None:
                self.fd_paths_by_pid[context.pid][result] = virtual_path
            return

        if record.name in {"dup2", "dup3"}:
            old_fd = signed64(record.args[0])
            new_fd = signed64(record.args[1])
            fd_paths = self.fd_paths_by_pid.setdefault(context.pid, {})
            fd_paths.pop(new_fd, None)
            virtual_path = fd_paths.get(old_fd)
            if virtual_path is not None:
                fd_paths[new_fd] = virtual_path


ROOTFS: VirtualRoot | None = None
VIRTUAL_IDS: VirtualIds | None = None


def trace_log(message: str, *, file=sys.stdout) -> None:
    if TRACE_LOGGING:
        print(message, file=file, flush=True)


def print_syscall_event(context: SyscallContext) -> None:
    if context.event == "enter":
        trace_log(f"[pid {context.pid}] -> {context.name}({context.rendered_args})")
    elif context.event == "exit":
        trace_log(f"[pid {context.pid}] <- {context.name} = {context.result_text}")


@syscall_handler("*")
def print_syscall(context: SyscallContext) -> None:
    if context.name != "execve":
        print_syscall_event(context)


@syscall_handler("execve")
def handle_execve(context: SyscallContext) -> None:
    print_syscall_event(context)


def syscall_entry(pid: int) -> SyscallRecord:
    regs = get_regs(pid)
    number = int(regs.orig_rax)
    name = SYSCALL_NAMES.get(number, f"syscall_{number}")
    args = [
        int(regs.rdi),
        int(regs.rsi),
        int(regs.rdx),
        int(regs.r10),
        int(regs.r8),
        int(regs.r9),
    ]
    metadata: dict[str, object] = {}
    if ROOTFS is not None:
        metadata.update(ROOTFS.rewrite_syscall_entry(pid, name, args, regs))
    if VIRTUAL_IDS is not None:
        metadata.update(VIRTUAL_IDS.neutralize_syscall(pid, name, regs))

    rendered_args = format_syscall_args(pid, name, args)
    dispatch_syscall_handlers(
        SyscallContext(
            pid=pid,
            event="enter",
            name=name,
            number=number,
            args=args,
            regs=regs,
            rendered_args=rendered_args,
        )
    )
    return SyscallRecord(
        name=name,
        number=number,
        args=args,
        rendered_args=rendered_args,
        metadata=metadata,
    )


def syscall_exit(pid: int, record: SyscallRecord | None) -> None:
    regs = get_regs(pid)
    if record is None:
        number = int(regs.orig_rax)
        name = SYSCALL_NAMES.get(number, f"syscall_{number}")
        args = [
            int(regs.rdi),
            int(regs.rsi),
            int(regs.rdx),
            int(regs.r10),
            int(regs.r8),
            int(regs.r9),
        ]
        rendered_args = format_syscall_args(pid, name, args)
    else:
        number = record.number
        name = record.name
        args = record.args
        rendered_args = record.rendered_args

    context = SyscallContext(
        pid=pid,
        event="exit",
        name=name,
        number=number,
        args=args,
        regs=regs,
        rendered_args=rendered_args,
        result=int(regs.rax),
    )
    if ROOTFS is not None:
        ROOTFS.handle_syscall_exit(context, record)
    if VIRTUAL_IDS is not None:
        VIRTUAL_IDS.handle_syscall_exit(context, record)

    dispatch_syscall_handlers(context)


def resume_syscall(pid: int, sig: int = 0) -> None:
    ptrace(PTRACE_SYSCALL, pid, 0, sig)


def launch_tracee(command: list[str], rootfs: VirtualRoot | None = None) -> int:
    child_pid = os.fork()
    if child_pid == 0:
        try:
            env = os.environ.copy()
            if rootfs is not None:
                os.chdir(rootfs.root)
                env["PWD"] = "/"

            ptrace(PTRACE_TRACEME, 0, 0, 0)
            os.kill(os.getpid(), signal.SIGSTOP)
            os.execvpe(command[0], command, env)
        except OSError as exc:
            os.write(2, f"exec failed: {exc}\n".encode("utf-8"))
            os._exit(127)

    return child_pid


def trace(initial_pids: set[int]) -> int:
    if ROOTFS is not None:
        for pid in initial_pids:
            ROOTFS.register_pid(pid)
    if VIRTUAL_IDS is not None:
        for pid in initial_pids:
            VIRTUAL_IDS.register_pid(pid)

    alive = set(initial_pids)
    configured: set[int] = set()
    in_syscall: dict[int, bool] = {pid: False for pid in initial_pids}
    active_syscalls: dict[int, SyscallRecord] = {}
    exit_code = 0

    try:
        while alive:
            try:
                pid, status = os.waitpid(-1, WAIT_ALL_TRACED)
            except ChildProcessError:
                break
            except InterruptedError:
                continue

            if pid <= 0:
                continue

            if os.WIFEXITED(status):
                code = os.WEXITSTATUS(status)
                trace_log(f"[pid {pid}] exited with status {code}")
                alive.discard(pid)
                configured.discard(pid)
                in_syscall.pop(pid, None)
                active_syscalls.pop(pid, None)
                if ROOTFS is not None:
                    ROOTFS.drop_pid(pid)
                if VIRTUAL_IDS is not None:
                    VIRTUAL_IDS.drop_pid(pid)
                if not alive:
                    exit_code = code
                continue

            if os.WIFSIGNALED(status):
                sig = os.WTERMSIG(status)
                trace_log(f"[pid {pid}] killed by {signal_name(sig)}")
                alive.discard(pid)
                configured.discard(pid)
                in_syscall.pop(pid, None)
                active_syscalls.pop(pid, None)
                if ROOTFS is not None:
                    ROOTFS.drop_pid(pid)
                if VIRTUAL_IDS is not None:
                    VIRTUAL_IDS.drop_pid(pid)
                if not alive:
                    exit_code = 128 + sig
                continue

            if not os.WIFSTOPPED(status):
                continue

            sig = os.WSTOPSIG(status)
            event = status >> 16

            if pid not in alive:
                alive.add(pid)
                in_syscall[pid] = False

            if pid not in configured:
                try:
                    set_trace_options(pid)
                    configured.add(pid)
                except OSError as exc:
                    trace_log(f"[pid {pid}] could not set ptrace options: {exc}")

            if sig == SYSCALL_STOP:
                if in_syscall.get(pid, False):
                    syscall_exit(pid, active_syscalls.pop(pid, None))
                    in_syscall[pid] = False
                else:
                    active_syscalls[pid] = syscall_entry(pid)
                    in_syscall[pid] = True
                resume_syscall(pid)
                continue

            if sig == signal.SIGTRAP and event:
                if event in (PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_CLONE):
                    child_pid = get_event_msg(pid)
                    alive.add(child_pid)
                    in_syscall[child_pid] = False
                    if ROOTFS is not None:
                        ROOTFS.inherit_pid(pid, child_pid)
                    if VIRTUAL_IDS is not None:
                        VIRTUAL_IDS.inherit_pid(pid, child_pid)
                    event_name = {
                        PTRACE_EVENT_FORK: "fork",
                        PTRACE_EVENT_VFORK: "vfork",
                        PTRACE_EVENT_CLONE: "clone",
                    }[event]
                    trace_log(f"[pid {pid}] {event_name} -> new pid {child_pid}")
                elif event == PTRACE_EVENT_EXEC:
                    trace_log(f"[pid {pid}] exec event")
                elif event == PTRACE_EVENT_EXIT:
                    trace_log(f"[pid {pid}] exit event status={get_event_msg(pid)}")

                resume_syscall(pid)
                continue

            trace_log(f"[pid {pid}] stopped by {signal_name(sig)}")
            deliver_signal = 0 if sig in (signal.SIGSTOP, signal.SIGTRAP) else sig
            resume_syscall(pid, deliver_signal)
    except KeyboardInterrupt:
        trace_log("\nInterrupted, detaching tracees...", file=sys.stderr)
        for pid in list(alive):
            try:
                ptrace(PTRACE_DETACH, pid, 0, 0)
            except OSError:
                pass
        return 130

    return exit_code


def parse_virtual_id(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid id: {value}") from exc

    if not 0 <= parsed < NO_ID:
        raise argparse.ArgumentTypeError(f"id must be between 0 and {NO_ID - 1}")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Trace Linux syscalls with ptrace and follow fork/vfork/clone children."
    )
    parser.add_argument(
        "-r",
        "--rootfs",
        help=(
            "treat this host directory as the tracee's virtual / and rewrite "
            "absolute tracee paths through it"
        ),
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress tracer logs and leave only the traced program output",
    )
    parser.add_argument(
        "--uid",
        type=parse_virtual_id,
        help="virtual uid visible to the traced process",
    )
    parser.add_argument(
        "--gid",
        type=parse_virtual_id,
        help="virtual gid visible to the traced process; defaults to --uid if set",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="command to run under tracing; use '--' before the command",
    )
    args = parser.parse_args()

    if args.command and args.command[0] == "--":
        args.command = args.command[1:]

    if not args.command:
        parser.error("pass a command after --")

    if args.rootfs is not None:
        args.rootfs = os.path.abspath(args.rootfs)
        if not os.path.isdir(args.rootfs):
            parser.error(f"--rootfs must be an existing directory: {args.rootfs}")

    if args.uid is not None and args.gid is None:
        args.gid = args.uid
    elif args.uid is None and args.gid is not None:
        args.uid = os.getuid()

    return args


def ensure_supported_architecture() -> None:
    machine = platform.machine().lower()
    if machine not in {"x86_64", "amd64"} or WORD_SIZE != 8:
        raise SystemExit(
            "This tracer currently supports only Linux x86_64 processes."
        )


def main() -> int:
    global ROOTFS, TRACE_LOGGING, VIRTUAL_IDS

    ensure_supported_architecture()
    args = parse_args()
    TRACE_LOGGING = not args.quiet
    ROOTFS = VirtualRoot(args.rootfs) if args.rootfs is not None else None
    VIRTUAL_IDS = (
        VirtualIds(args.uid, args.gid)
        if args.uid is not None and args.gid is not None
        else None
    )
    return trace({launch_tracee(args.command, ROOTFS)})


if __name__ == "__main__":
    raise SystemExit(main())
