#!/usr/bin/env python3
"""Small Linux syscall tracer based on ptrace.

Usage examples:
    sudo ./ptrace_syscalls.py -- /bin/ls -la

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
import re
import signal
import sys
from collections.abc import Callable
from dataclasses import dataclass


PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_GETREGS = 12
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
            print(
                f"[pid {context.pid}] handler {handler.__name__} failed: {exc}",
                file=sys.stderr,
                flush=True,
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


def set_trace_options(pid: int) -> None:
    ptrace(PTRACE_SETOPTIONS, pid, 0, TRACE_OPTIONS)


def get_regs(pid: int) -> UserRegsStruct:
    regs = UserRegsStruct()
    ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs))
    return regs


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


def read_c_string(pid: int, address: int, max_bytes: int = 4096) -> str:
    if address == 0:
        return "NULL"

    data = bytearray()
    try:
        for offset in range(0, max_bytes, WORD_SIZE):
            word = ptrace_peek(pid, address + offset)
            chunk = word.to_bytes(WORD_SIZE, sys.byteorder)
            nul = chunk.find(b"\x00")
            if nul != -1:
                data.extend(chunk[:nul])
                return quote_bytes(bytes(data))
            data.extend(chunk)
    except OSError:
        return hex_or_null(address)

    return quote_bytes(bytes(data))[:-1] + '..."'


def read_pointer(pid: int, address: int) -> int:
    word = ptrace_peek(pid, address)
    mask = (1 << (WORD_SIZE * 8)) - 1
    return word & mask


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


def print_syscall_event(context: SyscallContext) -> None:
    if context.event == "enter":
        print(
            f"[pid {context.pid}] -> {context.name}({context.rendered_args})",
            flush=True,
        )
    elif context.event == "exit":
        print(
            f"[pid {context.pid}] <- {context.name} = {context.result_text}",
            flush=True,
        )


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
    return SyscallRecord(name=name, number=number, args=args, rendered_args=rendered_args)


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

    dispatch_syscall_handlers(
        SyscallContext(
            pid=pid,
            event="exit",
            name=name,
            number=number,
            args=args,
            regs=regs,
            rendered_args=rendered_args,
            result=int(regs.rax),
        )
    )


def resume_syscall(pid: int, sig: int = 0) -> None:
    ptrace(PTRACE_SYSCALL, pid, 0, sig)


def launch_tracee(command: list[str]) -> int:
    child_pid = os.fork()
    if child_pid == 0:
        try:
            ptrace(PTRACE_TRACEME, 0, 0, 0)
            os.kill(os.getpid(), signal.SIGSTOP)
            os.execvp(command[0], command)
        except OSError as exc:
            os.write(2, f"exec failed: {exc}\n".encode("utf-8"))
            os._exit(127)

    return child_pid


def trace(initial_pids: set[int]) -> int:
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
                print(f"[pid {pid}] exited with status {code}", flush=True)
                alive.discard(pid)
                configured.discard(pid)
                in_syscall.pop(pid, None)
                active_syscalls.pop(pid, None)
                if not alive:
                    exit_code = code
                continue

            if os.WIFSIGNALED(status):
                sig = os.WTERMSIG(status)
                print(f"[pid {pid}] killed by {signal_name(sig)}", flush=True)
                alive.discard(pid)
                configured.discard(pid)
                in_syscall.pop(pid, None)
                active_syscalls.pop(pid, None)
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
                    print(f"[pid {pid}] could not set ptrace options: {exc}", flush=True)

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
                    event_name = {
                        PTRACE_EVENT_FORK: "fork",
                        PTRACE_EVENT_VFORK: "vfork",
                        PTRACE_EVENT_CLONE: "clone",
                    }[event]
                    print(f"[pid {pid}] {event_name} -> new pid {child_pid}", flush=True)
                elif event == PTRACE_EVENT_EXEC:
                    print(f"[pid {pid}] exec event", flush=True)
                elif event == PTRACE_EVENT_EXIT:
                    print(f"[pid {pid}] exit event status={get_event_msg(pid)}", flush=True)

                resume_syscall(pid)
                continue

            print(f"[pid {pid}] stopped by {signal_name(sig)}", flush=True)
            deliver_signal = 0 if sig in (signal.SIGSTOP, signal.SIGTRAP) else sig
            resume_syscall(pid, deliver_signal)
    except KeyboardInterrupt:
        print("\nInterrupted, detaching tracees...", file=sys.stderr)
        for pid in list(alive):
            try:
                ptrace(PTRACE_DETACH, pid, 0, 0)
            except OSError:
                pass
        return 130

    return exit_code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Trace Linux syscalls with ptrace and follow fork/vfork/clone children."
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

    return args


def ensure_supported_architecture() -> None:
    machine = platform.machine().lower()
    if machine not in {"x86_64", "amd64"} or WORD_SIZE != 8:
        raise SystemExit(
            "This tracer currently supports only Linux x86_64 processes."
        )


def main() -> int:
    ensure_supported_architecture()
    args = parse_args()
    return trace({launch_tracee(args.command)})


if __name__ == "__main__":
    raise SystemExit(main())
