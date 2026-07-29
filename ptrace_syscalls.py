#!/usr/bin/env python3
"""Small Linux syscall tracer based on ptrace.

Usage examples:
    ./ptrace_syscalls.py -- /bin/ls -la
    ./ptrace_syscalls.py --rootfs ./ubuntu_c -- /bin/bash
    ./ptrace_syscalls.py --rootfs ./ubuntu_c --uid 0 --gid 0 -- /bin/bash
    ./ptrace_syscalls.py --rootfs ./ubuntu_c --bind /tmp:/host-tmp -- /bin/ls /host-tmp
    ./ptrace_syscalls.py --netdev name=eth0,network=backend --netservice /tmp/net.unix -- /bin/bash

This script is intentionally dependency-free. It currently supports Linux
x86_64, where syscall arguments live in rdi, rsi, rdx, r10, r8, r9.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import os
import platform
import signal
import sys
import termios
from collections.abc import Callable

from ptrace_common import (
    PTRACE_DETACH,
    PTRACE_EVENT_CLONE,
    PTRACE_EVENT_EXEC,
    PTRACE_EVENT_EXIT,
    PTRACE_EVENT_FORK,
    PTRACE_EVENT_VFORK,
    PTRACE_SYSCALL,
    PTRACE_TRACEME,
    SYSCALL_NAMES,
    SYSCALL_NUMBERS,
    SYSCALL_STOP,
    WAIT_ALL_TRACED,
    WORD_SIZE,
    SyscallContext,
    SyscallRecord,
    get_event_msg,
    get_regs,
    hex_or_null,
    ptrace,
    read_c_string,
    read_string_array,
    set_regs,
    set_syscall_result,
    set_trace_options,
    signal_name,
)
from virtual_ids import NO_ID, VirtualIds
from virtual_network import (
    ContainerNetworkConfig,
    NetworkServiceError,
    VirtualNetworkRuntime,
    generate_container_id,
    parse_netdev,
    parse_publish,
)
from virtual_paths import BindMount, VirtualRoot, normalize_virtual_path, read_elf_interpreter


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
    "mount": {0, 1, 2},
    "symlink": {0, 1},
    "umount": {0},
    "umount2": {0},
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


SyscallHandler = Callable[[SyscallContext], None]
SYSCALL_HANDLERS: dict[str, list[tuple[str, SyscallHandler]]] = {}
TRACE_LOGGING = False
ROOTFS: VirtualRoot | None = None
VIRTUAL_IDS: VirtualIds | None = None
VIRTUAL_NETWORK: VirtualNetworkRuntime | None = None
NOOP_SYSCALL_NUMBER = SYSCALL_NUMBERS.get("getpid", 39)


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


def trace_log(message: str, *, file=sys.stdout) -> None:
    if TRACE_LOGGING:
        print(message, file=file, flush=True)


def dispatch_syscall_handlers(context: SyscallContext) -> None:
    if not TRACE_LOGGING:
        return

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
    if name == "rseq":
        regs.orig_rax = NOOP_SYSCALL_NUMBER
        set_regs(pid, regs)
        metadata["forced_result"] = -errno.ENOSYS
    if ROOTFS is not None:
        metadata.update(ROOTFS.rewrite_syscall_entry(pid, name, args, regs))
    if VIRTUAL_IDS is not None:
        metadata.update(VIRTUAL_IDS.neutralize_syscall(pid, name, regs))
    if VIRTUAL_NETWORK is not None:
        metadata.update(VIRTUAL_NETWORK.rewrite_syscall_entry(pid, name, args, regs))

    rendered_args = format_syscall_args(pid, name, args) if TRACE_LOGGING else ""
    if TRACE_LOGGING:
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
        rendered_args = format_syscall_args(pid, name, args) if TRACE_LOGGING else ""
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
    if VIRTUAL_NETWORK is not None:
        VIRTUAL_NETWORK.handle_syscall_exit(context, record)
    if record is not None and "forced_result" in record.metadata:
        set_syscall_result(context, int(record.metadata["forced_result"]))

    if TRACE_LOGGING:
        dispatch_syscall_handlers(context)


def resume_syscall(pid: int, sig: int = 0) -> None:
    ptrace(PTRACE_SYSCALL, pid, 0, sig)


def process_is_gone(exc: OSError) -> bool:
    return exc.errno == errno.ESRCH


def read_script_interpreter(path: str) -> list[str] | None:
    try:
        with open(path, "rb") as handle:
            line = handle.readline(256)
    except OSError:
        return None
    if not line.startswith(b"#!"):
        return None
    text = os.fsdecode(line[2:].strip())
    return text.split() or None


def rootfs_exec_command(command: list[str], rootfs: VirtualRoot) -> list[str]:
    if not command or not command[0].startswith("/"):
        return command

    virtual_executable = normalize_virtual_path(command[0])
    host_executable = rootfs.raw_host_path(virtual_executable)

    script_interpreter = read_script_interpreter(host_executable)
    if script_interpreter:
        interpreter = script_interpreter[0]
        if interpreter.startswith("/"):
            rewritten = rootfs_exec_command([interpreter, *script_interpreter[1:], virtual_executable, *command[1:]], rootfs)
            return rewritten if rewritten[0] != interpreter else command
        return command

    elf_interpreter = read_elf_interpreter(host_executable)
    if elf_interpreter and rootfs.should_use_direct_loader(host_executable):
        host_interpreter = rootfs.raw_host_path(elf_interpreter)
        if os.path.exists(host_interpreter):
            return [host_interpreter, "--argv0", command[0], host_executable, *command[1:]]

    return command


def launch_tracee(
    command: list[str],
    rootfs: VirtualRoot | None = None,
    cwd: str = "/",
    env: dict[str, str] | None = None,
    stdin_fd: int | None = None,
    stdout_fd: int | None = None,
    stderr_fd: int | None = None,
    controlling_tty: bool = False,
) -> int:
    child_pid = os.fork()
    if child_pid == 0:
        try:
            exec_command = command
            child_env = os.environ.copy() if env is None else dict(env)
            if rootfs is not None:
                os.chdir(rootfs.raw_host_path(cwd))
                child_env["PWD"] = cwd
                exec_command = rootfs_exec_command(command, rootfs)

            if controlling_tty:
                os.setsid()
                tty_fd = stdin_fd if stdin_fd is not None else stdout_fd
                if tty_fd is not None:
                    fcntl.ioctl(tty_fd, termios.TIOCSCTTY, 0)

            for target_fd, source_fd in (
                (0, stdin_fd),
                (1, stdout_fd),
                (2, stderr_fd),
            ):
                if source_fd is not None:
                    os.dup2(source_fd, target_fd)

            try:
                open_max = os.sysconf("SC_OPEN_MAX")
            except (OSError, ValueError):
                open_max = 1024
            os.closerange(3, min(int(open_max), 65536))

            ptrace(PTRACE_TRACEME, 0, 0, 0)
            os.kill(os.getpid(), signal.SIGSTOP)
            os.execvpe(exec_command[0], exec_command, child_env)
        except OSError as exc:
            os.write(2, f"exec failed: {exc}\n".encode("utf-8"))
            os._exit(127)

    return child_pid


def run_tracee(
    command: list[str],
    *,
    rootfs_path: str | None = None,
    binds: list[BindMount] | None = None,
    cwd: str = "/",
    env: dict[str, str] | None = None,
    stdin_fd: int | None = None,
    stdout_fd: int | None = None,
    stderr_fd: int | None = None,
    controlling_tty: bool = False,
    uid: int | None = None,
    gid: int | None = None,
    network_config: ContainerNetworkConfig | None = None,
    trace_logging: bool = False,
) -> int:
    global ROOTFS, TRACE_LOGGING, VIRTUAL_IDS, VIRTUAL_NETWORK

    ensure_supported_architecture()
    cwd = normalize_virtual_path(cwd)
    TRACE_LOGGING = trace_logging
    ROOTFS = (
        VirtualRoot(rootfs_path, binds=binds or [])
        if rootfs_path is not None
        else None
    )
    VIRTUAL_IDS = (
        VirtualIds(uid, gid)
        if uid is not None and gid is not None
        else None
    )
    VIRTUAL_NETWORK = (
        VirtualNetworkRuntime(network_config)
        if network_config is not None
        else None
    )

    child_pid = launch_tracee(
        command,
        ROOTFS,
        cwd,
        env=env,
        stdin_fd=stdin_fd,
        stdout_fd=stdout_fd,
        stderr_fd=stderr_fd,
        controlling_tty=controlling_tty,
    )
    for fd in {stdin_fd, stdout_fd, stderr_fd} - {None}:
        try:
            os.close(fd)
        except OSError:
            pass

    try:
        if VIRTUAL_NETWORK is not None:
            VIRTUAL_NETWORK.register_container(child_pid)
        return trace({child_pid}, initial_cwd=cwd)
    except NetworkServiceError as exc:
        print(str(exc), file=sys.stderr)
        try:
            os.kill(child_pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(child_pid, 0)
        except OSError:
            pass
        return 125
    finally:
        if VIRTUAL_NETWORK is not None:
            VIRTUAL_NETWORK.unregister_container()


def trace(initial_pids: set[int], initial_cwd: str = "/") -> int:
    if ROOTFS is not None:
        for pid in initial_pids:
            ROOTFS.register_pid(pid, initial_cwd)
    if VIRTUAL_IDS is not None:
        for pid in initial_pids:
            VIRTUAL_IDS.register_pid(pid)
    if VIRTUAL_NETWORK is not None:
        for pid in initial_pids:
            VIRTUAL_NETWORK.register_pid(pid)

    alive = set(initial_pids)
    configured: set[int] = set()
    in_syscall: dict[int, bool] = {pid: False for pid in initial_pids}
    active_syscalls: dict[int, SyscallRecord] = {}
    exit_code = 0

    def forget_pid(pid: int) -> None:
        alive.discard(pid)
        configured.discard(pid)
        in_syscall.pop(pid, None)
        active_syscalls.pop(pid, None)
        if ROOTFS is not None:
            ROOTFS.drop_pid(pid)
        if VIRTUAL_IDS is not None:
            VIRTUAL_IDS.drop_pid(pid)
        if VIRTUAL_NETWORK is not None:
            VIRTUAL_NETWORK.drop_pid(pid)

    def try_resume(pid: int, sig: int = 0) -> bool:
        try:
            resume_syscall(pid, sig)
        except OSError as exc:
            if not process_is_gone(exc):
                raise
            trace_log(f"[pid {pid}] disappeared before ptrace resume")
            forget_pid(pid)
            return False
        return True

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
                forget_pid(pid)
                if not alive:
                    exit_code = code
                continue

            if os.WIFSIGNALED(status):
                sig = os.WTERMSIG(status)
                trace_log(f"[pid {pid}] killed by {signal_name(sig)}")
                forget_pid(pid)
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
                    if process_is_gone(exc):
                        forget_pid(pid)
                        continue
                    trace_log(f"[pid {pid}] could not set ptrace options: {exc}")

            if sig == SYSCALL_STOP:
                try:
                    if in_syscall.get(pid, False):
                        syscall_exit(pid, active_syscalls.pop(pid, None))
                        in_syscall[pid] = False
                    else:
                        active_syscalls[pid] = syscall_entry(pid)
                        in_syscall[pid] = True
                except OSError as exc:
                    if not process_is_gone(exc):
                        raise
                    forget_pid(pid)
                    continue
                try_resume(pid)
                continue

            if sig == signal.SIGTRAP and event:
                try:
                    if event in (PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_CLONE):
                        child_pid = get_event_msg(pid)
                        alive.add(child_pid)
                        in_syscall[child_pid] = False
                        if ROOTFS is not None:
                            ROOTFS.inherit_pid(pid, child_pid)
                        if VIRTUAL_IDS is not None:
                            VIRTUAL_IDS.inherit_pid(pid, child_pid)
                        if VIRTUAL_NETWORK is not None:
                            VIRTUAL_NETWORK.inherit_pid(pid, child_pid)
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
                except OSError as exc:
                    if not process_is_gone(exc):
                        raise
                    forget_pid(pid)
                    continue

                try_resume(pid)
                continue

            trace_log(f"[pid {pid}] stopped by {signal_name(sig)}")
            deliver_signal = 0 if sig in (signal.SIGSTOP, signal.SIGTRAP) else sig
            try_resume(pid, deliver_signal)
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


def parse_bind_mount(value: str) -> BindMount:
    if ":" in value:
        host_path, virtual_path = value.split(":", 1)
        if not host_path or not virtual_path:
            raise argparse.ArgumentTypeError(
                "bind must be HOST:VIRTUAL or HOST"
            )
    else:
        host_path = value
        virtual_path = os.path.abspath(value)

    host_path = os.path.abspath(host_path)
    if not os.path.exists(host_path):
        raise argparse.ArgumentTypeError(f"bind host path does not exist: {host_path}")

    return BindMount.from_paths(host_path, virtual_path)


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
        help="deprecated no-op; tracer logs are disabled by default",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        "--log",
        dest="verbose",
        action="store_true",
        help="enable tracer syscall logs",
    )
    parser.add_argument(
        "-b",
        "--bind",
        action="append",
        default=[],
        type=parse_bind_mount,
        metavar="HOST[:VIRTUAL]",
        help=(
            "bind a host path into the virtual root; repeatable, and HOST alone "
            "binds it at the same absolute path; missing targets are created "
            "inside the rootfs"
        ),
    )
    parser.add_argument(
        "--cwd",
        default="/",
        help="initial working directory visible inside the virtual rootfs",
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
        "--netdev",
        action="append",
        default=[],
        type=parse_netdev,
        metavar="FIELD=VALUE,...",
        help=(
            "virtual network interface description; repeatable. Required fields "
            "are name and network, optional fields are ip, gateway, mac, mtu, dns"
        ),
    )
    parser.add_argument(
        "--netservice",
        metavar="UNIX_SOCKET",
        help="Unix stream socket path for the external virtual network service",
    )
    parser.add_argument(
        "-p",
        "--publish",
        action="append",
        default=[],
        type=parse_publish,
        metavar="[HOST_IP:]HOST_PORT:CONTAINER_PORT[/tcp]",
        help=(
            "publish a container TCP port on the host through netservice; "
            "repeatable, default HOST_IP is 127.0.0.1"
        ),
    )
    parser.add_argument(
        "--container-id",
        help="stable container id sent to the virtual network service",
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
    elif args.bind:
        parser.error("--bind requires --rootfs")

    args.cwd = normalize_virtual_path(args.cwd)
    if args.rootfs is None and args.cwd != "/":
        parser.error("--cwd requires --rootfs")

    if args.uid is not None and args.gid is None:
        args.gid = args.uid
    elif args.uid is None and args.gid is not None:
        args.uid = os.getuid()

    if args.netdev and not args.netservice:
        parser.error("--netdev requires --netservice")
    if args.publish and not args.netdev:
        parser.error("--publish requires --netdev")

    if args.netservice is not None:
        args.netservice = os.path.abspath(args.netservice)

    if args.netdev:
        seen_interfaces: set[str] = set()
        for interface in args.netdev:
            if interface.name in seen_interfaces:
                parser.error(f"duplicate --netdev interface name: {interface.name}")
            seen_interfaces.add(interface.name)
        args.container_id = args.container_id or generate_container_id()
        args.network_config = ContainerNetworkConfig(
            container_id=args.container_id,
            interfaces=args.netdev,
            service_socket=args.netservice,
            published_ports=args.publish,
        )
    else:
        args.network_config = None

    return args


def ensure_supported_architecture() -> None:
    machine = platform.machine().lower()
    if machine not in {"x86_64", "amd64"} or WORD_SIZE != 8:
        raise SystemExit(
            "This tracer currently supports only Linux x86_64 processes."
        )


def main() -> int:
    args = parse_args()
    return run_tracee(
        args.command,
        rootfs_path=args.rootfs,
        binds=args.bind,
        cwd=args.cwd,
        uid=args.uid,
        gid=args.gid,
        network_config=args.network_config,
        trace_logging=bool(args.verbose),
    )


if __name__ == "__main__":
    raise SystemExit(main())
