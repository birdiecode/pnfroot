import errno
import os
import shutil
import signal
import sys

import ptrace_syscalls
from virtual_paths import VirtualRoot, read_elf_interpreter


def stopped_status(sig: int, event: int = 0) -> int:
    return (event << 16) | (sig << 8) | 0x7F


def missing_process(*args, **kwargs) -> None:
    raise ProcessLookupError(errno.ESRCH, os.strerror(errno.ESRCH))


def test_trace_ignores_process_that_disappears_before_resume(monkeypatch) -> None:
    status = stopped_status(signal.SIGTRAP, ptrace_syscalls.PTRACE_EVENT_EXEC)
    monkeypatch.setattr(ptrace_syscalls.os, "waitpid", lambda *args: (123, status))
    monkeypatch.setattr(ptrace_syscalls, "set_trace_options", lambda pid: None)
    monkeypatch.setattr(ptrace_syscalls, "resume_syscall", missing_process)

    assert ptrace_syscalls.trace({123}) == 0


def test_trace_ignores_process_that_disappears_at_syscall_stop(monkeypatch) -> None:
    status = stopped_status(ptrace_syscalls.SYSCALL_STOP)
    monkeypatch.setattr(ptrace_syscalls.os, "waitpid", lambda *args: (123, status))
    monkeypatch.setattr(ptrace_syscalls, "set_trace_options", lambda pid: None)
    monkeypatch.setattr(ptrace_syscalls, "syscall_entry", missing_process)

    assert ptrace_syscalls.trace({123}) == 0


def test_parse_args_accepts_repeatable_dns_server(monkeypatch, tmp_path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ptrace_syscalls.py",
            "--rootfs",
            str(rootfs),
            "--dns-server",
            "8.8.8.8",
            "--dns",
            "1.1.1.1",
            "--",
            "/bin/sh",
        ],
    )

    args = ptrace_syscalls.parse_args()

    assert args.dns == ["8.8.8.8", "1.1.1.1"]


def test_rootfs_exec_command_uses_rootfs_loader_for_dynamic_elf(tmp_path) -> None:
    rootfs = tmp_path / "rootfs"
    executable = rootfs / "bin" / "echo"
    executable.parent.mkdir(parents=True)
    shutil.copy2("/bin/echo", executable)

    interpreter = read_elf_interpreter(str(executable))
    assert interpreter is not None
    interpreter_path = rootfs.joinpath(*interpreter.lstrip("/").split("/"))
    interpreter_path.parent.mkdir(parents=True, exist_ok=True)
    interpreter_path.write_bytes(b"loader")

    command = ptrace_syscalls.rootfs_exec_command(
        ["/bin/echo", "ok"],
        VirtualRoot(str(rootfs)),
    )

    assert command == [
        str(interpreter_path),
        "--argv0",
        "/bin/echo",
        str(executable),
        "ok",
    ]


def test_rootfs_exec_command_resolves_rootfs_symlink_before_loader(tmp_path) -> None:
    rootfs = tmp_path / "rootfs"
    busybox = rootfs / "bin" / "busybox"
    busybox.parent.mkdir(parents=True)
    shutil.copy2("/bin/echo", busybox)
    (rootfs / "bin" / "sh").symlink_to("/bin/busybox")

    interpreter = read_elf_interpreter(str(busybox))
    assert interpreter is not None
    interpreter_path = rootfs.joinpath(*interpreter.lstrip("/").split("/"))
    interpreter_path.parent.mkdir(parents=True, exist_ok=True)
    interpreter_path.write_bytes(b"loader")

    command = ptrace_syscalls.rootfs_exec_command(
        ["/bin/sh", "-c", "echo ok"],
        VirtualRoot(str(rootfs)),
    )

    assert command == [
        str(interpreter_path),
        "--argv0",
        "/bin/sh",
        str(busybox),
        "-c",
        "echo ok",
    ]


def test_read_elf_interpreter_returns_none_when_interp_is_absent() -> None:
    loader = "/lib64/ld-linux-x86-64.so.2"
    if not os.path.exists(loader):
        return

    assert read_elf_interpreter(loader) is None
