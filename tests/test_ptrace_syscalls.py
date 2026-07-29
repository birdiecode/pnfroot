import errno
import os
import signal

import ptrace_syscalls


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
