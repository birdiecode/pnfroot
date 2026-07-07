"""Virtual root filesystem path translation for traced processes."""

from __future__ import annotations

import errno
import os
import posixpath
from dataclasses import dataclass

from ptrace_common import (
    ARG_REGISTERS,
    SyscallContext,
    SyscallRecord,
    UserRegsStruct,
    WORD_SIZE,
    read_c_string_bytes,
    set_regs,
    set_syscall_result,
    signed64,
    syscall_error,
    write_tracee_bytes,
)


AT_FDCWD = -100
O_DIRECTORY = 0o200000
SCRATCH_STACK_GAP = 256


@dataclass(frozen=True)
class PathArgSpec:
    path_index: int
    dirfd_index: int | None = None
    follow_final_symlink: bool = True


@dataclass(frozen=True)
class BindMount:
    host_path: str
    virtual_path: str

    @classmethod
    def from_paths(cls, host_path: str, virtual_path: str) -> BindMount:
        return cls(
            host_path=os.path.realpath(host_path),
            virtual_path=normalize_virtual_path(virtual_path),
        )


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


class TraceeScratch:
    def __init__(self, pid: int, regs: UserRegsStruct):
        self.pid = pid
        self.cursor = int(regs.rsp) - SCRATCH_STACK_GAP

    def write_c_string(self, value: bytes) -> int:
        data = value + b"\x00"
        self.cursor = (self.cursor - len(data)) & ~(WORD_SIZE - 1)
        write_tracee_bytes(self.pid, self.cursor, data)
        return self.cursor


class VirtualRoot:
    def __init__(self, root: str, binds: list[BindMount] | None = None):
        self.root = os.path.abspath(root)
        self.binds = sorted(
            binds or [],
            key=lambda bind: len(split_virtual_path(bind.virtual_path)),
            reverse=True,
        )
        self.ensure_bind_mountpoints()
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
        bind = self.bind_for(virtual_path)
        if bind is not None:
            if virtual_path == bind.virtual_path:
                return bind.host_path
            relative = posixpath.relpath(virtual_path, bind.virtual_path)
            return os.path.join(bind.host_path, *split_virtual_path(relative))

        if virtual_path == "/":
            return self.root
        return os.path.join(self.root, virtual_path[1:])

    def rootfs_backing_path(self, virtual_path: str) -> str:
        virtual_path = normalize_virtual_path(virtual_path)
        if virtual_path == "/":
            return self.root
        return os.path.join(self.root, *split_virtual_path(virtual_path))

    def ensure_bind_mountpoints(self) -> None:
        for bind in self.binds:
            self.ensure_bind_mountpoint(bind)

    def ensure_bind_mountpoint(self, bind: BindMount) -> None:
        if bind.virtual_path == "/":
            return

        target = self.rootfs_backing_path(bind.virtual_path)
        parent = os.path.dirname(target)
        self.ensure_path_stays_under_root(parent)
        os.makedirs(parent, exist_ok=True)

        if os.path.isdir(bind.host_path):
            if os.path.exists(target) and not os.path.isdir(target):
                raise RuntimeError(
                    f"bind target exists and is not a directory: {bind.virtual_path}"
                )
            os.makedirs(target, exist_ok=True)
            return

        if os.path.isdir(target):
            raise RuntimeError(
                f"bind target exists as a directory for file bind: {bind.virtual_path}"
            )
        if not os.path.exists(target):
            open(target, "a", encoding="utf-8").close()

    def ensure_path_stays_under_root(self, path: str) -> None:
        root = os.path.realpath(self.root)
        resolved = os.path.realpath(path)
        if os.path.commonpath([root, resolved]) != root:
            raise RuntimeError(f"bind target escapes rootfs: {path}")

    def bind_for(self, virtual_path: str) -> BindMount | None:
        virtual_path = normalize_virtual_path(virtual_path)
        for bind in self.binds:
            if virtual_path == bind.virtual_path:
                return bind
            if bind.virtual_path == "/":
                return bind
            if virtual_path.startswith(bind.virtual_path.rstrip("/") + "/"):
                return bind
        return None

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

        if len(data) > buffer_size:
            set_syscall_result(context, -errno.ERANGE)
        else:
            write_tracee_bytes(context.pid, buffer_address, data)
            set_syscall_result(context, len(data))

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
