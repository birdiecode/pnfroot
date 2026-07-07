"""Virtual root filesystem path translation for traced processes."""

from __future__ import annotations

import errno
import os
import posixpath
import stat as stat_module
import tempfile
from dataclasses import dataclass

from ptrace_common import (
    ARG_REGISTERS,
    SYSCALL_NUMBERS,
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
AT_SYMLINK_NOFOLLOW = 0x100
O_DIRECTORY = 0o200000
O_ACCMODE = 0o3
O_TMPFILE = 0o20200000
SCRATCH_STACK_GAP = 256
MS_BIND = 4096
MS_REC = 16384
VIRTUAL_MOUNT_FILES = {
    "/etc/mtab": "mounts",
    "/proc/mounts": "mounts",
    "/proc/self/mounts": "mounts",
    "/proc/self/mountinfo": "mountinfo",
}
VIRTUAL_PROC_FILES = {
    "/proc/filesystems": "filesystems",
}
VIRTUAL_MOUNT_FILE_SYSCALLS = {
    "access",
    "faccessat",
    "faccessat2",
    "lstat",
    "newfstatat",
    "newlstat",
    "newstat",
    "open",
    "openat",
    "stat",
    "statx",
}
VIRTUAL_SPECIAL_PATH_SYSCALLS = VIRTUAL_MOUNT_FILE_SYSCALLS | {
    "readlink",
    "readlinkat",
}
VIRTUAL_DEVICE_PATHS = {
    "/dev/console": "/dev/console",
    "/dev/fd": "/dev/fd",
    "/dev/full": "/dev/full",
    "/dev/null": "/dev/null",
    "/dev/ptmx": "/dev/ptmx",
    "/dev/random": "/dev/random",
    "/dev/stderr": "/dev/stderr",
    "/dev/stdin": "/dev/stdin",
    "/dev/stdout": "/dev/stdout",
    "/dev/tty": "/dev/tty",
    "/dev/urandom": "/dev/urandom",
    "/dev/zero": "/dev/zero",
}
VIRTUAL_DEVICE_PREFIXES = {
    "/dev/fd": "/dev/fd",
    "/dev/pts": "/dev/pts",
}
VIRTUAL_PROC_READONLY_PATHS = {
    "/proc/cpuinfo": "/proc/cpuinfo",
    "/proc/loadavg": "/proc/loadavg",
    "/proc/meminfo": "/proc/meminfo",
    "/proc/stat": "/proc/stat",
    "/proc/sys/kernel/hostname": "/proc/sys/kernel/hostname",
    "/proc/sys/kernel/osrelease": "/proc/sys/kernel/osrelease",
    "/proc/sys/kernel/ostype": "/proc/sys/kernel/ostype",
    "/proc/uptime": "/proc/uptime",
    "/proc/version": "/proc/version",
}
VIRTUAL_PROC_PREFIXES = {
    "/proc/self/fd": "/proc/self/fd",
    "/proc/thread-self/fd": "/proc/thread-self/fd",
}
WRITE_PARENT_SYSCALLS = {
    "creat",
    "link",
    "linkat",
    "mkdir",
    "mkdirat",
    "mknodat",
    "rename",
    "renameat",
    "renameat2",
    "rmdir",
    "symlink",
    "symlinkat",
    "unlink",
    "unlinkat",
}


@dataclass(frozen=True)
class PathArgSpec:
    path_index: int
    dirfd_index: int | None = None
    follow_final_symlink: bool = True
    nofollow_flag_index: int | None = None

    def follows_final_symlink(self, args: list[int]) -> bool:
        if self.nofollow_flag_index is None:
            return self.follow_final_symlink
        if signed64(args[self.nofollow_flag_index]) & AT_SYMLINK_NOFOLLOW:
            return False
        return self.follow_final_symlink


@dataclass(frozen=True)
class BindMount:
    host_path: str
    virtual_path: str
    source_display: str | None = None
    recursive: bool = False
    origin: str = "cli"

    @classmethod
    def from_paths(
        cls,
        host_path: str,
        virtual_path: str,
        *,
        source_display: str | None = None,
        recursive: bool = False,
        origin: str = "cli",
    ) -> BindMount:
        return cls(
            host_path=os.path.realpath(host_path),
            virtual_path=normalize_virtual_path(virtual_path),
            source_display=source_display,
            recursive=recursive,
            origin=origin,
        )


PATH_ARG_SPECS: dict[str, tuple[PathArgSpec, ...]] = {
    "open": (PathArgSpec(0),),
    "creat": (PathArgSpec(0, follow_final_symlink=False),),
    "access": (PathArgSpec(0),),
    "faccessat": (PathArgSpec(1, dirfd_index=0),),
    "faccessat2": (PathArgSpec(1, dirfd_index=0, nofollow_flag_index=3),),
    "stat": (PathArgSpec(0),),
    "lstat": (PathArgSpec(0, follow_final_symlink=False),),
    "newstat": (PathArgSpec(0),),
    "newlstat": (PathArgSpec(0, follow_final_symlink=False),),
    "statx": (PathArgSpec(1, dirfd_index=0, nofollow_flag_index=2),),
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
    "fchownat": (PathArgSpec(1, dirfd_index=0, nofollow_flag_index=4),),
    "futimesat": (PathArgSpec(1, dirfd_index=0),),
    "utimensat": (PathArgSpec(1, dirfd_index=0, nofollow_flag_index=3),),
    "newfstatat": (PathArgSpec(1, dirfd_index=0, nofollow_flag_index=3),),
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


def escape_mount_field(value: str) -> str:
    return (
        value.replace("\\", "\\134")
        .replace(" ", "\\040")
        .replace("\t", "\\011")
        .replace("\n", "\\012")
    )


def prefixed_host_path(
    virtual_path: str, virtual_prefix: str, host_prefix: str
) -> str | None:
    if virtual_path == virtual_prefix:
        return host_prefix
    if not virtual_path.startswith(virtual_prefix.rstrip("/") + "/"):
        return None

    relative = posixpath.relpath(virtual_path, virtual_prefix)
    return os.path.join(host_prefix, *split_virtual_path(relative))


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
        self.noop_syscall_number = SYSCALL_NUMBERS.get("getpid", 39)

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

    def rootfs_host_path_to_virtual(self, host_path: str) -> str | None:
        root = os.path.realpath(self.root)
        resolved = os.path.realpath(host_path)
        try:
            if os.path.commonpath([root, resolved]) != root:
                return None
        except ValueError:
            return None

        if resolved == root:
            return "/"

        relative = os.path.relpath(resolved, root)
        return normalize_virtual_path("/" + "/".join(relative.split(os.sep)))

    def ensure_bind_mountpoints(self) -> None:
        for bind in self.binds:
            self.ensure_bind_mountpoint(bind)

    def add_bind(self, bind: BindMount) -> None:
        self.binds = [
            existing
            for existing in self.binds
            if existing.virtual_path != bind.virtual_path
        ]
        self.binds.append(bind)
        self.binds.sort(
            key=lambda item: len(split_virtual_path(item.virtual_path)),
            reverse=True,
        )
        self.ensure_bind_mountpoint(bind)

    def remove_bind(self, virtual_path: str) -> bool:
        virtual_path = normalize_virtual_path(virtual_path)
        old_count = len(self.binds)
        self.binds = [
            bind for bind in self.binds if bind.virtual_path != virtual_path
        ]
        return len(self.binds) != old_count

    def virtual_mount_file_kind(self, virtual_path: str) -> str | None:
        return VIRTUAL_MOUNT_FILES.get(normalize_virtual_path(virtual_path))

    def virtual_generated_file_kind(self, virtual_path: str) -> str | None:
        virtual_path = normalize_virtual_path(virtual_path)
        return VIRTUAL_MOUNT_FILES.get(virtual_path) or VIRTUAL_PROC_FILES.get(
            virtual_path
        )

    def should_use_virtual_mount_file(self, name: str, args: list[int]) -> bool:
        if name not in VIRTUAL_SPECIAL_PATH_SYSCALLS:
            return False
        if name in {"open", "openat"}:
            flags_index = 1 if name == "open" else 2
            flags = signed64(args[flags_index])
            return flags & O_ACCMODE == os.O_RDONLY
        return True

    def make_virtual_file(self, kind: str) -> str:
        if kind == "mountinfo":
            content = self.render_mountinfo()
        elif kind == "filesystems":
            content = self.render_filesystems()
        else:
            content = self.render_mounts()
        fd, path = tempfile.mkstemp(prefix="pnfroot-mount-table-")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def render_mounts(self) -> str:
        lines = [
            "rootfs / rootfs rw,relatime 0 0\n",
            (
                "pnfroot-dev /dev pnfroot-dev "
                "rw,nosuid,noexec,pnfroot.virtual-dev 0 0\n"
            ),
            (
                "pnfroot-devpts /dev/pts devpts "
                "rw,nosuid,noexec,pnfroot.virtual-devpts 0 0\n"
            ),
            (
                "pnfroot-proc /proc proc "
                "rw,nosuid,nodev,noexec,pnfroot.virtual-proc 0 0\n"
            ),
        ]
        for bind in self.binds:
            options = self.bind_mount_options(bind)
            lines.append(
                f"{escape_mount_field(self.mount_source(bind))} "
                f"{escape_mount_field(bind.virtual_path)} "
                f"none {options} 0 0\n"
            )
        return "".join(lines)

    def render_mountinfo(self) -> str:
        lines = [
            "1 0 0:1 / / rw,relatime - rootfs rootfs rw\n",
            (
                "2 1 0:2 / /dev rw,nosuid,noexec - "
                "pnfroot-dev pnfroot-dev rw,pnfroot.virtual-dev\n"
            ),
            (
                "3 2 0:3 / /dev/pts rw,nosuid,noexec - "
                "devpts pnfroot-devpts rw,pnfroot.virtual-devpts\n"
            ),
            (
                "4 1 0:4 / /proc rw,nosuid,nodev,noexec - "
                "proc pnfroot-proc rw,pnfroot.virtual-proc\n"
            ),
        ]
        for mount_id, bind in enumerate(self.binds, start=5):
            super_options = self.bind_mount_options(bind)
            lines.append(
                f"{mount_id} 1 0:{mount_id} / "
                f"{escape_mount_field(bind.virtual_path)} rw,relatime - "
                f"none {escape_mount_field(self.mount_source(bind))} "
                f"{super_options}\n"
            )
        return "".join(lines)

    def render_filesystems(self) -> str:
        return (
            "nodev\tsysfs\n"
            "nodev\ttmpfs\n"
            "nodev\tdevtmpfs\n"
            "nodev\tdevpts\n"
            "nodev\tproc\n"
            "nodev\tcgroup\n"
            "nodev\tcgroup2\n"
            "nodev\tfuse\n"
            "ext2\n"
            "ext3\n"
            "ext4\n"
            "squashfs\n"
            "vfat\n"
            "overlay\n"
        )

    def bind_mount_options(self, bind: BindMount) -> str:
        options = ["rw", "bind"]
        if bind.recursive:
            options.append("rbind")
        if bind.origin == "internal":
            options.append("pnfroot.internal-bind")
        else:
            options.append("pnfroot.cli-bind")
        return ",".join(options)

    def mount_source(self, bind: BindMount) -> str:
        return bind.source_display or bind.host_path

    def special_host_path(
        self, virtual_path: str, name: str, args: list[int]
    ) -> str | None:
        if name not in VIRTUAL_SPECIAL_PATH_SYSCALLS:
            return None

        virtual_path = normalize_virtual_path(virtual_path)
        if self.bind_for(virtual_path) is not None:
            return None

        host_path = self.device_host_path(virtual_path)
        if host_path is not None:
            return host_path

        host_path = self.proc_host_path(virtual_path, name, args)
        if host_path is not None:
            return host_path

        return None

    def device_host_path(self, virtual_path: str) -> str | None:
        host_path = VIRTUAL_DEVICE_PATHS.get(virtual_path)
        if host_path is not None and os.path.exists(host_path):
            return host_path

        for virtual_prefix, host_prefix in VIRTUAL_DEVICE_PREFIXES.items():
            host_path = prefixed_host_path(virtual_path, virtual_prefix, host_prefix)
            if host_path is not None and os.path.exists(host_path):
                return host_path

        return None

    def proc_host_path(
        self, virtual_path: str, name: str, args: list[int]
    ) -> str | None:
        for virtual_prefix, host_prefix in VIRTUAL_PROC_PREFIXES.items():
            host_path = prefixed_host_path(virtual_path, virtual_prefix, host_prefix)
            if host_path is not None and os.path.exists(host_path):
                return host_path

        if not self.should_use_virtual_mount_file(name, args):
            return None

        host_path = VIRTUAL_PROC_READONLY_PATHS.get(virtual_path)
        if host_path is not None and os.path.exists(host_path):
            return host_path

        return None

    def internal_mount_directory(
        self, virtual_path: str, *, allow_root: bool = True
    ) -> tuple[str | None, int]:
        virtual_path = normalize_virtual_path(virtual_path)
        if virtual_path == "/" and not allow_root:
            return None, errno.EPERM
        if self.bind_for(virtual_path) is not None:
            return None, errno.EPERM

        host_path = self.host_path(virtual_path)
        root = os.path.realpath(self.root)
        resolved = os.path.realpath(host_path)
        if os.path.commonpath([root, resolved]) != root:
            return None, errno.EPERM
        if not os.path.exists(host_path):
            return None, errno.ENOENT
        if not os.path.isdir(host_path):
            return None, errno.ENOTDIR
        return host_path, 0

    def cleanup_temporary_paths(self, record: SyscallRecord) -> None:
        paths = record.metadata.pop("temporary_paths", [])
        if not isinstance(paths, list):
            return
        for path in paths:
            if not isinstance(path, str):
                continue
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def prepare_write_parent(
        self, virtual_path: str, host_path: str, metadata: dict[str, object]
    ) -> None:
        if self.bind_for(virtual_path) is not None:
            return

        parent = os.path.dirname(host_path)
        if not parent:
            return

        root = os.path.realpath(self.root)
        try:
            resolved_parent = os.path.realpath(parent)
            if os.path.commonpath([root, resolved_parent]) != root:
                return
            st = os.stat(resolved_parent)
        except (OSError, ValueError):
            return

        mode = stat_module.S_IMODE(st.st_mode)
        needed_bits = stat_module.S_IWUSR | stat_module.S_IXUSR
        if mode & needed_bits == needed_bits:
            return

        chmods = metadata.setdefault("temporary_chmods", [])
        if not isinstance(chmods, list):
            return
        if any(isinstance(item, tuple) and item[0] == resolved_parent for item in chmods):
            return

        try:
            os.chmod(resolved_parent, mode | needed_bits)
        except OSError:
            return
        chmods.append((resolved_parent, mode))

    def cleanup_temporary_chmods(self, record: SyscallRecord) -> None:
        chmods = record.metadata.pop("temporary_chmods", [])
        if not isinstance(chmods, list):
            return
        for item in reversed(chmods):
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not isinstance(item[1], int)
            ):
                continue
            try:
                os.chmod(item[0], item[1])
            except OSError:
                pass

    def path_needs_writable_parent(
        self, name: str, args: list[int], spec: PathArgSpec
    ) -> bool:
        if name in WRITE_PARENT_SYSCALLS:
            return True
        if name == "open":
            flags = signed64(args[1])
            return bool(flags & os.O_CREAT or flags & O_TMPFILE)
        if name == "openat":
            flags = signed64(args[2])
            return bool(flags & os.O_CREAT or flags & O_TMPFILE)
        return False

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
            rootfs_virtual_path = self.rootfs_host_path_to_virtual(path)
            if rootfs_virtual_path is not None:
                return rootfs_virtual_path
            return normalize_virtual_path(path)

        base = self.cwd_by_pid.get(pid, "/")
        if dirfd is not None and signed64(dirfd) != AT_FDCWD:
            base = self.fd_paths_by_pid.get(pid, {}).get(signed64(dirfd))
            if base is None:
                return None

        return normalize_virtual_path(posixpath.join(base, path))

    def neutralize_mount_syscall(
        self, pid: int, name: str, args: list[int], regs: UserRegsStruct
    ) -> dict[str, object]:
        if name == "mount":
            metadata = self.prepare_mount(pid, args)
        elif name in {"umount", "umount2"}:
            metadata = self.prepare_umount(pid, args)
        else:
            return {}

        regs.orig_rax = self.noop_syscall_number
        set_regs(pid, regs)
        metadata["mount_neutralized"] = True
        return metadata

    def prepare_mount(self, pid: int, args: list[int]) -> dict[str, object]:
        source = self.read_string(pid, args[0])
        target = self.read_string(pid, args[1])
        filesystem = self.read_string(pid, args[2])
        flags = args[3]

        if target is None:
            return {
                "mount_action": "mount",
                "mount_result": -errno.EFAULT,
            }

        target_virtual = self.virtual_path(pid, target)
        if target_virtual is None:
            return {
                "mount_action": "mount",
                "mount_result": -errno.ENOENT,
            }

        if not flags & MS_BIND:
            return {
                "mount_action": "mount",
                "mount_result": -errno.EPERM,
                "mount_virtual_target": target_virtual,
                "mount_filesystem": filesystem,
            }

        if source is None:
            return {
                "mount_action": "mount",
                "mount_result": -errno.EFAULT,
                "mount_virtual_target": target_virtual,
            }

        source_virtual = self.virtual_path(pid, source)
        if source_virtual is None:
            return {
                "mount_action": "mount",
                "mount_result": -errno.ENOENT,
                "mount_virtual_target": target_virtual,
            }

        source_host, source_error = self.internal_mount_directory(source_virtual)
        if source_error:
            return {
                "mount_action": "mount",
                "mount_result": -source_error,
                "mount_virtual_source": source_virtual,
                "mount_virtual_target": target_virtual,
            }

        target_host, target_error = self.internal_mount_directory(
            target_virtual, allow_root=False
        )
        if target_error:
            return {
                "mount_action": "mount",
                "mount_result": -target_error,
                "mount_virtual_source": source_virtual,
                "mount_virtual_target": target_virtual,
            }

        return {
            "mount_action": "mount",
            "mount_result": 0,
            "mount_kind": "bind",
            "mount_recursive": bool(flags & MS_REC),
            "mount_virtual_source": source_virtual,
            "mount_virtual_target": target_virtual,
            "mount_host_source": source_host,
            "mount_host_target": target_host,
        }

    def prepare_umount(self, pid: int, args: list[int]) -> dict[str, object]:
        target = self.read_string(pid, args[0])
        if target is None:
            return {
                "mount_action": "umount",
                "mount_result": -errno.EFAULT,
            }

        target_virtual = self.virtual_path(pid, target)
        if target_virtual is None:
            return {
                "mount_action": "umount",
                "mount_result": -errno.ENOENT,
            }

        return {
            "mount_action": "umount",
            "mount_result": 0,
            "mount_virtual_target": target_virtual,
        }

    def read_string(self, pid: int, address: int) -> str | None:
        data = read_c_string_bytes(pid, address)
        if data is None:
            return None
        return os.fsdecode(data)

    def rewrite_syscall_entry(
        self, pid: int, name: str, args: list[int], regs: UserRegsStruct
    ) -> dict[str, object]:
        mount_metadata = self.neutralize_mount_syscall(pid, name, args, regs)
        if mount_metadata:
            return mount_metadata

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

            generated_file_kind = self.virtual_generated_file_kind(virtual_path)
            if generated_file_kind is not None and self.should_use_virtual_mount_file(
                name, args
            ):
                host_path = self.make_virtual_file(generated_file_kind)
                temporary_paths = metadata.setdefault("temporary_paths", [])
                if isinstance(temporary_paths, list):
                    temporary_paths.append(host_path)
            else:
                host_path = self.special_host_path(virtual_path, name, args)
                if host_path is None:
                    host_path = self.host_path(
                        virtual_path,
                        follow_final_symlink=spec.follows_final_symlink(args),
                    )
            if self.path_needs_writable_parent(name, args, spec):
                self.prepare_write_parent(virtual_path, host_path, metadata)
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
        try:
            self.handle_syscall_exit_record(context, record)
        finally:
            self.cleanup_temporary_chmods(record)
            self.cleanup_temporary_paths(record)

    def handle_syscall_exit_record(
        self, context: SyscallContext, record: SyscallRecord
    ) -> None:
        if "mount_action" in record.metadata:
            self.handle_mount_exit(context, record)
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

    def handle_mount_exit(
        self, context: SyscallContext, record: SyscallRecord
    ) -> None:
        result = record.metadata.get("mount_result", -errno.EPERM)
        if result != 0:
            set_syscall_result(context, int(result))
            return

        action = record.metadata.get("mount_action")
        if action == "mount":
            result = self.apply_mount(record)
            set_syscall_result(context, -result if result else 0)
        elif action == "umount":
            target = record.metadata.get("mount_virtual_target")
            if isinstance(target, str) and self.remove_bind(target):
                set_syscall_result(context, 0)
            else:
                set_syscall_result(context, -errno.EINVAL)
        else:
            set_syscall_result(context, -errno.EPERM)

    def apply_mount(self, record: SyscallRecord) -> int:
        if record.metadata.get("mount_kind") != "bind":
            return errno.EPERM

        host_source = record.metadata.get("mount_host_source")
        virtual_target = record.metadata.get("mount_virtual_target")
        if not isinstance(host_source, str) or not isinstance(virtual_target, str):
            return errno.EPERM

        source_display = record.metadata.get("mount_virtual_source")
        recursive = bool(record.metadata.get("mount_recursive"))
        try:
            self.add_bind(
                BindMount.from_paths(
                    host_source,
                    virtual_target,
                    source_display=(
                        source_display if isinstance(source_display, str) else None
                    ),
                    recursive=recursive,
                    origin="internal",
                )
            )
        except OSError as exc:
            return exc.errno or errno.EPERM
        except RuntimeError:
            return errno.EPERM
        return 0
