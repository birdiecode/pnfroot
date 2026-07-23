"""Virtual uid/gid credentials for traced processes."""

from __future__ import annotations

import errno
import os
import stat as stat_module
from dataclasses import dataclass

from ptrace_common import (
    SYSCALL_NUMBERS,
    SyscallContext,
    SyscallRecord,
    UserRegsStruct,
    read_tracee_u32_array,
    set_regs,
    set_syscall_result,
    signed64,
    syscall_error,
    write_tracee_u32,
    write_tracee_u32_array,
)


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
    CHOWN_SYSCALLS = {"chown", "fchown", "fchownat", "lchown"}
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
    RESULT_SYSCALLS = {
        "getuid",
        "geteuid",
        "getgid",
        "getegid",
        "execve",
        "execveat",
    }
    ENTRY_SYSCALLS = SETTER_SYSCALLS | POINTER_GETTER_SYSCALLS | CHOWN_SYSCALLS
    EXIT_SYSCALLS = RESULT_SYSCALLS | ENTRY_SYSCALLS

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
        if name not in self.ENTRY_SYSCALLS:
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
        if name not in self.EXIT_SYSCALLS:
            return

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
        elif name in self.CHOWN_SYSCALLS:
            self.handle_chown(context, record)

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

    def handle_chown(self, context: SyscallContext, record: SyscallRecord) -> None:
        credentials = self.credentials(context.pid)
        if record.name == "fchownat":
            uid = self.id_arg(record.args[2])
            gid = self.id_arg(record.args[3])
        else:
            uid = self.id_arg(record.args[1])
            gid = self.id_arg(record.args[2])

        if not self.id_arg_or_none_is_valid(uid) or not self.id_arg_or_none_is_valid(
            gid
        ):
            set_syscall_result(context, -errno.EINVAL)
        elif credentials.euid == 0:
            set_syscall_result(context, 0)
        else:
            set_syscall_result(context, -errno.EPERM)

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
