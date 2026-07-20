"""Virtual network syscall handling for traced processes."""

from __future__ import annotations

import argparse
import errno
import hashlib
import ipaddress
import json
import os
import socket
import struct
import sys
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any

from ptrace_common import (
    SYSCALL_NUMBERS,
    SyscallContext,
    SyscallRecord,
    UserRegsStruct,
    WORD_SIZE,
    ptrace_peek,
    read_pointer,
    read_tracee_u32,
    set_regs,
    set_syscall_result,
    signed64,
    syscall_error,
    write_tracee_bytes,
    write_tracee_u32,
)


AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6
AF_NETLINK = socket.AF_NETLINK
IPPROTO_TCP = socket.IPPROTO_TCP
NETLINK_ROUTE = 0
SOCK_STREAM = int(socket.SOCK_STREAM)
SOCK_TYPE_MASK = 0xF
MSG_PEEK = socket.MSG_PEEK
MSG_TRUNC = socket.MSG_TRUNC
MAX_JSON_MESSAGE_SIZE = 1024 * 1024
MAX_SOCKADDR_SIZE = 128
MAX_IOVEC_COUNT = 64
MAX_NETLINK_REQUEST_SIZE = 1024 * 1024

NLMSG_HDRLEN = 16
NLMSG_DONE = 3
NLM_F_MULTI = 0x2
RTM_NEWLINK = 16
RTM_GETLINK = 18
RTM_NEWADDR = 20
RTM_GETADDR = 22

RT_SCOPE_UNIVERSE = 0
RT_SCOPE_HOST = 254

ARPHRD_ETHER = 1
ARPHRD_LOOPBACK = 772

IFF_UP = 0x1
IFF_BROADCAST = 0x2
IFF_LOOPBACK = 0x8
IFF_RUNNING = 0x40
IFF_MULTICAST = 0x1000
IFF_LOWER_UP = 0x10000

IFLA_ADDRESS = 1
IFLA_BROADCAST = 2
IFLA_IFNAME = 3
IFLA_MTU = 4
IFLA_TXQLEN = 13
IFLA_OPERSTATE = 16
IFLA_LINKMODE = 17
IFLA_GROUP = 27
IFLA_QDISC = 6
IF_OPER_UNKNOWN = 0
IF_OPER_UP = 6

IFA_ADDRESS = 1
IFA_LOCAL = 2
IFA_LABEL = 3
IFA_BROADCAST = 4
IFA_FLAGS = 8
IFA_F_PERMANENT = 0x80


class NetworkServiceError(RuntimeError):
    pass


@dataclass
class VirtualNetworkInterface:
    name: str
    network: str
    ip_address: str | None = None
    prefix_length: int | None = None
    gateway: str | None = None
    mac_address: str | None = None
    mtu: int = 1500
    dns_servers: list[str] = field(default_factory=list)

    def to_message(self) -> dict[str, object]:
        return {
            "name": self.name,
            "network": self.network,
            "ip": self.ip_address,
            "prefix_length": self.prefix_length,
            "gateway": self.gateway,
            "mac": self.mac_address,
            "mtu": self.mtu,
            "dns": list(self.dns_servers),
        }

    def apply_service_update(self, data: dict[str, object]) -> None:
        ip = data.get("ip")
        prefix_length = data.get("prefix_length")
        gateway = data.get("gateway")
        if isinstance(ip, str) and ip:
            self.ip_address = ip
        if isinstance(prefix_length, int):
            self.prefix_length = prefix_length
        if isinstance(gateway, str) and gateway:
            self.gateway = gateway


@dataclass
class PublishedPort:
    host_ip: str
    host_port: int
    container_port: int
    protocol: str = "tcp"

    def to_message(self) -> dict[str, object]:
        return {
            "host_ip": self.host_ip,
            "host_port": self.host_port,
            "container_port": self.container_port,
            "protocol": self.protocol,
        }


@dataclass
class ContainerNetworkConfig:
    container_id: str
    interfaces: list[VirtualNetworkInterface]
    service_socket: str
    published_ports: list[PublishedPort] = field(default_factory=list)

    def interface_for_destination(
        self, destination_ip: str | None
    ) -> VirtualNetworkInterface | None:
        if not self.interfaces:
            return None

        if destination_ip is not None:
            for interface in self.interfaces:
                if interface.ip_address is None or interface.prefix_length is None:
                    continue
                try:
                    network = ipaddress.ip_network(
                        f"{interface.ip_address}/{interface.prefix_length}",
                        strict=False,
                    )
                    if ipaddress.ip_address(destination_ip) in network:
                        return interface
                except ValueError:
                    continue

        return self.interfaces[0]

    def interface_for_bind(self, bind_ip: str) -> VirtualNetworkInterface | None:
        if bind_ip in {"0.0.0.0", "::"}:
            return self.interfaces[0] if self.interfaces else None

        for interface in self.interfaces:
            if interface.ip_address == bind_ip:
                return interface

        return self.interface_for_destination(bind_ip)


@dataclass
class Sockaddr:
    family: int
    address_family: str
    ip: str
    port: int
    raw: bytes


@dataclass(frozen=True)
class TraceeIovec:
    base: int
    length: int


@dataclass(frozen=True)
class TraceeMsghdr:
    address: int
    name: int
    name_length: int
    iovecs: list[TraceeIovec]
    flags_address: int
    name_length_address: int


@dataclass
class TrackedSocket:
    pid: int
    fd: int
    family: int
    socket_type: int
    protocol: int
    interface_name: str | None = None
    network_name: str | None = None
    virtual_local_address: tuple[str, int] | None = None
    virtual_remote_address: tuple[str, int] | None = None
    real_local_address: tuple[str, int] | None = None
    real_remote_address: tuple[str, int] | None = None
    connection_id: str | None = None
    netlink_port_id: int = 0
    netlink_queue: list[bytes] = field(default_factory=list)

    @property
    def is_tcp_stream(self) -> bool:
        return (
            self.socket_type & SOCK_TYPE_MASK == SOCK_STREAM
            and self.protocol in {0, IPPROTO_TCP}
        )

    @property
    def is_route_netlink(self) -> bool:
        return self.family == AF_NETLINK and self.protocol == NETLINK_ROUTE

    def copy_for_pid_fd(self, pid: int, fd: int) -> TrackedSocket:
        return TrackedSocket(
            pid=pid,
            fd=fd,
            family=self.family,
            socket_type=self.socket_type,
            protocol=self.protocol,
            interface_name=self.interface_name,
            network_name=self.network_name,
            virtual_local_address=self.virtual_local_address,
            virtual_remote_address=self.virtual_remote_address,
            real_local_address=self.real_local_address,
            real_remote_address=self.real_remote_address,
            connection_id=self.connection_id,
            netlink_port_id=self.netlink_port_id,
            netlink_queue=list(self.netlink_queue),
        )


class SocketTable:
    def __init__(self) -> None:
        self._sockets: dict[tuple[int, int], TrackedSocket] = {}

    def register_pid(self, pid: int) -> None:
        pass

    def inherit_pid(self, parent_pid: int, child_pid: int) -> None:
        for (pid, fd), tracked in list(self._sockets.items()):
            if pid == parent_pid:
                self._sockets[(child_pid, fd)] = tracked.copy_for_pid_fd(
                    child_pid, fd
                )

    def drop_pid(self, pid: int) -> None:
        for key in [key for key in self._sockets if key[0] == pid]:
            self._sockets.pop(key, None)

    def set(self, socket_info: TrackedSocket) -> None:
        self._sockets[(socket_info.pid, socket_info.fd)] = socket_info

    def get(self, pid: int, fd: int) -> TrackedSocket | None:
        return self._sockets.get((pid, fd))

    def close(self, pid: int, fd: int) -> None:
        self._sockets.pop((pid, fd), None)

    def close_range(self, pid: int, first_fd: int, last_fd: int) -> None:
        for key in [
            key
            for key in self._sockets
            if key[0] == pid and first_fd <= key[1] <= last_fd
        ]:
            self._sockets.pop(key, None)

    def duplicate(self, pid: int, old_fd: int, new_fd: int) -> None:
        old_socket = self.get(pid, old_fd)
        self.close(pid, new_fd)
        if old_socket is not None:
            self.set(old_socket.copy_for_pid_fd(pid, new_fd))


class NetworkServiceClient:
    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self._lock = threading.Lock()
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._socket.connect(socket_path)
        except OSError as exc:
            self._socket.close()
            if exc.errno in {errno.ENOENT, errno.ECONNREFUSED, errno.ENOTSOCK}:
                raise NetworkServiceError(
                    f"network service is unavailable: {socket_path}"
                ) from exc
            raise NetworkServiceError(str(exc)) from exc
        self._reader = self._socket.makefile("rb")
        self._writer = self._socket.makefile("wb")

    def close(self) -> None:
        try:
            self._writer.close()
        except OSError:
            pass
        try:
            self._reader.close()
        except OSError:
            pass
        try:
            self._socket.close()
        except OSError:
            pass

    def request(self, message: dict[str, object]) -> dict[str, object]:
        payload = json.dumps(message, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        if len(payload) > MAX_JSON_MESSAGE_SIZE:
            raise NetworkServiceError("network service message is too large")

        with self._lock:
            try:
                self._writer.write(payload + b"\n")
                self._writer.flush()
                line = self._reader.readline(MAX_JSON_MESSAGE_SIZE + 1)
            except OSError as exc:
                raise NetworkServiceError(str(exc)) from exc

        if not line:
            raise NetworkServiceError("network service closed connection")
        if len(line) > MAX_JSON_MESSAGE_SIZE:
            raise NetworkServiceError("network service response is too large")

        try:
            response = json.loads(line.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise NetworkServiceError("network service returned invalid JSON") from exc
        if not isinstance(response, dict):
            raise NetworkServiceError("network service returned invalid response")
        return response

    def register_container(
        self, config: ContainerNetworkConfig, pid: int
    ) -> dict[str, object]:
        message = {
            "version": 1,
            "type": "register_container",
            "container_id": config.container_id,
            "pid": pid,
            "interfaces": [interface.to_message() for interface in config.interfaces],
            "published_ports": [
                published_port.to_message()
                for published_port in config.published_ports
            ],
        }
        response = self.request(message)
        if not response.get("success", False):
            error = response.get("error") or response.get("reason")
            raise NetworkServiceError(str(error or "network registration failed"))

        interfaces = response.get("interfaces")
        if isinstance(interfaces, list):
            for update in interfaces:
                if not isinstance(update, dict):
                    continue
                name = update.get("name")
                network = update.get("network")
                for interface in config.interfaces:
                    if interface.name == name and interface.network == network:
                        interface.apply_service_update(update)
        return response

    def unregister_container(self, container_id: str) -> None:
        try:
            self.request(
                {
                    "version": 1,
                    "type": "unregister_container",
                    "container_id": container_id,
                }
            )
        except NetworkServiceError:
            pass

    def connect_request(
        self,
        config: ContainerNetworkConfig,
        pid: int,
        tid: int,
        fd: int,
        interface: VirtualNetworkInterface,
        destination: Sockaddr,
        source_port: int,
    ) -> dict[str, object]:
        request_id = make_request_id()
        return self.request(
            {
                "version": 1,
                "type": "connect_request",
                "request_id": request_id,
                "container_id": config.container_id,
                "pid": pid,
                "tid": tid,
                "fd": fd,
                "protocol": "tcp",
                "address_family": destination.address_family,
                "source": {
                    "interface": interface.name,
                    "network": interface.network,
                    "ip": interface.ip_address or "0.0.0.0",
                    "port": source_port,
                },
                "destination": {
                    "ip": destination.ip,
                    "port": destination.port,
                },
            }
        )

    def bind_request(
        self,
        config: ContainerNetworkConfig,
        pid: int,
        fd: int,
        interface: VirtualNetworkInterface,
        virtual_ip: str,
        virtual_port: int,
    ) -> dict[str, object]:
        request_id = make_request_id()
        return self.request(
            {
                "version": 1,
                "type": "bind_request",
                "request_id": request_id,
                "container_id": config.container_id,
                "pid": pid,
                "fd": fd,
                "protocol": "tcp",
                "interface": interface.name,
                "network": interface.network,
                "virtual_address": {
                    "ip": virtual_ip,
                    "port": virtual_port,
                },
            }
        )


class VirtualNetworkRuntime:
    def __init__(self, config: ContainerNetworkConfig):
        self.config = config
        self.sockets = SocketTable()
        self.noop_syscall_number = SYSCALL_NUMBERS.get("getpid", 39)
        self.client: NetworkServiceClient | None = None
        self.registered = False
        self.initial_pid: int | None = None

    def register_container(self, pid: int) -> None:
        self.initial_pid = pid
        self.register_pid(pid)
        self.client = NetworkServiceClient(self.config.service_socket)
        self.client.register_container(self.config, pid)
        self.registered = True

    def unregister_container(self) -> None:
        if self.client is not None and self.registered:
            self.client.unregister_container(self.config.container_id)
        if self.client is not None:
            self.client.close()
        self.client = None
        self.registered = False

    def register_pid(self, pid: int) -> None:
        self.sockets.register_pid(pid)

    def inherit_pid(self, parent_pid: int, child_pid: int) -> None:
        self.sockets.inherit_pid(parent_pid, child_pid)

    def drop_pid(self, pid: int) -> None:
        self.sockets.drop_pid(pid)

    def rewrite_syscall_entry(
        self, pid: int, name: str, args: list[int], regs: UserRegsStruct
    ) -> dict[str, object]:
        if name == "socket":
            return {
                "network_socket_family": signed64(args[0]),
                "network_socket_type": signed64(args[1]),
                "network_socket_protocol": signed64(args[2]),
            }
        if self.client is None:
            return {}
        if name == "connect":
            return self.prepare_connect(pid, args, regs)
        if name == "bind":
            return self.prepare_bind(pid, args, regs)
        if name == "sendmsg":
            return self.prepare_sendmsg(pid, args, regs)
        if name == "sendto":
            return self.prepare_sendto(pid, args, regs)
        if name == "recvmsg":
            return self.prepare_recvmsg(pid, args, regs)
        return {}

    def handle_syscall_exit(
        self, context: SyscallContext, record: SyscallRecord | None
    ) -> None:
        if record is None:
            return

        try:
            self.handle_syscall_exit_record(context, record)
        finally:
            self.restore_sockaddr_if_needed(context.pid, record)

    def handle_syscall_exit_record(
        self, context: SyscallContext, record: SyscallRecord
    ) -> None:
        if "network_forced_result" in record.metadata:
            set_syscall_result(context, int(record.metadata["network_forced_result"]))
            return
        if record.name == "socket":
            self.handle_socket_exit(context, record)
            return
        if record.name == "connect":
            self.handle_connect_exit(context, record)
            return
        if record.name == "bind":
            self.handle_bind_exit(context, record)
            return
        if record.name in {"getsockname", "getpeername"}:
            self.handle_socket_name_exit(context, record)
            return
        if record.name == "close":
            if syscall_error(context.result or 0) is None:
                self.sockets.close(context.pid, signed64(record.args[0]))
            return
        if record.name in {"dup", "dup2", "dup3"}:
            self.handle_dup_exit(context, record)
            return
        if record.name == "close_range":
            self.handle_close_range_exit(context, record)
            return
        if record.name in {"accept", "accept4"}:
            self.handle_accept_exit(context, record)

    def handle_socket_exit(
        self, context: SyscallContext, record: SyscallRecord
    ) -> None:
        if syscall_error(context.result or 0) is not None:
            return
        fd = signed64(context.result or 0)
        family = int(record.metadata.get("network_socket_family", record.args[0]))
        socket_type = int(record.metadata.get("network_socket_type", record.args[1]))
        protocol = int(
            record.metadata.get("network_socket_protocol", record.args[2])
        )
        self.sockets.set(
            TrackedSocket(
                pid=context.pid,
                fd=fd,
                family=family,
                socket_type=socket_type,
                protocol=protocol,
                netlink_port_id=context.pid if family == AF_NETLINK else 0,
            )
        )

    def handle_dup_exit(
        self, context: SyscallContext, record: SyscallRecord
    ) -> None:
        if syscall_error(context.result or 0) is not None:
            return
        old_fd = signed64(record.args[0])
        new_fd = signed64(context.result or 0)
        self.sockets.duplicate(context.pid, old_fd, new_fd)

    def handle_close_range_exit(
        self, context: SyscallContext, record: SyscallRecord
    ) -> None:
        if syscall_error(context.result or 0) is not None:
            return
        first_fd = signed64(record.args[0])
        last_fd = signed64(record.args[1])
        self.sockets.close_range(context.pid, first_fd, last_fd)

    def handle_accept_exit(
        self, context: SyscallContext, record: SyscallRecord
    ) -> None:
        if syscall_error(context.result or 0) is not None:
            return
        listener_fd = signed64(record.args[0])
        accepted_fd = signed64(context.result or 0)
        listener = self.sockets.get(context.pid, listener_fd)
        if listener is None:
            return
        accepted = listener.copy_for_pid_fd(context.pid, accepted_fd)
        accepted.virtual_remote_address = None
        accepted.real_remote_address = None
        accepted.connection_id = None
        self.sockets.set(accepted)

    def prepare_connect(
        self, pid: int, args: list[int], regs: UserRegsStruct
    ) -> dict[str, object]:
        fd = signed64(args[0])
        tracked = self.sockets.get(pid, fd)
        sockaddr = read_sockaddr(pid, args[1], signed64(args[2]))
        if sockaddr is None:
            return {}
        if sockaddr.family not in {AF_INET, AF_INET6}:
            return {}

        if tracked is not None and not tracked.is_tcp_stream:
            return {}
        if sockaddr.family != AF_INET:
            return self.neutralize_syscall(
                pid,
                regs,
                errno.EAFNOSUPPORT,
                {"network_connect_reason": "IPv6 routing is not implemented yet"},
            )

        interface = self.config.interface_for_destination(sockaddr.ip)
        if interface is None:
            return self.neutralize_syscall(
                pid,
                regs,
                errno.ENETUNREACH,
                {"network_connect_reason": "no virtual network interface"},
            )

        source_port = 0
        if tracked is not None and tracked.virtual_local_address is not None:
            source_port = tracked.virtual_local_address[1]

        try:
            assert self.client is not None
            response = self.client.connect_request(
                self.config,
                self.initial_pid or pid,
                pid,
                fd,
                interface,
                sockaddr,
                source_port,
            )
        except NetworkServiceError as exc:
            return self.neutralize_syscall(
                pid,
                regs,
                errno.EHOSTUNREACH,
                {"network_connect_reason": str(exc)},
            )

        metadata: dict[str, object] = {
            "network_connect_action": response.get("action"),
            "network_sockaddr_family": sockaddr.family,
            "network_virtual_remote": (sockaddr.ip, sockaddr.port),
            "network_interface": interface.name,
            "network_name": interface.network,
        }
        action = response.get("action")
        if action == "allow":
            return metadata
        if action == "deny":
            err_no = errno_from_name(response.get("errno"), errno.EACCES)
            metadata["network_connect_reason"] = response.get("reason")
            return self.neutralize_syscall(pid, regs, err_no, metadata)
        if action in {"redirect", "proxy"}:
            destination_key = "proxy" if action == "proxy" else "destination"
            destination = response.get(destination_key)
            if not isinstance(destination, dict):
                return self.neutralize_syscall(pid, regs, errno.EPROTO, metadata)
            target_ip = destination.get("ip")
            target_port = destination.get("port")
            if not isinstance(target_ip, str) or not isinstance(target_port, int):
                return self.neutralize_syscall(pid, regs, errno.EPROTO, metadata)
            if not rewrite_ipv4_sockaddr(pid, args[1], signed64(args[2]), target_ip, target_port):
                return self.neutralize_syscall(pid, regs, errno.EFAULT, metadata)
            metadata.update(
                {
                    "network_restore_sockaddr": (args[1], sockaddr.raw),
                    "network_real_remote": (target_ip, target_port),
                    "network_connection_id": response.get("connection_id"),
                }
            )
            return metadata

        return self.neutralize_syscall(pid, regs, errno.EPROTO, metadata)

    def prepare_sendmsg(
        self, pid: int, args: list[int], regs: UserRegsStruct
    ) -> dict[str, object]:
        fd = signed64(args[0])
        tracked = self.sockets.get(pid, fd)
        if tracked is None or not tracked.is_route_netlink:
            return {}

        msghdr = read_msghdr(pid, args[1])
        if msghdr is None:
            return self.neutralize_syscall_result(pid, regs, -errno.EFAULT)
        payload = read_iovec_payload(pid, msghdr.iovecs, MAX_NETLINK_REQUEST_SIZE)
        if payload is None:
            return self.neutralize_syscall_result(pid, regs, -errno.EFAULT)

        tracked.netlink_queue.extend(
            build_rtnetlink_datagrams(
                payload,
                self.config,
                port_id=tracked.netlink_port_id or pid,
            )
        )
        return self.neutralize_syscall_result(pid, regs, len(payload))

    def prepare_sendto(
        self, pid: int, args: list[int], regs: UserRegsStruct
    ) -> dict[str, object]:
        fd = signed64(args[0])
        tracked = self.sockets.get(pid, fd)
        if tracked is None or not tracked.is_route_netlink:
            return {}

        length = signed64(args[2])
        if length < 0 or length > MAX_NETLINK_REQUEST_SIZE:
            return self.neutralize_syscall_result(pid, regs, -errno.EMSGSIZE)
        try:
            payload = read_tracee_bytes(pid, args[1], length)
        except OSError:
            return self.neutralize_syscall_result(pid, regs, -errno.EFAULT)

        tracked.netlink_queue.extend(
            build_rtnetlink_datagrams(
                payload,
                self.config,
                port_id=tracked.netlink_port_id or pid,
            )
        )
        return self.neutralize_syscall_result(pid, regs, length)

    def prepare_recvmsg(
        self, pid: int, args: list[int], regs: UserRegsStruct
    ) -> dict[str, object]:
        fd = signed64(args[0])
        tracked = self.sockets.get(pid, fd)
        if tracked is None or not tracked.is_route_netlink:
            return {}

        msghdr = read_msghdr(pid, args[1])
        if msghdr is None:
            return self.neutralize_syscall_result(pid, regs, -errno.EFAULT)

        if not tracked.netlink_queue:
            return self.neutralize_syscall_result(pid, regs, -errno.EAGAIN)

        flags = signed64(args[2])
        message = tracked.netlink_queue[0]
        capacity = iovec_capacity(msghdr.iovecs)
        out_flags = MSG_TRUNC if len(message) > capacity else 0

        if capacity:
            written = write_iovec_payload(pid, msghdr.iovecs, message)
            if written is None:
                return self.neutralize_syscall_result(pid, regs, -errno.EFAULT)
        else:
            written = 0

        if not flags & MSG_PEEK:
            if written < len(message) and not flags & MSG_TRUNC:
                tracked.netlink_queue[0] = message[written:]
            else:
                tracked.netlink_queue.pop(0)

        write_netlink_msg_name(pid, msghdr)
        try:
            write_tracee_u32(pid, msghdr.flags_address, out_flags)
        except OSError:
            pass

        result = len(message) if flags & MSG_TRUNC else written
        return self.neutralize_syscall_result(pid, regs, result)

    def prepare_bind(
        self, pid: int, args: list[int], regs: UserRegsStruct
    ) -> dict[str, object]:
        fd = signed64(args[0])
        tracked = self.sockets.get(pid, fd)
        sockaddr = read_sockaddr(pid, args[1], signed64(args[2]))
        if sockaddr is None:
            return {}
        if sockaddr.family not in {AF_INET, AF_INET6}:
            return {}

        if tracked is not None and not tracked.is_tcp_stream:
            return {}
        if sockaddr.family != AF_INET:
            return self.neutralize_syscall(
                pid,
                regs,
                errno.EAFNOSUPPORT,
                {"network_bind_reason": "IPv6 routing is not implemented yet"},
            )

        interface = self.config.interface_for_bind(sockaddr.ip)
        if interface is None:
            return self.neutralize_syscall(
                pid,
                regs,
                errno.ENETUNREACH,
                {"network_bind_reason": "no virtual network interface"},
            )
        virtual_ip = (
            interface.ip_address
            if sockaddr.ip == "0.0.0.0" and interface.ip_address is not None
            else sockaddr.ip
        )

        try:
            assert self.client is not None
            response = self.client.bind_request(
                self.config,
                self.initial_pid or pid,
                fd,
                interface,
                virtual_ip,
                sockaddr.port,
            )
        except NetworkServiceError as exc:
            return self.neutralize_syscall(
                pid,
                regs,
                errno.EHOSTUNREACH,
                {"network_bind_reason": str(exc)},
            )

        metadata: dict[str, object] = {
            "network_bind_action": response.get("action"),
            "network_sockaddr_family": sockaddr.family,
            "network_virtual_local": (virtual_ip, sockaddr.port),
            "network_interface": interface.name,
            "network_name": interface.network,
        }
        action = response.get("action")
        if action == "allow":
            return metadata
        if action == "deny":
            err_no = errno_from_name(response.get("errno"), errno.EACCES)
            metadata["network_bind_reason"] = response.get("reason")
            return self.neutralize_syscall(pid, regs, err_no, metadata)
        if action == "redirect":
            real_address = response.get("real_address")
            if not isinstance(real_address, dict):
                return self.neutralize_syscall(pid, regs, errno.EPROTO, metadata)
            real_ip = real_address.get("ip")
            real_port = real_address.get("port")
            if not isinstance(real_ip, str) or not isinstance(real_port, int):
                return self.neutralize_syscall(pid, regs, errno.EPROTO, metadata)
            if not rewrite_ipv4_sockaddr(pid, args[1], signed64(args[2]), real_ip, real_port):
                return self.neutralize_syscall(pid, regs, errno.EFAULT, metadata)
            metadata.update(
                {
                    "network_restore_sockaddr": (args[1], sockaddr.raw),
                    "network_real_local": (real_ip, real_port),
                }
            )
            return metadata

        return self.neutralize_syscall(pid, regs, errno.EPROTO, metadata)

    def handle_connect_exit(
        self, context: SyscallContext, record: SyscallRecord
    ) -> None:
        if "network_forced_errno" in record.metadata:
            set_syscall_result(context, -int(record.metadata["network_forced_errno"]))
            return
        if syscall_error(context.result or 0) is not None:
            return

        fd = signed64(record.args[0])
        tracked = self.sockets.get(context.pid, fd)
        if tracked is None:
            tracked = TrackedSocket(
                pid=context.pid,
                fd=fd,
                family=int(record.metadata.get("network_sockaddr_family", AF_INET)),
                socket_type=SOCK_STREAM,
                protocol=IPPROTO_TCP,
            )
            self.sockets.set(tracked)
        virtual_remote = record.metadata.get("network_virtual_remote")
        real_remote = record.metadata.get("network_real_remote")
        if is_address_tuple(virtual_remote):
            tracked.virtual_remote_address = virtual_remote
        if is_address_tuple(real_remote):
            tracked.real_remote_address = real_remote
        tracked.interface_name = string_or_none(record.metadata.get("network_interface"))
        tracked.network_name = string_or_none(record.metadata.get("network_name"))
        tracked.connection_id = string_or_none(
            record.metadata.get("network_connection_id")
        )

    def handle_bind_exit(
        self, context: SyscallContext, record: SyscallRecord
    ) -> None:
        if "network_forced_errno" in record.metadata:
            set_syscall_result(context, -int(record.metadata["network_forced_errno"]))
            return
        if syscall_error(context.result or 0) is not None:
            return

        fd = signed64(record.args[0])
        tracked = self.sockets.get(context.pid, fd)
        if tracked is None:
            tracked = TrackedSocket(
                pid=context.pid,
                fd=fd,
                family=int(record.metadata.get("network_sockaddr_family", AF_INET)),
                socket_type=SOCK_STREAM,
                protocol=IPPROTO_TCP,
            )
            self.sockets.set(tracked)
        virtual_local = record.metadata.get("network_virtual_local")
        real_local = record.metadata.get("network_real_local")
        if is_address_tuple(virtual_local):
            tracked.virtual_local_address = virtual_local
        if is_address_tuple(real_local):
            tracked.real_local_address = real_local
        tracked.interface_name = string_or_none(record.metadata.get("network_interface"))
        tracked.network_name = string_or_none(record.metadata.get("network_name"))

    def handle_socket_name_exit(
        self, context: SyscallContext, record: SyscallRecord
    ) -> None:
        if syscall_error(context.result or 0) is not None:
            return
        fd = signed64(record.args[0])
        tracked = self.sockets.get(context.pid, fd)
        if tracked is None:
            return
        address = (
            tracked.virtual_local_address
            if record.name == "getsockname"
            else tracked.virtual_remote_address
        )
        if address is None and record.name == "getsockname":
            address = self.virtual_getsockname_from_real_result(context, tracked)
        if address is None:
            return

        sockaddr_ptr = record.args[1]
        length_ptr = record.args[2]
        if sockaddr_ptr == 0 or length_ptr == 0:
            return
        try:
            current_len = read_tracee_u32(context.pid, length_ptr)
            if current_len < 16:
                return
            write_ipv4_sockaddr(context.pid, sockaddr_ptr, address[0], address[1])
            write_tracee_u32(context.pid, length_ptr, 16)
        except OSError:
            return

    def virtual_getsockname_from_real_result(
        self, context: SyscallContext, tracked: TrackedSocket
    ) -> tuple[str, int] | None:
        try:
            real_address = read_sockaddr(
                context.pid,
                context.args[1],
                read_tracee_u32(context.pid, context.args[2]),
            )
        except OSError:
            return None
        if real_address is None or real_address.family != AF_INET:
            return None

        interface = None
        if tracked.interface_name is not None:
            for candidate in self.config.interfaces:
                if candidate.name == tracked.interface_name:
                    interface = candidate
                    break
        if interface is None:
            interface = self.config.interface_for_destination(
                tracked.virtual_remote_address[0]
                if tracked.virtual_remote_address is not None
                else None
            )
        if interface is None:
            return None

        virtual = (interface.ip_address or "0.0.0.0", real_address.port)
        tracked.virtual_local_address = virtual
        return virtual

    def restore_sockaddr_if_needed(self, pid: int, record: SyscallRecord) -> None:
        restore = record.metadata.get("network_restore_sockaddr")
        if (
            not isinstance(restore, tuple)
            or len(restore) != 2
            or not isinstance(restore[0], int)
            or not isinstance(restore[1], bytes)
        ):
            return
        try:
            write_tracee_bytes(pid, restore[0], restore[1])
        except OSError:
            pass

    def neutralize_syscall(
        self,
        pid: int,
        regs: UserRegsStruct,
        err_no: int,
        metadata: dict[str, object] | None = None,
    ) -> dict[str, object]:
        regs.orig_rax = self.noop_syscall_number
        set_regs(pid, regs)
        result = dict(metadata or {})
        result["network_forced_errno"] = err_no
        return result

    def neutralize_syscall_result(
        self,
        pid: int,
        regs: UserRegsStruct,
        syscall_result: int,
        metadata: dict[str, object] | None = None,
    ) -> dict[str, object]:
        regs.orig_rax = self.noop_syscall_number
        set_regs(pid, regs)
        result = dict(metadata or {})
        result["network_forced_result"] = syscall_result
        return result


def make_request_id() -> str:
    return f"req-{uuid.uuid4().hex[:6]}"


def generate_container_id() -> str:
    return f"container-{uuid.uuid4().hex[:6]}"


def parse_netdev(value: str) -> VirtualNetworkInterface:
    fields: dict[str, str] = {}
    dns_servers: list[str] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise argparse.ArgumentTypeError(
                f"invalid --netdev field {item!r}; expected key=value"
            )
        key, raw_value = item.split("=", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        if key == "dns":
            dns_servers.extend(split_dns_servers(raw_value))
            continue
        if key in fields:
            raise argparse.ArgumentTypeError(f"duplicate --netdev field: {key}")
        fields[key] = raw_value

    allowed = {"name", "network", "ip", "gateway", "mac", "mtu"}
    unknown = sorted(set(fields) - allowed)
    if unknown:
        raise argparse.ArgumentTypeError(
            "unknown --netdev field(s): " + ", ".join(unknown)
        )
    for required in ("name", "network"):
        if not fields.get(required):
            raise argparse.ArgumentTypeError(
                f"--netdev requires field {required!r}"
            )

    ip_address = None
    prefix_length = None
    if fields.get("ip"):
        try:
            interface = ipaddress.ip_interface(fields["ip"])
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid --netdev ip: {fields['ip']}") from exc
        ip_address = str(interface.ip)
        prefix_length = interface.network.prefixlen

    gateway = fields.get("gateway") or None
    if gateway is not None:
        try:
            ipaddress.ip_address(gateway)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"invalid --netdev gateway: {gateway}"
            ) from exc

    for dns_server in dns_servers:
        try:
            ipaddress.ip_address(dns_server)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"invalid --netdev dns server: {dns_server}"
            ) from exc

    mtu = 1500
    if fields.get("mtu"):
        try:
            mtu = int(fields["mtu"], 10)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"invalid --netdev mtu: {fields['mtu']}"
            ) from exc
        if mtu <= 0:
            raise argparse.ArgumentTypeError("--netdev mtu must be positive")

    return VirtualNetworkInterface(
        name=fields["name"],
        network=fields["network"],
        ip_address=ip_address,
        prefix_length=prefix_length,
        gateway=gateway,
        mac_address=fields.get("mac") or None,
        mtu=mtu,
        dns_servers=dns_servers,
    )


def parse_publish(value: str) -> PublishedPort:
    address_part, protocol = split_publish_protocol(value)
    pieces = address_part.split(":")
    if len(pieces) == 2:
        host_ip = "127.0.0.1"
        host_port_text, container_port_text = pieces
    elif len(pieces) == 3:
        host_ip, host_port_text, container_port_text = pieces
    else:
        raise argparse.ArgumentTypeError(
            "--publish must be HOST_PORT:CONTAINER_PORT or "
            "HOST_IP:HOST_PORT:CONTAINER_PORT"
        )

    if protocol != "tcp":
        raise argparse.ArgumentTypeError("--publish currently supports only tcp")

    try:
        ipaddress.IPv4Address(host_ip)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid --publish host IP: {host_ip}") from exc

    host_port = parse_tcp_port(host_port_text, "--publish host port")
    container_port = parse_tcp_port(
        container_port_text,
        "--publish container port",
    )
    return PublishedPort(
        host_ip=host_ip,
        host_port=host_port,
        container_port=container_port,
        protocol=protocol,
    )


def split_publish_protocol(value: str) -> tuple[str, str]:
    if "/" not in value:
        return value, "tcp"
    address_part, protocol = value.rsplit("/", 1)
    protocol = protocol.strip().lower()
    if not address_part or not protocol:
        raise argparse.ArgumentTypeError(f"invalid --publish value: {value}")
    return address_part, protocol


def parse_tcp_port(value: str, label: str) -> int:
    try:
        port = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid {label}: {value}") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"{label} must be between 1 and 65535")
    return port


def split_dns_servers(value: str) -> list[str]:
    return [item.strip() for item in value.replace(";", ",").split(",") if item.strip()]


def read_msghdr(pid: int, address: int) -> TraceeMsghdr | None:
    if address == 0:
        return None
    try:
        msg_name = read_pointer(pid, address)
        msg_namelen = read_tracee_u32(pid, address + 8)
        msg_iov = read_pointer(pid, address + 16)
        msg_iovlen = read_pointer(pid, address + 24)
        iovecs = read_iovecs(pid, msg_iov, msg_iovlen)
    except OSError:
        return None
    if iovecs is None:
        return None
    return TraceeMsghdr(
        address=address,
        name=msg_name,
        name_length=msg_namelen,
        iovecs=iovecs,
        flags_address=address + 48,
        name_length_address=address + 8,
    )


def read_iovecs(
    pid: int, address: int, count: int
) -> list[TraceeIovec] | None:
    if count < 0 or count > MAX_IOVEC_COUNT:
        return None
    if count > 0 and address == 0:
        return None

    result: list[TraceeIovec] = []
    try:
        for index in range(count):
            item_address = address + index * 16
            base = read_pointer(pid, item_address)
            length = read_pointer(pid, item_address + 8)
            result.append(TraceeIovec(base=base, length=length))
    except OSError:
        return None
    return result


def read_iovec_payload(
    pid: int, iovecs: list[TraceeIovec], max_bytes: int
) -> bytes | None:
    remaining = max_bytes
    chunks: list[bytes] = []
    for iovec in iovecs:
        if iovec.length == 0:
            continue
        if iovec.base == 0 or iovec.length > remaining:
            return None
        try:
            chunks.append(read_tracee_bytes(pid, iovec.base, iovec.length))
        except OSError:
            return None
        remaining -= iovec.length
    return b"".join(chunks)


def write_iovec_payload(
    pid: int, iovecs: list[TraceeIovec], data: bytes
) -> int | None:
    written = 0
    for iovec in iovecs:
        if written >= len(data):
            break
        if iovec.length == 0:
            continue
        if iovec.base == 0:
            return None
        chunk = data[written : written + iovec.length]
        try:
            write_tracee_bytes(pid, iovec.base, chunk)
        except OSError:
            return None
        written += len(chunk)
    return written


def iovec_capacity(iovecs: list[TraceeIovec]) -> int:
    return sum(iovec.length for iovec in iovecs)


def write_netlink_msg_name(pid: int, msghdr: TraceeMsghdr) -> None:
    if msghdr.name == 0 or msghdr.name_length < 12:
        return
    sockaddr_nl = (
        int(AF_NETLINK).to_bytes(2, sys.byteorder)
        + b"\x00\x00"
        + (0).to_bytes(4, sys.byteorder)
        + (0).to_bytes(4, sys.byteorder)
    )
    try:
        write_tracee_bytes(pid, msghdr.name, sockaddr_nl)
        write_tracee_u32(pid, msghdr.name_length_address, len(sockaddr_nl))
    except OSError:
        pass


def read_tracee_bytes(pid: int, address: int, length: int) -> bytes:
    if length == 0:
        return b""
    if address == 0 or length < 0:
        raise OSError(errno.EFAULT, os.strerror(errno.EFAULT))
    data = bytearray()
    for offset in range(0, length, WORD_SIZE):
        word = ptrace_peek(pid, address + offset)
        data.extend(word.to_bytes(WORD_SIZE, sys.byteorder))
    return bytes(data[:length])


def read_sockaddr(pid: int, address: int, addrlen: int) -> Sockaddr | None:
    if address == 0 or addrlen < 2:
        return None
    length = min(addrlen, MAX_SOCKADDR_SIZE)
    try:
        raw = read_tracee_bytes(pid, address, length)
    except OSError:
        return None
    if len(raw) < 2:
        return None

    family = int.from_bytes(raw[0:2], sys.byteorder)
    if family == AF_INET:
        if len(raw) < 8:
            return None
        return Sockaddr(
            family=family,
            address_family="ipv4",
            ip=str(ipaddress.IPv4Address(raw[4:8])),
            port=int.from_bytes(raw[2:4], "big"),
            raw=raw[:16],
        )
    if family == AF_INET6:
        if len(raw) < 28:
            return None
        return Sockaddr(
            family=family,
            address_family="ipv6",
            ip=str(ipaddress.IPv6Address(raw[8:24])),
            port=int.from_bytes(raw[2:4], "big"),
            raw=raw[:28],
        )
    return Sockaddr(
        family=family,
        address_family=f"af_{family}",
        ip="",
        port=0,
        raw=raw,
    )


def write_ipv4_sockaddr(pid: int, address: int, ip: str, port: int) -> None:
    data = bytearray(16)
    data[0:2] = int(AF_INET).to_bytes(2, sys.byteorder)
    data[2:4] = int(port).to_bytes(2, "big")
    data[4:8] = ipaddress.IPv4Address(ip).packed
    write_tracee_bytes(pid, address, bytes(data))


def rewrite_ipv4_sockaddr(
    pid: int, address: int, addrlen: int, ip: str, port: int
) -> bool:
    if addrlen < 16:
        return False
    try:
        write_ipv4_sockaddr(pid, address, ip, port)
    except (OSError, ValueError, OverflowError):
        return False
    return True


def build_rtnetlink_response(
    request_payload: bytes, config: ContainerNetworkConfig, port_id: int = 0
) -> bytes:
    return b"".join(build_rtnetlink_datagrams(request_payload, config, port_id=port_id))


def build_rtnetlink_datagrams(
    request_payload: bytes, config: ContainerNetworkConfig, *, port_id: int = 0
) -> list[bytes]:
    responses: list[bytes] = []
    offset = 0
    while offset + NLMSG_HDRLEN <= len(request_payload):
        try:
            nlmsg_len, nlmsg_type, _flags, seq, _pid = struct.unpack_from(
                "=IHHII", request_payload, offset
            )
        except struct.error:
            break
        if nlmsg_len < NLMSG_HDRLEN or offset + nlmsg_len > len(request_payload):
            break

        if nlmsg_type == RTM_GETLINK:
            data = b"".join(build_link_messages(config, seq, port_id))
            if data:
                responses.append(data)
            responses.append(build_done_message(seq, port_id))
        elif nlmsg_type == RTM_GETADDR:
            data = b"".join(build_address_messages(config, seq, port_id))
            if data:
                responses.append(data)
            responses.append(build_done_message(seq, port_id))
        else:
            responses.append(build_done_message(seq, port_id))

        offset += align4(nlmsg_len)
    return responses


def build_link_messages(
    config: ContainerNetworkConfig, seq: int, port_id: int
) -> list[bytes]:
    messages = [build_loopback_link_message(seq, port_id)]
    for index, interface in enumerate(config.interfaces, start=2):
        messages.append(build_interface_link_message(seq, port_id, index, interface))
    return messages


def build_address_messages(
    config: ContainerNetworkConfig, seq: int, port_id: int
) -> list[bytes]:
    messages = [build_loopback_address_message(seq, port_id)]
    for index, interface in enumerate(config.interfaces, start=2):
        if interface.ip_address is None or not is_ipv4_text(interface.ip_address):
            continue
        messages.append(build_interface_address_message(seq, port_id, index, interface))
    return messages


def build_loopback_link_message(seq: int, port_id: int) -> bytes:
    attrs = b"".join(
        [
            rtattr(IFLA_IFNAME, b"lo\x00"),
            rtattr(IFLA_MTU, struct.pack("=I", 65536)),
            rtattr(IFLA_ADDRESS, b"\x00" * 6),
            rtattr(IFLA_BROADCAST, b"\x00" * 6),
            rtattr(IFLA_TXQLEN, struct.pack("=I", 1000)),
            rtattr(IFLA_OPERSTATE, bytes([IF_OPER_UNKNOWN])),
            rtattr(IFLA_LINKMODE, b"\x00"),
            rtattr(IFLA_GROUP, struct.pack("=I", 0)),
            rtattr(IFLA_QDISC, b"noqueue\x00"),
        ]
    )
    payload = ifinfomsg(
        family=0,
        link_type=ARPHRD_LOOPBACK,
        index=1,
        flags=IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP,
    ) + attrs
    return nlmsg(RTM_NEWLINK, NLM_F_MULTI, seq, port_id, payload)


def build_interface_link_message(
    seq: int, port_id: int, index: int, interface: VirtualNetworkInterface
) -> bytes:
    mac = mac_bytes(interface)
    attrs = b"".join(
        [
            rtattr(IFLA_IFNAME, interface.name.encode("ascii", errors="ignore") + b"\x00"),
            rtattr(IFLA_MTU, struct.pack("=I", interface.mtu)),
            rtattr(IFLA_ADDRESS, mac),
            rtattr(IFLA_BROADCAST, b"\xff" * 6),
            rtattr(IFLA_TXQLEN, struct.pack("=I", 1000)),
            rtattr(IFLA_OPERSTATE, bytes([IF_OPER_UP])),
            rtattr(IFLA_LINKMODE, b"\x00"),
            rtattr(IFLA_GROUP, struct.pack("=I", 0)),
            rtattr(IFLA_QDISC, b"noqueue\x00"),
        ]
    )
    payload = ifinfomsg(
        family=0,
        link_type=ARPHRD_ETHER,
        index=index,
        flags=IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST | IFF_LOWER_UP,
    ) + attrs
    return nlmsg(RTM_NEWLINK, NLM_F_MULTI, seq, port_id, payload)


def build_loopback_address_message(seq: int, port_id: int) -> bytes:
    local = ipaddress.IPv4Address("127.0.0.1").packed
    attrs = b"".join(
        [
            rtattr(IFA_ADDRESS, local),
            rtattr(IFA_LOCAL, local),
            rtattr(IFA_LABEL, b"lo\x00"),
            rtattr(IFA_FLAGS, struct.pack("=I", IFA_F_PERMANENT)),
        ]
    )
    payload = ifaddrmsg(
        family=AF_INET,
        prefix_length=8,
        flags=IFA_F_PERMANENT,
        scope=RT_SCOPE_HOST,
        index=1,
    ) + attrs
    return nlmsg(RTM_NEWADDR, NLM_F_MULTI, seq, port_id, payload)


def build_interface_address_message(
    seq: int, port_id: int, index: int, interface: VirtualNetworkInterface
) -> bytes:
    assert interface.ip_address is not None
    prefix_length = interface.prefix_length if interface.prefix_length is not None else 24
    local = ipaddress.IPv4Address(interface.ip_address).packed
    attrs = [
        rtattr(IFA_ADDRESS, local),
        rtattr(IFA_LOCAL, local),
        rtattr(IFA_LABEL, interface.name.encode("ascii", errors="ignore") + b"\x00"),
        rtattr(IFA_FLAGS, struct.pack("=I", IFA_F_PERMANENT)),
    ]
    try:
        network = ipaddress.ip_network(
            f"{interface.ip_address}/{prefix_length}",
            strict=False,
        )
        attrs.append(rtattr(IFA_BROADCAST, network.broadcast_address.packed))
    except ValueError:
        pass
    payload = ifaddrmsg(
        family=AF_INET,
        prefix_length=prefix_length,
        flags=IFA_F_PERMANENT,
        scope=RT_SCOPE_UNIVERSE,
        index=index,
    ) + b"".join(attrs)
    return nlmsg(RTM_NEWADDR, NLM_F_MULTI, seq, port_id, payload)


def build_done_message(seq: int, port_id: int) -> bytes:
    return nlmsg(NLMSG_DONE, NLM_F_MULTI, seq, port_id, struct.pack("=i", 0))


def nlmsg(
    message_type: int, flags: int, seq: int, port_id: int, payload: bytes
) -> bytes:
    length = NLMSG_HDRLEN + len(payload)
    header = struct.pack("=IHHII", length, message_type, flags, seq, port_id)
    return header + payload + (b"\x00" * (align4(length) - length))


def ifinfomsg(family: int, link_type: int, index: int, flags: int) -> bytes:
    return struct.pack("=BBHiII", family, 0, link_type, index, flags, 0xFFFFFFFF)


def ifaddrmsg(
    family: int, prefix_length: int, flags: int, scope: int, index: int
) -> bytes:
    return struct.pack("=BBBBI", family, prefix_length, flags, scope, index)


def rtattr(attr_type: int, payload: bytes) -> bytes:
    length = 4 + len(payload)
    return struct.pack("=HH", length, attr_type) + payload + (
        b"\x00" * (align4(length) - length)
    )


def align4(value: int) -> int:
    return (value + 3) & ~3


def mac_bytes(interface: VirtualNetworkInterface) -> bytes:
    if interface.mac_address:
        parts = interface.mac_address.split(":")
        if len(parts) == 6:
            try:
                return bytes(int(part, 16) for part in parts)
            except ValueError:
                pass

    if interface.ip_address is not None:
        try:
            return b"\x02\x42" + ipaddress.IPv4Address(interface.ip_address).packed
        except ValueError:
            pass

    digest = hashlib.sha256(
        f"{interface.network}/{interface.name}".encode("utf-8")
    ).digest()
    return b"\x02\x42" + digest[:4]


def is_ipv4_text(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def errno_from_name(value: object, default: int) -> int:
    if not isinstance(value, str):
        return default
    return getattr(errno, value, default)


def is_address_tuple(value: Any) -> bool:
    return (
        isinstance(value, tuple)
        and len(value) == 2
        and isinstance(value[0], str)
        and isinstance(value[1], int)
    )


def string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None
