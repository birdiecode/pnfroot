"""In-memory virtual network registry."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import threading
from dataclasses import dataclass, field


class RegistryError(RuntimeError):
    def __init__(self, message: str, errno_name: str = "EACCES"):
        super().__init__(message)
        self.errno_name = errno_name


@dataclass
class InterfaceRecord:
    container_id: str
    name: str
    network: str
    ip: str
    prefix_length: int
    gateway: str | None = None
    mac: str | None = None
    mtu: int = 1500
    dns: list[str] = field(default_factory=list)

    def to_message(self) -> dict[str, object]:
        return {
            "name": self.name,
            "network": self.network,
            "ip": self.ip,
            "prefix_length": self.prefix_length,
            "gateway": self.gateway,
            "mac": self.mac,
            "mtu": self.mtu,
            "dns": list(self.dns),
        }


@dataclass
class ContainerRecord:
    container_id: str
    pid: int
    interfaces: list[InterfaceRecord]


@dataclass
class PortMapping:
    container_id: str
    interface: str
    network: str
    virtual_ip: str
    virtual_port: int
    protocol: str
    real_ip: str
    real_port: int

    def virtual_key(self) -> tuple[str, str, int, str]:
        return (self.network, self.virtual_ip, self.virtual_port, self.protocol)


@dataclass
class NetworkState:
    name: str
    subnet: ipaddress.IPv4Network
    gateway: str
    interfaces_by_ip: dict[str, InterfaceRecord] = field(default_factory=dict)


class VirtualNetworkRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.containers: dict[str, ContainerRecord] = {}
        self.networks: dict[str, NetworkState] = {}
        self.ports: dict[tuple[str, str, int, str], PortMapping] = {}

    def register_container(
        self, container_id: str, pid: int, interfaces: list[dict[str, object]]
    ) -> list[InterfaceRecord]:
        with self._lock:
            self.unregister_container(container_id)
            records = [
                self._register_interface(container_id, interface)
                for interface in interfaces
            ]
            self.containers[container_id] = ContainerRecord(
                container_id=container_id,
                pid=pid,
                interfaces=records,
            )
            return records

    def unregister_container(self, container_id: str) -> None:
        with self._lock:
            record = self.containers.pop(container_id, None)
            if record is not None:
                for interface in record.interfaces:
                    network = self.networks.get(interface.network)
                    if network is not None:
                        network.interfaces_by_ip.pop(interface.ip, None)
            for key, mapping in list(self.ports.items()):
                if mapping.container_id == container_id:
                    self.ports.pop(key, None)

    def _register_interface(
        self, container_id: str, data: dict[str, object]
    ) -> InterfaceRecord:
        name = require_string(data, "name")
        network_name = require_string(data, "network")
        ip_value = optional_string(data.get("ip"))
        prefix_value = data.get("prefix_length")
        prefix_length = prefix_value if isinstance(prefix_value, int) else None

        network = self._network_for(network_name, ip_value, prefix_length)
        if ip_value is None:
            ip_value = self._allocate_ip(network)
            prefix_length = network.subnet.prefixlen
        else:
            try:
                ipaddress.IPv4Address(ip_value)
            except ValueError as exc:
                raise RegistryError(f"invalid IPv4 address: {ip_value}", "EINVAL") from exc
            if prefix_length is None:
                prefix_length = network.subnet.prefixlen

        if ip_value == network.gateway:
            raise RegistryError(f"address is already allocated: {ip_value}", "EADDRINUSE")
        existing = network.interfaces_by_ip.get(ip_value)
        if existing is not None and existing.container_id != container_id:
            raise RegistryError(f"address is already allocated: {ip_value}", "EADDRINUSE")

        record = InterfaceRecord(
            container_id=container_id,
            name=name,
            network=network_name,
            ip=ip_value,
            prefix_length=prefix_length,
            gateway=optional_string(data.get("gateway")) or network.gateway,
            mac=optional_string(data.get("mac")),
            mtu=int(data.get("mtu") or 1500),
            dns=list(data.get("dns") or []),
        )
        network.interfaces_by_ip[ip_value] = record
        return record

    def _network_for(
        self, name: str, ip_value: str | None, prefix_length: int | None
    ) -> NetworkState:
        existing = self.networks.get(name)
        if existing is not None:
            return existing

        if ip_value is not None:
            prefix = prefix_length if prefix_length is not None else 24
            subnet = ipaddress.ip_network(f"{ip_value}/{prefix}", strict=False)
        else:
            subnet = deterministic_subnet(name)
        gateway = str(next(subnet.hosts()))
        state = NetworkState(name=name, subnet=subnet, gateway=gateway)
        self.networks[name] = state
        return state

    def _allocate_ip(self, network: NetworkState) -> str:
        for host in network.subnet.hosts():
            value = str(host)
            if value == network.gateway:
                continue
            if value not in network.interfaces_by_ip:
                return value
        raise RegistryError(f"network has no free addresses: {network.name}", "EADDRINUSE")

    def bind_port(
        self,
        container_id: str,
        interface_name: str,
        network_name: str,
        virtual_ip: str,
        virtual_port: int,
        protocol: str,
    ) -> PortMapping:
        with self._lock:
            interface = self.interface(container_id, interface_name, network_name)
            if virtual_ip == "0.0.0.0":
                virtual_ip = interface.ip
            if virtual_ip != interface.ip:
                raise RegistryError(f"address is not assigned: {virtual_ip}", "EADDRNOTAVAIL")

            key = (network_name, virtual_ip, virtual_port, protocol)
            if key in self.ports:
                raise RegistryError(
                    f"address is already allocated: {virtual_ip}:{virtual_port}",
                    "EADDRINUSE",
                )
            real_ip, real_port = reserve_loopback_port()
            mapping = PortMapping(
                container_id=container_id,
                interface=interface_name,
                network=network_name,
                virtual_ip=virtual_ip,
                virtual_port=virtual_port,
                protocol=protocol,
                real_ip=real_ip,
                real_port=real_port,
            )
            self.ports[key] = mapping
            return mapping

    def route_connect(
        self,
        container_id: str,
        network_name: str,
        destination_ip: str,
        destination_port: int,
        protocol: str,
    ) -> PortMapping:
        with self._lock:
            self.ensure_source_network(container_id, network_name)
            network = self.networks[network_name]
            if destination_ip not in network.interfaces_by_ip:
                raise RegistryError(
                    f"host is unreachable: {destination_ip}",
                    "EHOSTUNREACH",
                )

            key = (network_name, destination_ip, destination_port, protocol)
            mapping = self.ports.get(key)
            if mapping is None:
                raise RegistryError(
                    f"connection refused: {destination_ip}:{destination_port}",
                    "ECONNREFUSED",
                )
            return mapping

    def ensure_source_network(self, container_id: str, network_name: str) -> None:
        with self._lock:
            source = self.containers.get(container_id)
            if source is None:
                raise RegistryError(f"unknown container: {container_id}", "ENETUNREACH")
            if not any(interface.network == network_name for interface in source.interfaces):
                raise RegistryError(f"network does not exist: {network_name}", "ENETUNREACH")
            if network_name not in self.networks:
                raise RegistryError(f"network does not exist: {network_name}", "ENETUNREACH")

    def destination_inside_network(self, network_name: str, destination_ip: str) -> bool:
        with self._lock:
            network = self.networks.get(network_name)
            if network is None:
                raise RegistryError(f"network does not exist: {network_name}", "ENETUNREACH")
            try:
                address = ipaddress.ip_address(destination_ip)
            except ValueError as exc:
                raise RegistryError(f"invalid IP address: {destination_ip}", "EINVAL") from exc
            return address.version == network.subnet.version and address in network.subnet

    def interface(
        self, container_id: str, interface_name: str, network_name: str
    ) -> InterfaceRecord:
        container = self.containers.get(container_id)
        if container is None:
            raise RegistryError(f"unknown container: {container_id}", "ENETUNREACH")
        for interface in container.interfaces:
            if interface.name == interface_name and interface.network == network_name:
                return interface
        raise RegistryError(f"network does not exist: {network_name}", "ENETUNREACH")


def deterministic_subnet(network_name: str) -> ipaddress.IPv4Network:
    digest = hashlib.sha256(network_name.encode("utf-8")).digest()
    second_octet = 16 + digest[0] % 200
    third_octet = digest[1]
    return ipaddress.ip_network(f"10.{second_octet}.{third_octet}.0/24")


def reserve_loopback_port() -> tuple[str, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()
    finally:
        sock.close()


def require_string(data: dict[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise RegistryError(f"missing field: {key}", "EINVAL")
    return value


def optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None
