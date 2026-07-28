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
    pids: set[int]
    interfaces: list[InterfaceRecord]
    leased: bool = False


@dataclass
class PortMapping:
    container_id: str
    pid: int
    interface: str
    network: str
    virtual_ip: str
    virtual_port: int
    protocol: str
    real_ip: str
    real_port: int
    scope: str = ""

    def virtual_key(self) -> tuple[str, str, str, int, str]:
        return (
            self.network,
            self.scope,
            self.virtual_ip,
            self.virtual_port,
            self.protocol,
        )


@dataclass
class NetworkState:
    name: str
    subnet: ipaddress.IPv4Network
    gateway: str
    interfaces_by_ip: dict[str, InterfaceRecord] = field(default_factory=dict)


@dataclass(frozen=True)
class NetworkDefinition:
    name: str
    subnet: ipaddress.IPv4Network
    gateway: str | None = None


class VirtualNetworkRegistry:
    def __init__(self, networks: list[NetworkDefinition] | None = None) -> None:
        self._lock = threading.RLock()
        self.containers: dict[str, ContainerRecord] = {}
        self.networks: dict[str, NetworkState] = {}
        self.ports: dict[tuple[str, str, str, int, str], PortMapping] = {}
        self.peered_networks: dict[str, set[str]] = {}
        for network in networks or []:
            self.define_network(network)

    def define_network(self, definition: NetworkDefinition) -> None:
        with self._lock:
            gateway = definition.gateway or default_gateway(definition.subnet)
            try:
                gateway_address = ipaddress.IPv4Address(gateway)
            except ValueError as exc:
                raise RegistryError(f"invalid gateway: {gateway}", "EINVAL") from exc
            if gateway_address not in definition.subnet:
                raise RegistryError(
                    f"gateway is outside subnet: {gateway}",
                    "EINVAL",
                )

            existing = self.networks.get(definition.name)
            if existing is not None:
                if existing.subnet != definition.subnet or existing.gateway != gateway:
                    raise RegistryError(
                        f"network is already defined: {definition.name}",
                        "EADDRINUSE",
                    )
                return

            self.networks[definition.name] = NetworkState(
                name=definition.name,
                subnet=definition.subnet,
                gateway=gateway,
            )

    def remove_network(self, name: str) -> None:
        with self._lock:
            network = self.networks.pop(name, None)
            if network is None:
                raise RegistryError(f"network does not exist: {name}", "ENETUNREACH")
            for container in list(self.containers.values()):
                container.interfaces[:] = [
                    iface for iface in container.interfaces if iface.network != name
                ]
            for key in list(self.ports):
                if key[0] == name:
                    self.ports.pop(key, None)
            self.peered_networks.pop(name, None)
            for targets in self.peered_networks.values():
                targets.discard(name)

    def peer_networks(self, source: str, target: str) -> None:
        with self._lock:
            if source not in self.networks:
                raise RegistryError(f"network does not exist: {source}", "ENETUNREACH")
            if target not in self.networks:
                raise RegistryError(f"network does not exist: {target}", "ENETUNREACH")
            if source == target:
                raise RegistryError("cannot peer network with itself", "EINVAL")
            self.peered_networks.setdefault(source, set()).add(target)

    def unpeer_networks(self, source: str, target: str) -> None:
        with self._lock:
            self.peered_networks.get(source, set()).discard(target)

    def list_peerings(self) -> list[dict[str, str]]:
        with self._lock:
            result: list[dict[str, str]] = []
            for source, targets in sorted(self.peered_networks.items()):
                for target in sorted(targets):
                    result.append({"source": source, "target": target})
            return result

    def list_containers(
        self, network_name: str | None = None
    ) -> list[dict[str, object]]:
        with self._lock:
            result: list[dict[str, object]] = []
            for cid in sorted(self.containers):
                record = self.containers[cid]
                interfaces = [
                    {
                        "name": iface.name,
                        "network": iface.network,
                        "ip": iface.ip,
                        "prefix_length": iface.prefix_length,
                        "gateway": iface.gateway,
                        "mac": iface.mac,
                        "mtu": iface.mtu,
                        "dns": list(iface.dns),
                    }
                    for iface in record.interfaces
                    if network_name is None or iface.network == network_name
                ]
                if not interfaces:
                    continue
                result.append({
                    "container_id": cid,
                    "pids": sorted(record.pids),
                    "leased": record.leased,
                    "interfaces": interfaces,
                })
            return result

    def find_mapping(
        self, container_id: str, virtual_port: int, protocol: str
    ) -> PortMapping | None:
        with self._lock:
            for mapping in self.ports.values():
                if (
                    mapping.container_id == container_id
                    and mapping.virtual_port == virtual_port
                    and mapping.protocol == protocol
                ):
                    return mapping
            return None

    def allocate_container(
        self, container_id: str, interfaces: list[dict[str, object]]
    ) -> list[InterfaceRecord]:
        return self._ensure_container(container_id, None, interfaces, leased=True)

    def register_container(
        self, container_id: str, pid: int, interfaces: list[dict[str, object]]
    ) -> list[InterfaceRecord]:
        return self._ensure_container(container_id, pid, interfaces, leased=False)

    def _ensure_container(
        self,
        container_id: str,
        pid: int | None,
        interfaces: list[dict[str, object]],
        *,
        leased: bool,
    ) -> list[InterfaceRecord]:
        with self._lock:
            existing = self.containers.get(container_id)
            if existing is not None:
                self._validate_existing_interfaces(container_id, existing, interfaces)
                if pid is not None:
                    existing.pids.add(pid)
                existing.leased = existing.leased or leased
                return existing.interfaces

            records = [
                self._register_interface(container_id, interface)
                for interface in interfaces
            ]
            self.containers[container_id] = ContainerRecord(
                container_id=container_id,
                pids={pid} if pid is not None else set(),
                interfaces=records,
                leased=leased,
            )
            return records

    def unregister_container(self, container_id: str, pid: int | None = None) -> bool:
        with self._lock:
            record = self.containers.get(container_id)
            if record is None:
                return False

            if pid is not None:
                record.pids.discard(pid)
                self._release_port_mappings(container_id, pid=pid)
                if record.pids or record.leased:
                    return False

            return self.release_container(container_id)

    def release_container(self, container_id: str) -> bool:
        with self._lock:
            record = self.containers.pop(container_id, None)
            if record is None:
                return False
            for interface in record.interfaces:
                network = self.networks.get(interface.network)
                if network is not None:
                    network.interfaces_by_ip.pop(interface.ip, None)
            for key, mapping in list(self.ports.items()):
                if mapping.container_id == container_id:
                    self.ports.pop(key, None)
            return True

    def _release_port_mappings(self, container_id: str, pid: int | None = None) -> None:
        for key, mapping in list(self.ports.items()):
            if mapping.container_id != container_id:
                continue
            if pid is not None and mapping.pid != pid:
                continue
            self.ports.pop(key, None)

    def _validate_existing_interfaces(
        self,
        container_id: str,
        existing: ContainerRecord,
        interfaces: list[dict[str, object]],
    ) -> None:
        existing_by_key = {
            (interface.name, interface.network): interface
            for interface in existing.interfaces
        }
        for data in interfaces:
            name = require_string(data, "name")
            network_name = require_string(data, "network")
            record = existing_by_key.get((name, network_name))
            if record is None:
                raise RegistryError(
                    f"network namespace already has different interfaces: {container_id}",
                    "EINVAL",
                )
            ip_value = optional_string(data.get("ip"))
            if ip_value is not None and ip_value != record.ip:
                raise RegistryError(
                    f"network namespace address mismatch: {ip_value} != {record.ip}",
                    "EINVAL",
                )

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
        gateway = default_gateway(subnet)
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
        pid: int,
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
            scope = ""
            if is_loopback_ip(virtual_ip):
                scope = container_id
            elif virtual_ip != interface.ip:
                raise RegistryError(f"address is not assigned: {virtual_ip}", "EADDRNOTAVAIL")

            key = (network_name, scope, virtual_ip, virtual_port, protocol)
            if key in self.ports:
                raise RegistryError(
                f"address is already allocated: {virtual_ip}:{virtual_port}",
                    "EADDRINUSE",
                )
            real_ip, real_port = reserve_loopback_port()
            mapping = PortMapping(
                container_id=container_id,
                pid=pid,
                interface=interface_name,
                network=network_name,
                virtual_ip=virtual_ip,
                virtual_port=virtual_port,
                protocol=protocol,
                real_ip=real_ip,
                real_port=real_port,
                scope=scope,
            )
            self.ports[key] = mapping
            return mapping

    def release_port_mapping(self, mapping: PortMapping) -> None:
        with self._lock:
            self.ports.pop(mapping.virtual_key(), None)

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
            scope = container_id if is_loopback_ip(destination_ip) else ""
            if scope == "" and destination_ip not in network.interfaces_by_ip:
                mapping = self._route_via_peered(
                    network_name, destination_ip, destination_port, protocol
                )
                if mapping is not None:
                    return mapping
                raise RegistryError(
                    f"host is unreachable: {destination_ip}",
                    "EHOSTUNREACH",
                )

            key = (network_name, scope, destination_ip, destination_port, protocol)
            mapping = self.ports.get(key)
            if mapping is None:
                raise RegistryError(
                    f"connection refused: {destination_ip}:{destination_port}",
                    "ECONNREFUSED",
                )
            return mapping

    def _route_via_peered(
        self,
        source_network: str,
        destination_ip: str,
        destination_port: int,
        protocol: str,
    ) -> PortMapping | None:
        for peered_name in self.peered_networks.get(source_network, set()):
            peered_network = self.networks.get(peered_name)
            if peered_network is None:
                continue
            if destination_ip in peered_network.interfaces_by_ip:
                key = (peered_name, "", destination_ip, destination_port, protocol)
                mapping = self.ports.get(key)
                if mapping is not None:
                    return mapping
        return None

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


def default_gateway(subnet: ipaddress.IPv4Network) -> str:
    try:
        return str(next(subnet.hosts()))
    except StopIteration as exc:
        raise RegistryError(f"network has no usable addresses: {subnet}", "EINVAL") from exc


def is_loopback_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


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
