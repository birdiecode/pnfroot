#!/usr/bin/env python3
"""Unix-socket virtual network service."""

from __future__ import annotations

import argparse
import errno
import ipaddress
import os
import socket
import stat
import sys
import threading
import uuid
from dataclasses import dataclass

if __package__ in {None, ""}:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netservice.protocol import ProtocolError, read_message, write_message
from netservice.registry import PortMapping, RegistryError, VirtualNetworkRegistry
from netservice.tcp_proxy import TcpForwarder, TcpProxyManager


@dataclass
class PublishRule:
    container_id: str
    host_ip: str
    host_port: int
    container_port: int
    protocol: str

    def key(self) -> tuple[str, str, int, int, str]:
        return (
            self.container_id,
            self.host_ip,
            self.host_port,
            self.container_port,
            self.protocol,
        )

    def to_message(self) -> dict[str, object]:
        return {
            "host_ip": self.host_ip,
            "host_port": self.host_port,
            "container_port": self.container_port,
            "protocol": self.protocol,
        }


@dataclass
class ActivePublish:
    rule: PublishRule
    mapping: PortMapping
    forwarder: TcpForwarder


class VirtualNetworkService:
    def __init__(
        self,
        socket_path: str,
        *,
        quiet: bool = True,
        internet_networks: set[str] | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.quiet = quiet
        self.internet_networks = set(internet_networks or set())
        self.registry = VirtualNetworkRegistry()
        self.proxy_manager = TcpProxyManager()
        self.publish_rules: dict[str, list[PublishRule]] = {}
        self.active_publishes: dict[tuple[str, str, int, int, str], ActivePublish] = {}
        self._publish_lock = threading.RLock()
        self.listener: socket.socket | None = None
        self._stop = threading.Event()

    def serve_forever(self) -> None:
        self.prepare_socket_path()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(self.socket_path)
        listener.listen(128)
        self.listener = listener
        self.log(f"listening on {self.socket_path}")
        try:
            while not self._stop.is_set():
                try:
                    connection, _ = listener.accept()
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                thread = threading.Thread(target=self.handle_client, args=(connection,))
                thread.daemon = True
                thread.start()
        finally:
            self.stop_all_published_ports()
            listener.close()
            try:
                os.unlink(self.socket_path)
            except FileNotFoundError:
                pass

    def stop(self) -> None:
        self._stop.set()
        if self.listener is not None:
            try:
                self.listener.close()
            except OSError:
                pass

    def prepare_socket_path(self) -> None:
        try:
            mode = os.stat(self.socket_path).st_mode
        except FileNotFoundError:
            parent = os.path.dirname(self.socket_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            return
        if stat.S_ISSOCK(mode):
            os.unlink(self.socket_path)
            return
        raise SystemExit(f"refusing to replace non-socket path: {self.socket_path}")

    def handle_client(self, connection: socket.socket) -> None:
        with connection:
            reader = connection.makefile("rb")
            writer = connection.makefile("wb")
            while True:
                try:
                    message = read_message(reader)
                except ProtocolError as exc:
                    write_message(
                        writer,
                        {
                            "version": 1,
                            "type": "error",
                            "success": False,
                            "error": str(exc),
                        },
                    )
                    return
                if message is None:
                    return
                response = self.handle_message(message)
                write_message(writer, response)

    def handle_message(self, message: dict[str, object]) -> dict[str, object]:
        message_type = message.get("type")
        try:
            if message_type == "register_container":
                return self.handle_register_container(message)
            if message_type == "unregister_container":
                return self.handle_unregister_container(message)
            if message_type == "bind_request":
                return self.handle_bind_request(message)
            if message_type == "connect_request":
                return self.handle_connect_request(message)
        except RegistryError as exc:
            self.log(f"{message_type} denied: {exc.errno_name} {exc}")
            return error_response(message, exc.errno_name, str(exc))
        except (KeyError, TypeError, ValueError) as exc:
            self.log(f"{message_type} failed: EINVAL {exc}")
            return error_response(message, "EINVAL", str(exc))

        self.log(f"unknown message type: {message_type}")
        return error_response(message, "EINVAL", f"unknown message type: {message_type}")

    def handle_register_container(
        self, message: dict[str, object]
    ) -> dict[str, object]:
        container_id = require_string(message, "container_id")
        pid = require_int(message, "pid")
        interfaces = message.get("interfaces")
        if not isinstance(interfaces, list):
            raise ValueError("interfaces must be a list")
        publish_rules = parse_publish_rules(
            container_id,
            message.get("published_ports", []),
        )
        self.remove_published_ports(container_id)
        records = self.registry.register_container(container_id, pid, interfaces)
        with self._publish_lock:
            self.publish_rules[container_id] = publish_rules
        self.log(
            "registered "
            + container_id
            + " "
            + ", ".join(f"{item.network}/{item.name}/{item.ip}" for item in records)
        )
        if publish_rules:
            self.log(
                "publish "
                + container_id
                + " "
                + ", ".join(
                    f"{rule.host_ip}:{rule.host_port}->{rule.container_port}/{rule.protocol}"
                    for rule in publish_rules
                )
            )
        return {
            "version": 1,
            "type": "register_container_result",
            "success": True,
            "container_id": container_id,
            "interfaces": [record.to_message() for record in records],
            "published_ports": [rule.to_message() for rule in publish_rules],
        }

    def handle_unregister_container(
        self, message: dict[str, object]
    ) -> dict[str, object]:
        container_id = require_string(message, "container_id")
        self.remove_published_ports(container_id)
        self.registry.unregister_container(container_id)
        self.log(f"unregistered {container_id}")
        return {
            "version": 1,
            "type": "unregister_container_result",
            "success": True,
            "container_id": container_id,
        }

    def handle_bind_request(self, message: dict[str, object]) -> dict[str, object]:
        request_id = require_string(message, "request_id")
        virtual_address = require_dict(message, "virtual_address")
        container_id = require_string(message, "container_id")
        mapping = self.registry.bind_port(
            container_id=container_id,
            interface_name=require_string(message, "interface"),
            network_name=require_string(message, "network"),
            virtual_ip=require_string(virtual_address, "ip"),
            virtual_port=require_int(virtual_address, "port"),
            protocol=require_string(message, "protocol"),
        )
        try:
            self.activate_published_ports(mapping)
        except RegistryError:
            self.registry.release_port_mapping(mapping)
            raise
        self.log(
            f"bind {mapping.network}/{mapping.virtual_ip}:{mapping.virtual_port} "
            f"-> {mapping.real_ip}:{mapping.real_port}"
        )
        return {
            "version": 1,
            "type": "bind_result",
            "request_id": request_id,
            "action": "redirect",
            "real_address": {
                "ip": mapping.real_ip,
                "port": mapping.real_port,
            },
        }

    def handle_connect_request(self, message: dict[str, object]) -> dict[str, object]:
        request_id = require_string(message, "request_id")
        container_id = require_string(message, "container_id")
        source = require_dict(message, "source")
        destination = require_dict(message, "destination")
        network_name = require_string(source, "network")
        destination_ip = require_string(destination, "ip")
        destination_port = require_int(destination, "port")
        protocol = require_string(message, "protocol")
        try:
            mapping = self.registry.route_connect(
                container_id=container_id,
                network_name=network_name,
                destination_ip=destination_ip,
                destination_port=destination_port,
                protocol=protocol,
            )
        except RegistryError as exc:
            if self.allow_internet_egress(
                container_id,
                network_name,
                destination_ip,
                protocol,
            ):
                self.log(
                    f"connect allowed internet {container_id} "
                    f"{network_name} -> {destination_ip}:{destination_port}"
                )
                return {
                    "version": 1,
                    "type": "connect_result",
                    "request_id": request_id,
                    "action": "allow",
                }
            self.log(
                f"connect denied {container_id} -> "
                f"{destination_ip}:{destination_port} "
                f"{exc.errno_name} {exc}"
            )
            return {
                "version": 1,
                "type": "connect_result",
                "request_id": request_id,
                "action": "deny",
                "errno": exc.errno_name,
                "reason": str(exc),
            }

        connection_id = f"conn-{uuid.uuid4().hex[:6]}"
        proxy_ip, proxy_port = self.proxy_manager.create_proxy(
            connection_id,
            mapping.real_ip,
            mapping.real_port,
        )
        self.log(
            f"connect {message.get('container_id')} -> "
            f"{mapping.network}/{mapping.virtual_ip}:{mapping.virtual_port} "
            f"via {proxy_ip}:{proxy_port}"
        )
        return {
            "version": 1,
            "type": "connect_result",
            "request_id": request_id,
            "action": "proxy",
            "connection_id": connection_id,
            "proxy": {
                "ip": proxy_ip,
                "port": proxy_port,
            },
        }

    def activate_published_ports(self, mapping: PortMapping) -> None:
        with self._publish_lock:
            rules = [
                rule
                for rule in self.publish_rules.get(mapping.container_id, [])
                if (
                    rule.container_port == mapping.virtual_port
                    and rule.protocol == mapping.protocol
                )
            ]
            started: list[PublishRule] = []
            try:
                for rule in rules:
                    key = rule.key()
                    if key in self.active_publishes:
                        continue
                    forwarder_id = (
                        f"pub-{mapping.container_id}-"
                        f"{rule.host_ip}-{rule.host_port}-{rule.container_port}"
                    )
                    forwarder, address = self.proxy_manager.create_forwarder(
                        forwarder_id=forwarder_id,
                        listen_host=rule.host_ip,
                        listen_port=rule.host_port,
                        target_host=mapping.real_ip,
                        target_port=mapping.real_port,
                    )
                    self.active_publishes[key] = ActivePublish(
                        rule=rule,
                        mapping=mapping,
                        forwarder=forwarder,
                    )
                    started.append(rule)
                    self.log(
                        f"published {address[0]}:{address[1]} -> "
                        f"{mapping.network}/{mapping.virtual_ip}:{mapping.virtual_port} "
                        f"({mapping.real_ip}:{mapping.real_port})"
                    )
            except OSError as exc:
                for rule in started:
                    self.deactivate_published_port(rule.key())
                errno_name = errno.errorcode.get(exc.errno or errno.EADDRINUSE, "EADDRINUSE")
                raise RegistryError(f"host port publish failed: {exc}", errno_name) from exc

    def remove_published_ports(self, container_id: str) -> None:
        with self._publish_lock:
            for key in [
                key
                for key in self.active_publishes
                if key[0] == container_id
            ]:
                self.deactivate_published_port(key)
            self.publish_rules.pop(container_id, None)

    def stop_all_published_ports(self) -> None:
        with self._publish_lock:
            for key in list(self.active_publishes):
                self.deactivate_published_port(key)
            self.publish_rules.clear()

    def deactivate_published_port(
        self,
        key: tuple[str, str, int, int, str],
    ) -> None:
        active = self.active_publishes.pop(key, None)
        if active is not None:
            active.forwarder.stop()

    def allow_internet_egress(
        self,
        container_id: str,
        network_name: str,
        destination_ip: str,
        protocol: str,
    ) -> bool:
        if network_name not in self.internet_networks or protocol != "tcp":
            return False

        self.registry.ensure_source_network(container_id, network_name)
        if self.registry.destination_inside_network(network_name, destination_ip):
            return False
        try:
            address = ipaddress.ip_address(destination_ip)
        except ValueError:
            return False

        return not (
            address.is_loopback
            or address.is_multicast
            or address.is_unspecified
            or address.is_link_local
        )

    def log(self, message: str) -> None:
        if not self.quiet:
            print(f"[netservice] {message}", file=sys.stderr, flush=True)


def error_response(
    request: dict[str, object], errno_name: str, reason: str
) -> dict[str, object]:
    response: dict[str, object] = {
        "version": 1,
        "success": False,
        "error": reason,
        "errno": errno_name,
    }
    request_id = request.get("request_id")
    if isinstance(request_id, str):
        response["request_id"] = request_id
    request_type = request.get("type")
    if request_type == "connect_request":
        response.update({"type": "connect_result", "action": "deny", "reason": reason})
    elif request_type == "bind_request":
        response.update({"type": "bind_result", "action": "deny", "reason": reason})
    elif request_type == "register_container":
        response.update({"type": "register_container_result"})
    else:
        response.update({"type": "error"})
    return response


def require_string(data: dict[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing field: {key}")
    return value


def require_int(data: dict[str, object], key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int):
        raise ValueError(f"missing field: {key}")
    return value


def require_dict(data: dict[str, object], key: str) -> dict[str, object]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"missing field: {key}")
    return value


def parse_publish_rules(container_id: str, value: object) -> list[PublishRule]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("published_ports must be a list")

    rules: list[PublishRule] = []
    seen_host_ports: set[tuple[str, int, str]] = set()
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("published port must be an object")
        host_ip = require_string(item, "host_ip")
        host_port = require_int(item, "host_port")
        container_port = require_int(item, "container_port")
        protocol_value = item.get("protocol", "tcp")
        if not isinstance(protocol_value, str) or not protocol_value:
            raise ValueError("missing field: protocol")
        protocol = protocol_value.lower()

        validate_publish_ip(host_ip)
        validate_publish_port(host_port, "host_port")
        validate_publish_port(container_port, "container_port")
        if protocol != "tcp":
            raise ValueError("published ports currently support only tcp")

        host_key = (host_ip, host_port, protocol)
        if host_key in seen_host_ports:
            raise ValueError(f"duplicate published host port: {host_ip}:{host_port}")
        seen_host_ports.add(host_key)

        rules.append(
            PublishRule(
                container_id=container_id,
                host_ip=host_ip,
                host_port=host_port,
                container_port=container_port,
                protocol=protocol,
            )
        )
    return rules


def validate_publish_ip(value: str) -> None:
    try:
        ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ValueError(f"invalid published host IP: {value}") from exc


def validate_publish_port(value: int, name: str) -> None:
    if not 1 <= value <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Virtual network Unix-socket service.")
    parser.add_argument(
        "--socket",
        default="/tmp/net.unix",
        help="Unix stream socket path to listen on",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="deprecated no-op; service logs are disabled by default",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        "--log",
        dest="verbose",
        action="store_true",
        help="enable service logs",
    )
    parser.add_argument(
        "--internet-networks",
        action="append",
        default=[],
        metavar="NETWORK[,NETWORK...]",
        help=(
            "comma-separated logical networks allowed to connect to non-virtual "
            "destinations through the host network"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    service = VirtualNetworkService(
        os.path.abspath(args.socket),
        quiet=not args.verbose,
        internet_networks=parse_network_list(args.internet_networks),
    )
    try:
        service.serve_forever()
    except KeyboardInterrupt:
        service.stop()
        return 130
    return 0


def parse_network_list(values: list[str]) -> set[str]:
    networks: set[str] = set()
    for value in values:
        for item in value.split(","):
            network = item.strip()
            if network:
                networks.add(network)
    return networks


if __name__ == "__main__":
    raise SystemExit(main())
