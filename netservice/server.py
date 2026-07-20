#!/usr/bin/env python3
"""Unix-socket virtual network service."""

from __future__ import annotations

import argparse
import os
import socket
import stat
import sys
import threading
import uuid

if __package__ in {None, ""}:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netservice.protocol import ProtocolError, read_message, write_message
from netservice.registry import RegistryError, VirtualNetworkRegistry
from netservice.tcp_proxy import TcpProxyManager


class VirtualNetworkService:
    def __init__(self, socket_path: str, *, quiet: bool = True) -> None:
        self.socket_path = socket_path
        self.quiet = quiet
        self.registry = VirtualNetworkRegistry()
        self.proxy_manager = TcpProxyManager()
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
        records = self.registry.register_container(container_id, pid, interfaces)
        self.log(
            "registered "
            + container_id
            + " "
            + ", ".join(f"{item.network}/{item.name}/{item.ip}" for item in records)
        )
        return {
            "version": 1,
            "type": "register_container_result",
            "success": True,
            "container_id": container_id,
            "interfaces": [record.to_message() for record in records],
        }

    def handle_unregister_container(
        self, message: dict[str, object]
    ) -> dict[str, object]:
        container_id = require_string(message, "container_id")
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
        mapping = self.registry.bind_port(
            container_id=require_string(message, "container_id"),
            interface_name=require_string(message, "interface"),
            network_name=require_string(message, "network"),
            virtual_ip=require_string(virtual_address, "ip"),
            virtual_port=require_int(virtual_address, "port"),
            protocol=require_string(message, "protocol"),
        )
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
        source = require_dict(message, "source")
        destination = require_dict(message, "destination")
        try:
            mapping = self.registry.route_connect(
                container_id=require_string(message, "container_id"),
                network_name=require_string(source, "network"),
                destination_ip=require_string(destination, "ip"),
                destination_port=require_int(destination, "port"),
                protocol=require_string(message, "protocol"),
            )
        except RegistryError as exc:
            self.log(
                f"connect denied {message.get('container_id')} -> "
                f"{destination.get('ip')}:{destination.get('port')} "
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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    service = VirtualNetworkService(
        os.path.abspath(args.socket),
        quiet=not args.verbose,
    )
    try:
        service.serve_forever()
    except KeyboardInterrupt:
        service.stop()
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
