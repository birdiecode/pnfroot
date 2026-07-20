from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
import unittest

from netservice.server import VirtualNetworkService, parse_network_list
from virtual_network import (
    ContainerNetworkConfig,
    NetworkServiceClient,
    PublishedPort,
    VirtualNetworkInterface,
)


class NetserviceIntegrationTests(unittest.TestCase):
    def test_routes_virtual_connect_through_tcp_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            socket_path = os.path.join(directory, "net.unix")
            service = VirtualNetworkService(socket_path, quiet=True)
            service_thread = threading.Thread(target=service.serve_forever)
            service_thread.daemon = True
            service_thread.start()
            wait_for_path(socket_path)

            db_client = NetworkServiceClient(socket_path)
            app_client = NetworkServiceClient(socket_path)
            try:
                db_config = ContainerNetworkConfig(
                    container_id="db-01",
                    service_socket=socket_path,
                    interfaces=[
                        VirtualNetworkInterface(
                            name="eth0",
                            network="testnet",
                            ip_address="10.50.0.20",
                            prefix_length=24,
                        )
                    ],
                )
                app_config = ContainerNetworkConfig(
                    container_id="app-01",
                    service_socket=socket_path,
                    interfaces=[
                        VirtualNetworkInterface(
                            name="eth0",
                            network="testnet",
                            ip_address="10.50.0.10",
                            prefix_length=24,
                        )
                    ],
                )
                db_client.register_container(db_config, 1001)
                app_client.register_container(app_config, 1002)

                bind_response = db_client.request(
                    {
                        "version": 1,
                        "type": "bind_request",
                        "request_id": "req-bind",
                        "container_id": "db-01",
                        "pid": 1001,
                        "fd": 5,
                        "protocol": "tcp",
                        "interface": "eth0",
                        "network": "testnet",
                        "virtual_address": {
                            "ip": "10.50.0.20",
                            "port": 8080,
                        },
                    }
                )
                real_address = bind_response["real_address"]
                server_thread = start_echo_server(
                    real_address["ip"],
                    real_address["port"],
                )

                connect_response = app_client.request(
                    {
                        "version": 1,
                        "type": "connect_request",
                        "request_id": "req-connect",
                        "container_id": "app-01",
                        "pid": 1002,
                        "tid": 1002,
                        "fd": 7,
                        "protocol": "tcp",
                        "address_family": "ipv4",
                        "source": {
                            "interface": "eth0",
                            "network": "testnet",
                            "ip": "10.50.0.10",
                            "port": 0,
                        },
                        "destination": {
                            "ip": "10.50.0.20",
                            "port": 8080,
                        },
                    }
                )

                self.assertEqual(connect_response["action"], "proxy")
                proxy = connect_response["proxy"]
                with socket.create_connection((proxy["ip"], proxy["port"]), timeout=5) as sock:
                    sock.sendall(b"ping")
                    self.assertEqual(sock.recv(1024), b"echo:ping")
                server_thread.join(timeout=2)
            finally:
                db_client.unregister_container("db-01")
                app_client.unregister_container("app-01")
                db_client.close()
                app_client.close()
                service.stop()
                poke_unix_socket(socket_path)
                service_thread.join(timeout=2)

    def test_publishes_container_port_on_host(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            socket_path = os.path.join(directory, "net.unix")
            host_port = reserve_local_port()
            service = VirtualNetworkService(socket_path, quiet=True)
            service_thread = threading.Thread(target=service.serve_forever)
            service_thread.daemon = True
            service_thread.start()
            wait_for_path(socket_path)

            client = NetworkServiceClient(socket_path)
            try:
                config = ContainerNetworkConfig(
                    container_id="web-01",
                    service_socket=socket_path,
                    interfaces=[
                        VirtualNetworkInterface(
                            name="eth0",
                            network="testnet",
                            ip_address="10.50.0.30",
                            prefix_length=24,
                        )
                    ],
                    published_ports=[
                        PublishedPort(
                            host_ip="127.0.0.1",
                            host_port=host_port,
                            container_port=8080,
                        )
                    ],
                )
                client.register_container(config, 1003)

                bind_response = client.request(
                    {
                        "version": 1,
                        "type": "bind_request",
                        "request_id": "req-bind-publish",
                        "container_id": "web-01",
                        "pid": 1003,
                        "fd": 5,
                        "protocol": "tcp",
                        "interface": "eth0",
                        "network": "testnet",
                        "virtual_address": {
                            "ip": "10.50.0.30",
                            "port": 8080,
                        },
                    }
                )
                real_address = bind_response["real_address"]
                server_thread = start_echo_server(
                    real_address["ip"],
                    real_address["port"],
                )

                with socket.create_connection(("127.0.0.1", host_port), timeout=5) as sock:
                    sock.sendall(b"publish")
                    self.assertEqual(sock.recv(1024), b"echo:publish")
                server_thread.join(timeout=2)
            finally:
                client.unregister_container("web-01")
                client.close()
                service.stop()
                poke_unix_socket(socket_path)
                service_thread.join(timeout=2)

    def test_allows_internet_egress_for_configured_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            socket_path = os.path.join(directory, "net.unix")
            service = VirtualNetworkService(
                socket_path,
                quiet=True,
                internet_networks={"testnet"},
            )
            service_thread = threading.Thread(target=service.serve_forever)
            service_thread.daemon = True
            service_thread.start()
            wait_for_path(socket_path)

            client = NetworkServiceClient(socket_path)
            try:
                config = ContainerNetworkConfig(
                    container_id="app-01",
                    service_socket=socket_path,
                    interfaces=[
                        VirtualNetworkInterface(
                            name="eth0",
                            network="testnet",
                            ip_address="10.50.0.10",
                            prefix_length=24,
                        )
                    ],
                )
                client.register_container(config, 1002)

                response = client.request(
                    {
                        "version": 1,
                        "type": "connect_request",
                        "request_id": "req-internet",
                        "container_id": "app-01",
                        "pid": 1002,
                        "tid": 1002,
                        "fd": 7,
                        "protocol": "tcp",
                        "address_family": "ipv4",
                        "source": {
                            "interface": "eth0",
                            "network": "testnet",
                            "ip": "10.50.0.10",
                            "port": 0,
                        },
                        "destination": {
                            "ip": "8.8.8.8",
                            "port": 80,
                        },
                    }
                )

                self.assertEqual(response["action"], "allow")
            finally:
                client.unregister_container("app-01")
                client.close()
                service.stop()
                poke_unix_socket(socket_path)
                service_thread.join(timeout=2)

    def test_denies_internet_egress_for_unconfigured_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            socket_path = os.path.join(directory, "net.unix")
            service = VirtualNetworkService(socket_path, quiet=True)
            service_thread = threading.Thread(target=service.serve_forever)
            service_thread.daemon = True
            service_thread.start()
            wait_for_path(socket_path)

            client = NetworkServiceClient(socket_path)
            try:
                config = ContainerNetworkConfig(
                    container_id="app-01",
                    service_socket=socket_path,
                    interfaces=[
                        VirtualNetworkInterface(
                            name="eth0",
                            network="testnet",
                            ip_address="10.50.0.10",
                            prefix_length=24,
                        )
                    ],
                )
                client.register_container(config, 1002)

                response = client.request(
                    {
                        "version": 1,
                        "type": "connect_request",
                        "request_id": "req-no-internet",
                        "container_id": "app-01",
                        "pid": 1002,
                        "tid": 1002,
                        "fd": 7,
                        "protocol": "tcp",
                        "address_family": "ipv4",
                        "source": {
                            "interface": "eth0",
                            "network": "testnet",
                            "ip": "10.50.0.10",
                            "port": 0,
                        },
                        "destination": {
                            "ip": "8.8.8.8",
                            "port": 80,
                        },
                    }
                )

                self.assertEqual(response["action"], "deny")
                self.assertEqual(response["errno"], "EHOSTUNREACH")
            finally:
                client.unregister_container("app-01")
                client.close()
                service.stop()
                poke_unix_socket(socket_path)
                service_thread.join(timeout=2)

    def test_does_not_treat_unregistered_virtual_ip_as_internet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            socket_path = os.path.join(directory, "net.unix")
            service = VirtualNetworkService(
                socket_path,
                quiet=True,
                internet_networks={"testnet"},
            )
            service_thread = threading.Thread(target=service.serve_forever)
            service_thread.daemon = True
            service_thread.start()
            wait_for_path(socket_path)

            client = NetworkServiceClient(socket_path)
            try:
                config = ContainerNetworkConfig(
                    container_id="app-01",
                    service_socket=socket_path,
                    interfaces=[
                        VirtualNetworkInterface(
                            name="eth0",
                            network="testnet",
                            ip_address="10.50.0.10",
                            prefix_length=24,
                        )
                    ],
                )
                client.register_container(config, 1002)

                response = client.request(
                    {
                        "version": 1,
                        "type": "connect_request",
                        "request_id": "req-virtual-miss",
                        "container_id": "app-01",
                        "pid": 1002,
                        "tid": 1002,
                        "fd": 7,
                        "protocol": "tcp",
                        "address_family": "ipv4",
                        "source": {
                            "interface": "eth0",
                            "network": "testnet",
                            "ip": "10.50.0.10",
                            "port": 0,
                        },
                        "destination": {
                            "ip": "10.50.0.99",
                            "port": 80,
                        },
                    }
                )

                self.assertEqual(response["action"], "deny")
                self.assertEqual(response["errno"], "EHOSTUNREACH")
            finally:
                client.unregister_container("app-01")
                client.close()
                service.stop()
                poke_unix_socket(socket_path)
                service_thread.join(timeout=2)

    def test_parses_internet_network_list(self) -> None:
        self.assertEqual(
            parse_network_list(["frontend, backend", "backend,database"]),
            {"frontend", "backend", "database"},
        )


def wait_for_path(path: str) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.01)
    raise TimeoutError(path)


def start_echo_server(host: str, port: int) -> threading.Thread:
    ready = threading.Event()

    def run() -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(1)
        listener.settimeout(5)
        ready.set()
        try:
            connection, _ = listener.accept()
            with connection:
                data = connection.recv(1024)
                connection.sendall(b"echo:" + data)
        finally:
            listener.close()

    thread = threading.Thread(target=run)
    thread.daemon = True
    thread.start()
    self_ready = ready.wait(timeout=5)
    if not self_ready:
        raise TimeoutError("echo server did not start")
    return thread


def reserve_local_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def poke_unix_socket(path: str) -> None:
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(path)
        finally:
            sock.close()
    except OSError:
        pass


if __name__ == "__main__":
    unittest.main()
