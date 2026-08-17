"""Small TCP proxy used by the virtual network service."""

from __future__ import annotations

import socket
import threading


class TcpProxyManager:
    def __init__(self, listen_host: str = "127.0.0.1") -> None:
        self.listen_host = listen_host

    def create_proxy(
        self, connection_id: str, target_host: str, target_port: int
    ) -> tuple[str, int]:
        proxy = OneShotTcpProxy(
            connection_id=connection_id,
            listen_host=self.listen_host,
            target_host=target_host,
            target_port=target_port,
        )
        return proxy.start()

    def create_forwarder(
        self,
        forwarder_id: str,
        listen_host: str,
        listen_port: int,
        target_host: str,
        target_port: int,
    ) -> tuple["TcpForwarder", tuple[str, int]]:
        forwarder = TcpForwarder(
            forwarder_id=forwarder_id,
            listen_host=listen_host,
            listen_port=listen_port,
            target_host=target_host,
            target_port=target_port,
        )
        try:
            address = forwarder.start()
        except OSError:
            forwarder.stop()
            raise
        return forwarder, address


class OneShotTcpProxy:
    def __init__(
        self,
        connection_id: str,
        listen_host: str,
        target_host: str,
        target_port: int,
    ) -> None:
        self.connection_id = connection_id
        self.listen_host = listen_host
        self.target_host = target_host
        self.target_port = target_port
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self) -> tuple[str, int]:
        self.listener.bind((self.listen_host, 0))
        self.listener.listen(1)
        address = self.listener.getsockname()
        thread = threading.Thread(target=self._run, name=f"tcp-proxy-{self.connection_id}")
        thread.daemon = True
        thread.start()
        return address

    def _run(self) -> None:
        try:
            self.listener.settimeout(60.0)
            client, _ = self.listener.accept()
        except OSError:
            self.close_listener()
            return
        finally:
            self.close_listener()

        try:
            upstream = socket.create_connection((self.target_host, self.target_port))
        except OSError:
            client.close()
            return

        forward = threading.Thread(target=pipe, args=(client, upstream))
        backward = threading.Thread(target=pipe, args=(upstream, client))
        forward.daemon = True
        backward.daemon = True
        forward.start()
        backward.start()

    def close_listener(self) -> None:
        try:
            self.listener.close()
        except OSError:
            pass


class TcpForwarder:
    def __init__(
        self,
        forwarder_id: str,
        listen_host: str,
        listen_port: int,
        target_host: str,
        target_port: int,
    ) -> None:
        self.forwarder_id = forwarder_id
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.settimeout(0.2)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> tuple[str, int]:
        self.listener.bind((self.listen_host, self.listen_port))
        self.listener.listen(128)
        address = self.listener.getsockname()
        thread = threading.Thread(
            target=self._run,
            name=f"tcp-forwarder-{self.forwarder_id}",
        )
        thread.daemon = True
        self._thread = thread
        thread.start()
        return address

    def stop(self) -> None:
        self._stop.set()
        self.close_listener()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self._handle_client, args=(client,))
            thread.daemon = True
            thread.start()
        self.close_listener()

    def _handle_client(self, client: socket.socket) -> None:
        try:
            upstream = socket.create_connection((self.target_host, self.target_port))
        except OSError:
            client.close()
            return

        forward = threading.Thread(target=pipe, args=(client, upstream))
        backward = threading.Thread(target=pipe, args=(upstream, client))
        forward.daemon = True
        backward.daemon = True
        forward.start()
        backward.start()

    def close_listener(self) -> None:
        try:
            self.listener.close()
        except OSError:
            pass


def pipe(source: socket.socket, destination: socket.socket) -> None:
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            destination.sendall(data)
    except OSError:
        pass
    finally:
        shutdown_close(source)
        shutdown_close(destination)


def shutdown_close(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass
