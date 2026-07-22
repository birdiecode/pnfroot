from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import http.server
import json
import os
import queue
import socket
import struct
import termios
import threading
import time
import uuid
import zlib
from typing import Any
from urllib.parse import urlsplit

from cri_common import logger


STREAM_HOST = "127.0.0.1"
STREAM_PORT = 0
STREAM_TOKEN_TTL_SECONDS = 300
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
CHANNEL_PROTOCOLS = (
    "v5.channel.k8s.io",
    "v4.channel.k8s.io",
    "v3.channel.k8s.io",
    "v2.channel.k8s.io",
    "channel.k8s.io",
)
WEBSOCKET_PROTOCOLS = (
    "v5.channel.k8s.io",
    "v4.channel.k8s.io",
    "v3.channel.k8s.io",
    "v2.channel.k8s.io",
    "channel.k8s.io",
    "v4.base64.channel.k8s.io",
    "v3.base64.channel.k8s.io",
    "v2.base64.channel.k8s.io",
    "base64.channel.k8s.io",
)
STREAM_STDIN = 0
STREAM_STDOUT = 1
STREAM_STDERR = 2
STREAM_ERROR = 3
STREAM_RESIZE = 4
STREAM_CLOSE = 255
SPDY_UPGRADE = "SPDY/3.1"
SPDY_VERSION = 3
SPDY_TYPE_SYN_STREAM = 0x0001
SPDY_TYPE_SYN_REPLY = 0x0002
SPDY_TYPE_RST_STREAM = 0x0003
SPDY_TYPE_SETTINGS = 0x0004
SPDY_TYPE_PING = 0x0006
SPDY_TYPE_GOAWAY = 0x0007
SPDY_TYPE_HEADERS = 0x0008
SPDY_TYPE_WINDOW_UPDATE = 0x0009
SPDY_FLAG_FIN = 0x01
SPDY_STATUS_CANCEL = 5
SPDY_HEADER_DICTIONARY = base64.b64decode(
    b"AAAAB29wdGlvbnMAAAAEaGVhZAAAAARwb3N0AAAAA3B1dAAAAAZkZWxldGUAAAAFdHJhY2UAAAAG"
    b"YWNjZXB0AAAADmFjY2VwdC1jaGFyc2V0AAAAD2FjY2VwdC1lbmNvZGluZwAAAA9hY2NlcHQtbGFu"
    b"Z3VhZ2UAAAANYWNjZXB0LXJhbmdlcwAAAANhZ2UAAAAFYWxsb3cAAAANYXV0aG9yaXphdGlvbgAA"
    b"AA1jYWNoZS1jb250cm9sAAAACmNvbm5lY3Rpb24AAAAMY29udGVudC1iYXNlAAAAEGNvbnRlbnQt"
    b"ZW5jb2RpbmcAAAAQY29udGVudC1sYW5ndWFnZQAAAA5jb250ZW50LWxlbmd0aAAAABBjb250ZW50"
    b"LWxvY2F0aW9uAAAAC2NvbnRlbnQtbWQ1AAAADWNvbnRlbnQtcmFuZ2UAAAAMY29udGVudC10eXBl"
    b"AAAABGRhdGUAAAAEZXRhZwAAAAZleHBlY3QAAAAHZXhwaXJlcwAAAARmcm9tAAAABGhvc3QAAAAI"
    b"aWYtbWF0Y2gAAAARaWYtbW9kaWZpZWQtc2luY2UAAAANaWYtbm9uZS1tYXRjaAAAAAhpZi1yYW5n"
    b"ZQAAABNpZi11bm1vZGlmaWVkLXNpbmNlAAAADWxhc3QtbW9kaWZpZWQAAAAIbG9jYXRpb24AAAAM"
    b"bWF4LWZvcndhcmRzAAAABnByYWdtYQAAABJwcm94eS1hdXRoZW50aWNhdGUAAAATcHJveHktYXV0"
    b"aG9yaXphdGlvbgAAAAVyYW5nZQAAAAdyZWZlcmVyAAAAC3JldHJ5LWFmdGVyAAAABnNlcnZlcgAA"
    b"AAJ0ZQAAAAd0cmFpbGVyAAAAEXRyYW5zZmVyLWVuY29kaW5nAAAAB3VwZ3JhZGUAAAAKdXNlci1h"
    b"Z2VudAAAAAR2YXJ5AAAAA3ZpYQAAAAd3YXJuaW5nAAAAEHd3dy1hdXRoZW50aWNhdGUAAAAGbWV0"
    b"aG9kAAAAA2dldAAAAAZzdGF0dXMAAAAGMjAwIE9LAAAAB3ZlcnNpb24AAAAISFRUUC8xLjEAAAAD"
    b"dXJsAAAABnB1YmxpYwAAAApzZXQtY29va2llAAAACmtlZXAtYWxpdmUAAAAGb3JpZ2luMTAwMTAx"
    b"MjAxMjAyMjA1MjA2MzAwMzAyMzAzMzA0MzA1MzA2MzA3NDAyNDA1NDA2NDA3NDA4NDA5NDEwNDEx"
    b"NDEyNDEzNDE0NDE1NDE2NDE3NTAyNTA0NTA1MjAzIE5vbi1BdXRob3JpdGF0aXZlIEluZm9ybWF0"
    b"aW9uMjA0IE5vIENvbnRlbnQzMDEgTW92ZWQgUGVybWFuZW50bHk0MDAgQmFkIFJlcXVlc3Q0MDEg"
    b"VW5hdXRob3JpemVkNDAzIEZvcmJpZGRlbjQwNCBOb3QgRm91bmQ1MDAgSW50ZXJuYWwgU2VydmVy"
    b"IEVycm9yNTAxIE5vdCBJbXBsZW1lbnRlZDUwMyBTZXJ2aWNlIFVuYXZhaWxhYmxlSmFuIEZlYiBN"
    b"YXIgQXByIE1heSBKdW4gSnVsIEF1ZyBTZXB0IE9jdCBOb3YgRGVjIDAwOjAwOjAwIE1vbiwgVHVl"
    b"LCBXZWQsIFRodSwgRnJpLCBTYXQsIFN1biwgR01UY2h1bmtlZCx0ZXh0L2h0bWwsaW1hZ2UvcG5n"
    b"LGltYWdlL2pwZyxpbWFnZS9naWYsYXBwbGljYXRpb24veG1sLGFwcGxpY2F0aW9uL3hodG1sK3ht"
    b"bCx0ZXh0L3BsYWluLHRleHQvamF2YXNjcmlwdCxwdWJsaWNwcml2YXRlbWF4LWFnZT1nemlwLGRl"
    b"ZmxhdGUsc2RjaGNoYXJzZXQ9dXRmLThjaGFyc2V0PWlzby04ODU5LTEsdXRmLSwqLGVucT0wLg=="
)
class ExecStreamRequest:
    def __init__(
        self,
        *,
        container_id: str,
        cmd: list[str],
        tty: bool,
        stdin: bool,
        stdout: bool,
        stderr: bool,
        created_at: float,
    ):
        self.container_id = container_id
        self.cmd = cmd
        self.tty = tty
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.created_at = created_at


class RemoteCommandHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class WebSocketConnection:
    def __init__(self, sock: socket.socket, protocol: str):
        self.sock = sock
        self.protocol = protocol
        self.base64_channel = "base64" in protocol
        self.write_lock = threading.Lock()
        self.closed = False

    @classmethod
    def accept(cls, handler: http.server.BaseHTTPRequestHandler, protocol: str) -> "WebSocketConnection":
        key = handler.headers.get("Sec-WebSocket-Key")
        if not key:
            raise ValueError("missing Sec-WebSocket-Key")
        try:
            base64.b64decode(key.encode("ascii"), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("invalid Sec-WebSocket-Key") from exc

        accept = base64.b64encode(hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()).decode("ascii")
        headers = [
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Accept: {accept}",
        ]
        if protocol:
            headers.append(f"Sec-WebSocket-Protocol: {protocol}")
        handler.request.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        return cls(handler.request, protocol)

    def _recv_exact(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise EOFError("websocket closed")
            data.extend(chunk)
        return bytes(data)

    def _send_frame(self, opcode: int, payload: bytes = b"") -> None:
        if self.closed:
            return
        header = bytearray([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header.append(length)
        elif length <= 0xFFFF:
            header.extend([126])
            header.extend(struct.pack("!H", length))
        else:
            header.extend([127])
            header.extend(struct.pack("!Q", length))
        with self.write_lock:
            if self.closed:
                return
            self.sock.sendall(bytes(header) + payload)

    def read_channel_message(self) -> tuple[int, bytes]:
        while True:
            first, second = self._recv_exact(2)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._recv_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._recv_exact(8))[0]

            mask = self._recv_exact(4) if masked else b""
            payload = self._recv_exact(length) if length else b""
            if masked:
                payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))

            if opcode == 0x8:
                raise EOFError("websocket close frame")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode not in {0x1, 0x2}:
                continue

            if opcode == 0x1 or self.base64_channel:
                payload = base64.b64decode(payload)
            if not payload:
                continue
            return payload[0], payload[1:]

    def send_channel(self, channel: int, data: bytes = b"") -> None:
        payload = bytes([channel]) + data
        if self.base64_channel:
            self._send_frame(0x1, base64.b64encode(payload))
        else:
            self._send_frame(0x2, payload)

    def close(self) -> None:
        with self.write_lock:
            if self.closed:
                return
            self.closed = True
            try:
                payload = struct.pack("!H", 1000)
                header = bytes([0x88, len(payload)])
                self.sock.sendall(header + payload)
            except OSError:
                pass
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass


class SpdyRemoteCommandConnection:
    channel_to_stream_type = {
        STREAM_STDIN: "stdin",
        STREAM_STDOUT: "stdout",
        STREAM_STDERR: "stderr",
        STREAM_ERROR: "error",
        STREAM_RESIZE: "resize",
    }
    stream_type_to_channel = {
        "stdin": STREAM_STDIN,
        "stdout": STREAM_STDOUT,
        "stderr": STREAM_STDERR,
        "error": STREAM_ERROR,
        "resize": STREAM_RESIZE,
    }

    def __init__(self, sock: socket.socket, protocol: str):
        self.sock = sock
        self.protocol = protocol
        self.write_lock = threading.Lock()
        self.closed = False
        self.streams_by_id: dict[int, str] = {}
        self.streams_by_type: dict[str, int] = {}
        self.local_finished: set[int] = set()
        self.remote_finished: set[int] = set()
        self.incoming: queue.Queue[tuple[int, bytes]] = queue.Queue()
        self.streams_changed = threading.Condition()
        self.header_compressor = zlib.compressobj(
            level=zlib.Z_BEST_COMPRESSION,
            wbits=zlib.MAX_WBITS,
            zdict=SPDY_HEADER_DICTIONARY,
        )
        self.header_decompressor = zlib.decompressobj(
            wbits=zlib.MAX_WBITS,
            zdict=SPDY_HEADER_DICTIONARY,
        )
        self.reader = threading.Thread(target=self._read_loop, name="pnfroot-spdy", daemon=True)
        self.reader.start()

    @classmethod
    def accept(cls, handler: http.server.BaseHTTPRequestHandler, protocol: str) -> "SpdyRemoteCommandConnection":
        headers = [
            "HTTP/1.1 101 Switching Protocols",
            "Connection: Upgrade",
            f"Upgrade: {SPDY_UPGRADE}",
            f"X-Stream-Protocol-Version: {protocol}",
        ]
        handler.request.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        return cls(handler.request, protocol)

    def wait_for_streams(self, request: ExecStreamRequest, timeout: float = 30.0) -> None:
        expected = {"error"}
        if request.stdin:
            expected.add("stdin")
        if request.stdout:
            expected.add("stdout")
        if request.stderr and not request.tty:
            expected.add("stderr")
        deadline = time.monotonic() + timeout
        with self.streams_changed:
            while not expected.issubset(self.streams_by_type):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    missing = sorted(expected - set(self.streams_by_type))
                    raise TimeoutError(f"timed out waiting for SPDY streams: {', '.join(missing)}")
                self.streams_changed.wait(timeout=remaining)

    def _recv_exact(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise EOFError("spdy closed")
            data.extend(chunk)
        return bytes(data)

    def _read_loop(self) -> None:
        try:
            while not self.closed:
                self._read_frame()
        except (EOFError, OSError, zlib.error, struct.error):
            pass
        finally:
            self.closed = True
            self.incoming.put((STREAM_CLOSE, b""))
            with self.streams_changed:
                self.streams_changed.notify_all()

    def _read_frame(self) -> None:
        first_word = struct.unpack("!I", self._recv_exact(4))[0]
        flags_and_length = struct.unpack("!I", self._recv_exact(4))[0]
        flags = (flags_and_length >> 24) & 0xFF
        length = flags_and_length & 0xFFFFFF
        payload = self._recv_exact(length) if length else b""

        if first_word & 0x80000000:
            version = (first_word >> 16) & 0x7FFF
            frame_type = first_word & 0xFFFF
            if version != SPDY_VERSION:
                raise EOFError(f"unsupported SPDY version {version}")
            self._handle_control_frame(frame_type, flags, payload)
            return

        stream_id = first_word & 0x7FFFFFFF
        self._handle_data_frame(stream_id, flags, payload)

    def _handle_control_frame(self, frame_type: int, flags: int, payload: bytes) -> None:
        if frame_type == SPDY_TYPE_SYN_STREAM:
            self._handle_syn_stream(flags, payload)
        elif frame_type == SPDY_TYPE_RST_STREAM:
            if len(payload) >= 4:
                stream_id = struct.unpack("!I", payload[:4])[0] & 0x7FFFFFFF
                self._finish_remote_stream(stream_id)
        elif frame_type == SPDY_TYPE_PING:
            if len(payload) == 4:
                self._write_control_frame(SPDY_TYPE_PING, 0, payload)
        elif frame_type == SPDY_TYPE_GOAWAY:
            raise EOFError("spdy goaway")
        elif frame_type in {SPDY_TYPE_SETTINGS, SPDY_TYPE_HEADERS, SPDY_TYPE_WINDOW_UPDATE, SPDY_TYPE_SYN_REPLY}:
            return

    def _handle_syn_stream(self, flags: int, payload: bytes) -> None:
        if len(payload) < 10:
            return
        stream_id = struct.unpack("!I", payload[:4])[0] & 0x7FFFFFFF
        headers = self._parse_header_block(self.header_decompressor.decompress(payload[10:]))
        stream_type = headers.get("streamtype", [""])[0]
        if stream_type not in self.stream_type_to_channel:
            self._write_rst_stream(stream_id, SPDY_STATUS_CANCEL)
            return

        with self.streams_changed:
            self.streams_by_id[stream_id] = stream_type
            self.streams_by_type[stream_type] = stream_id
            if flags & SPDY_FLAG_FIN:
                self.remote_finished.add(stream_id)
            self.streams_changed.notify_all()
        self._write_syn_reply(stream_id)
        if flags & SPDY_FLAG_FIN:
            self._queue_remote_finish(stream_id)

    def _handle_data_frame(self, stream_id: int, flags: int, payload: bytes) -> None:
        stream_type = self.streams_by_id.get(stream_id)
        if stream_type is None:
            return
        channel = self.stream_type_to_channel[stream_type]
        if payload and channel in {STREAM_STDIN, STREAM_RESIZE}:
            self.incoming.put((channel, payload))
        if flags & SPDY_FLAG_FIN:
            self._finish_remote_stream(stream_id)

    def _finish_remote_stream(self, stream_id: int) -> None:
        if stream_id in self.remote_finished:
            return
        self.remote_finished.add(stream_id)
        self._queue_remote_finish(stream_id)

    def _queue_remote_finish(self, stream_id: int) -> None:
        stream_type = self.streams_by_id.get(stream_id)
        if stream_type == "stdin":
            self.incoming.put((STREAM_CLOSE, bytes([STREAM_STDIN])))

    def _parse_header_block(self, data: bytes) -> dict[str, list[str]]:
        offset = 0
        if len(data) < 4:
            return {}
        count = struct.unpack("!I", data[offset : offset + 4])[0]
        offset += 4
        headers: dict[str, list[str]] = {}
        for _ in range(count):
            if offset + 4 > len(data):
                break
            name_len = struct.unpack("!I", data[offset : offset + 4])[0]
            offset += 4
            name = data[offset : offset + name_len].decode("utf-8", "replace").lower()
            offset += name_len
            if offset + 4 > len(data):
                break
            value_len = struct.unpack("!I", data[offset : offset + 4])[0]
            offset += 4
            value = data[offset : offset + value_len].decode("utf-8", "replace")
            offset += value_len
            headers[name] = value.split("\x00") if value else [""]
        return headers

    def _header_block(self, headers: dict[str, list[str] | str]) -> bytes:
        raw = bytearray()
        raw.extend(struct.pack("!I", len(headers)))
        for name, values in headers.items():
            header_name = name.lower().encode("utf-8")
            if isinstance(values, str):
                header_value = values.encode("utf-8")
            else:
                header_value = "\x00".join(values).encode("utf-8")
            raw.extend(struct.pack("!I", len(header_name)))
            raw.extend(header_name)
            raw.extend(struct.pack("!I", len(header_value)))
            raw.extend(header_value)
        return self.header_compressor.compress(bytes(raw)) + self.header_compressor.flush(zlib.Z_SYNC_FLUSH)

    def _write_control_frame(self, frame_type: int, flags: int, payload: bytes) -> None:
        header = struct.pack(
            "!HHI",
            0x8000 | SPDY_VERSION,
            frame_type,
            ((flags & 0xFF) << 24) | (len(payload) & 0xFFFFFF),
        )
        with self.write_lock:
            if not self.closed:
                self.sock.sendall(header + payload)

    def _write_data_frame(self, stream_id: int, data: bytes = b"", fin: bool = False) -> None:
        if stream_id in self.local_finished:
            return
        flags = SPDY_FLAG_FIN if fin else 0
        header = struct.pack("!II", stream_id & 0x7FFFFFFF, (flags << 24) | (len(data) & 0xFFFFFF))
        with self.write_lock:
            if self.closed:
                return
            self.sock.sendall(header + data)
            if fin:
                self.local_finished.add(stream_id)

    def _write_syn_reply(self, stream_id: int) -> None:
        payload = struct.pack("!I", stream_id & 0x7FFFFFFF) + self._header_block({})
        self._write_control_frame(SPDY_TYPE_SYN_REPLY, 0, payload)

    def _write_rst_stream(self, stream_id: int, status: int) -> None:
        self._write_control_frame(SPDY_TYPE_RST_STREAM, 0, struct.pack("!II", stream_id & 0x7FFFFFFF, status))

    def read_channel_message(self) -> tuple[int, bytes]:
        channel, payload = self.incoming.get()
        if channel == STREAM_CLOSE and not payload:
            raise EOFError("spdy closed")
        return channel, payload

    def send_channel(self, channel: int, data: bytes = b"") -> None:
        stream_type = self.channel_to_stream_type.get(channel)
        if stream_type is None:
            return
        with self.streams_changed:
            stream_id = self.streams_by_type.get(stream_type)
        if stream_id is None:
            return
        if data:
            self._write_data_frame(stream_id, data)

    def close(self) -> None:
        already_closed = self.closed
        if not already_closed:
            for stream_id in list(self.streams_by_id):
                try:
                    self._write_data_frame(stream_id, fin=True)
                except OSError:
                    break
            try:
                last_stream_id = max(self.streams_by_id) if self.streams_by_id else 0
                self._write_control_frame(SPDY_TYPE_GOAWAY, 0, struct.pack("!II", last_stream_id, 0))
            except OSError:
                pass
        self.closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class RemoteCommandRequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.debug("stream %s - %s", self.address_string(), fmt % args)

    def do_GET(self) -> None:
        self._handle_request()

    def do_POST(self) -> None:
        self._handle_request()

    def _handle_request(self) -> None:
        manager: RemoteCommandServer = self.server.remote_command_server  # type: ignore[attr-defined]
        parsed = urlsplit(self.path)
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) != 2 or parts[0] != "exec":
            self.send_error(404, "not found")
            return

        request = manager.consume_exec(parts[1])
        if request is None:
            self.send_error(404, "exec request not found")
            return

        self.close_connection = True
        if self._is_websocket_request():
            protocol = manager.negotiate_websocket_protocol(self.headers.get("Sec-WebSocket-Protocol", ""))
            if protocol is None:
                self.send_error(400, "unsupported websocket protocol")
                return
            try:
                stream = WebSocketConnection.accept(self, protocol)
            except ValueError as exc:
                self.send_error(400, str(exc))
                return
            manager.serve_exec(request, stream)
            return

        if self._is_spdy_request():
            protocol = manager.negotiate_spdy_protocol(self.headers.get_all("X-Stream-Protocol-Version") or [])
            if protocol is None:
                self.send_error(400, "unsupported SPDY stream protocol")
                return
            stream = SpdyRemoteCommandConnection.accept(self, protocol)
            manager.serve_exec(request, stream)
            return

        self.send_error(426, "websocket or SPDY upgrade required")

    def _is_websocket_request(self) -> bool:
        connection = self.headers.get("Connection", "").lower()
        upgrade = self.headers.get("Upgrade", "").lower()
        return "upgrade" in connection and upgrade == "websocket"

    def _is_spdy_request(self) -> bool:
        connection = self.headers.get("Connection", "").lower()
        upgrade = self.headers.get("Upgrade", "").lower()
        return "upgrade" in connection and upgrade == SPDY_UPGRADE.lower()


class RemoteCommandServer:
    def __init__(
        self,
        runtime: "RuntimeService",
        host: str = STREAM_HOST,
        port: int = STREAM_PORT,
        public_host: str | None = None,
        token_ttl_seconds: int = STREAM_TOKEN_TTL_SECONDS,
    ):
        self.runtime = runtime
        self.host = host
        self.port = port
        self.public_host = public_host
        self.token_ttl_seconds = token_ttl_seconds
        self._lock = threading.Lock()
        self._requests: dict[str, ExecStreamRequest] = {}
        self._server: RemoteCommandHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.start()

    @property
    def base_url(self) -> str:
        if self._server is None:
            self.start()
        assert self._server is not None
        host = self.public_host or self.host
        if host in {"", "0.0.0.0"}:
            host = "127.0.0.1"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"http://{host}:{self._server.server_address[1]}"

    def start(self) -> None:
        if self._server is not None:
            return
        self._server = RemoteCommandHTTPServer((self.host, self.port), RemoteCommandRequestHandler)
        self._server.remote_command_server = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, name="pnfroot-streaming", daemon=True)
        self._thread.start()
        logger.info("CRI streaming server started on %s", self.base_url)

    def shutdown(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None

    def build_exec_url(self, request: ExecStreamRequest) -> str:
        token = uuid.uuid4().hex
        with self._lock:
            self._drop_expired_locked()
            self._requests[token] = request
        return f"{self.base_url}/exec/{token}"

    def consume_exec(self, token: str) -> ExecStreamRequest | None:
        with self._lock:
            request = self._requests.pop(token, None)
            if request is None:
                return None
            if time.time() - request.created_at > self.token_ttl_seconds:
                return None
            return request

    def _drop_expired_locked(self) -> None:
        now = time.time()
        expired = [
            token
            for token, request in self._requests.items()
            if now - request.created_at > self.token_ttl_seconds
        ]
        for token in expired:
            self._requests.pop(token, None)

    def negotiate_websocket_protocol(self, offered_header: str) -> str | None:
        if not offered_header:
            return "channel.k8s.io"
        offered = [item.strip() for item in offered_header.split(",") if item.strip()]
        for protocol in offered:
            if protocol in WEBSOCKET_PROTOCOLS:
                return protocol
        return None

    def negotiate_spdy_protocol(self, offered_headers: list[str]) -> str | None:
        if not offered_headers:
            return "channel.k8s.io"
        offered: list[str] = []
        for header in offered_headers:
            offered.extend(item.strip() for item in header.split(",") if item.strip())
        for protocol in offered:
            if protocol in CHANNEL_PROTOCOLS:
                return protocol
        return None

    def serve_exec(self, request: ExecStreamRequest, stream: Any) -> None:
        stop_event = threading.Event()
        process: Any = None
        pty_master: int | None = None
        stdin_closed = threading.Event()

        def send_status(exit_code: int, message: str | None = None) -> None:
            if stream.protocol in {"v4.channel.k8s.io", "v5.channel.k8s.io", "v4.base64.channel.k8s.io"}:
                if exit_code == 0 and message is None:
                    status = {"status": "Success"}
                elif message is None:
                    status = {
                        "status": "Failure",
                        "reason": "NonZeroExitCode",
                        "message": f"command terminated with non-zero exit code: {exit_code}",
                        "details": {
                            "causes": [
                                {
                                    "reason": "ExitCode",
                                    "message": str(exit_code),
                                }
                            ]
                        },
                    }
                else:
                    status = {
                        "status": "Failure",
                        "reason": "InternalError",
                        "message": f"Internal error occurred: {message}",
                        "code": 500,
                    }
                stream.send_channel(STREAM_ERROR, json.dumps(status, separators=(",", ":")).encode("utf-8"))
            elif exit_code != 0 or message is not None:
                stream.send_channel(STREAM_ERROR, (message or f"command exited with {exit_code}").encode("utf-8"))

        def close_stdin() -> None:
            if stdin_closed.is_set():
                return
            stdin_closed.set()
            if process is not None and process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass

        def pipe_to_channel(pipe: Any, channel: int) -> None:
            try:
                while not stop_event.is_set():
                    data = pipe.read(32768)
                    if not data:
                        break
                    stream.send_channel(channel, data)
            except OSError:
                pass
            finally:
                try:
                    pipe.close()
                except OSError:
                    pass

        def pty_to_stdout(fd: int) -> None:
            try:
                while not stop_event.is_set():
                    try:
                        data = os.read(fd, 32768)
                    except OSError:
                        break
                    if not data:
                        break
                    stream.send_channel(STREAM_STDOUT, data)
            finally:
                try:
                    os.close(fd)
                except OSError:
                    pass

        def apply_resize(payload: bytes) -> None:
            if pty_master is None:
                return
            try:
                size = json.loads(payload.decode("utf-8"))
                width = int(size.get("Width", size.get("width", 0)))
                height = int(size.get("Height", size.get("height", 0)))
                if width > 0 and height > 0:
                    fcntl.ioctl(pty_master, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))
            except (OSError, ValueError, json.JSONDecodeError):
                pass

        def receive_loop() -> None:
            try:
                while not stop_event.is_set():
                    channel, payload = stream.read_channel_message()
                    if channel == STREAM_STDIN and request.stdin:
                        if request.tty and pty_master is not None:
                            os.write(pty_master, payload)
                        elif process is not None and process.stdin is not None and not stdin_closed.is_set():
                            process.stdin.write(payload)
                            process.stdin.flush()
                    elif channel == STREAM_RESIZE:
                        apply_resize(payload)
                    elif channel == STREAM_CLOSE:
                        if payload and payload[0] == STREAM_STDIN:
                            close_stdin()
            except (EOFError, OSError, BrokenPipeError):
                close_stdin()
                if not stop_event.is_set() and process is not None and process.poll() is None:
                    process.terminate()

        output_threads: list[threading.Thread] = []
        receiver: threading.Thread | None = None
        try:
            container = self.runtime.find_container(request.container_id)
            if container is None:
                send_status(1, "container not found")
                return

            if isinstance(stream, SpdyRemoteCommandConnection):
                stream.wait_for_streams(request)

            process, pty_master = self.runtime.start_exec_process(
                container,
                request.cmd,
                tty=request.tty,
                stdin=request.stdin,
                stdout=request.stdout,
                stderr=request.stderr,
            )

            if request.stdout:
                stream.send_channel(STREAM_STDOUT, b"")
            elif request.stderr:
                stream.send_channel(STREAM_STDERR, b"")
            else:
                stream.send_channel(STREAM_ERROR, b"")

            if request.tty and pty_master is not None:
                output_threads.append(threading.Thread(target=pty_to_stdout, args=(pty_master,), daemon=True))
            else:
                if request.stdout and process.stdout is not None:
                    output_threads.append(threading.Thread(target=pipe_to_channel, args=(process.stdout, STREAM_STDOUT), daemon=True))
                if request.stderr and process.stderr is not None:
                    output_threads.append(threading.Thread(target=pipe_to_channel, args=(process.stderr, STREAM_STDERR), daemon=True))

            for thread in output_threads:
                thread.start()

            receiver = threading.Thread(target=receive_loop, daemon=True)
            receiver.start()
            exit_code = process.wait()
            close_stdin()
            for thread in output_threads:
                thread.join(timeout=2)
            send_status(exit_code)
        except Exception as exc:
            logger.exception("Exec stream failed")
            send_status(1, str(exc))
            if process is not None and process.poll() is None:
                process.kill()
        finally:
            stop_event.set()
            stream.close()
            if receiver is not None:
                receiver.join(timeout=1)


