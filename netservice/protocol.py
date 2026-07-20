"""JSON-lines protocol helpers for the virtual network service."""

from __future__ import annotations

import json
from typing import BinaryIO


PROTOCOL_VERSION = 1
MAX_MESSAGE_SIZE = 1024 * 1024


class ProtocolError(RuntimeError):
    pass


def encode_message(message: dict[str, object]) -> bytes:
    if message.get("version") is None:
        message = {"version": PROTOCOL_VERSION, **message}
    payload = json.dumps(message, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    if len(payload) > MAX_MESSAGE_SIZE:
        raise ProtocolError("message is too large")
    return payload + b"\n"


def decode_message(line: bytes) -> dict[str, object]:
    if len(line) > MAX_MESSAGE_SIZE:
        raise ProtocolError("message is too large")
    try:
        message = json.loads(line.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ProtocolError("invalid JSON") from exc
    if not isinstance(message, dict):
        raise ProtocolError("message must be a JSON object")
    if message.get("version") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")
    return message


def read_message(reader: BinaryIO) -> dict[str, object] | None:
    line = reader.readline(MAX_MESSAGE_SIZE + 1)
    if not line:
        return None
    if not line.endswith(b"\n"):
        raise ProtocolError("message is not newline terminated")
    return decode_message(line[:-1])


def write_message(writer: BinaryIO, message: dict[str, object]) -> None:
    writer.write(encode_message(message))
    writer.flush()

