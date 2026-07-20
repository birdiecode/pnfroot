from __future__ import annotations

import socket
import sys


def main() -> None:
    with socket.create_connection(("10.50.0.20", 8080), timeout=5) as connection:
        connection.sendall(b"ping")
        sys.stdout.buffer.write(connection.recv(1024))
        sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()
