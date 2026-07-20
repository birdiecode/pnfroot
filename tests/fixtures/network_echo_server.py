from __future__ import annotations

import socket


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("10.50.0.20", 8080))
        listener.listen(1)
        connection, _ = listener.accept()
        with connection:
            data = connection.recv(1024)
            connection.sendall(b"echo:" + data)


if __name__ == "__main__":
    main()

