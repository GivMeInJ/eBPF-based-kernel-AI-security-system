#!/usr/bin/env python3
"""Generate deterministic TCP and UDP activity for the network sensor."""

import socket
import threading


def tcp_round_trip(family: int, host: str) -> None:
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, 0))
    listener.listen(4)

    def accept_once() -> None:
        connection, _ = listener.accept()
        connection.close()

    accept_thread = threading.Thread(target=accept_once)
    accept_thread.start()
    client = socket.socket(family, socket.SOCK_STREAM)
    client.connect(listener.getsockname())
    client.close()
    accept_thread.join()
    listener.close()


tcp_round_trip(socket.AF_INET, "127.0.0.1")
if socket.has_ipv6:
    try:
        tcp_round_trip(socket.AF_INET6, "::1")
    except OSError:
        pass

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.sendto(b"sendto", ("127.0.0.1", 9))
if hasattr(udp, "sendmsg"):
    udp.sendmsg([b"send", b"msg"], [], 0, ("127.0.0.1", 9))
udp.close()
