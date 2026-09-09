#!/usr/bin/env python3
"""Create concurrent TCP connect/accept pairs in one process."""

import socket
import threading
import time


WORKERS = 8
CONNECTIONS_PER_WORKER = 50
TOTAL = WORKERS * CONNECTIONS_PER_WORKER

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen(512)
address = listener.getsockname()
time.sleep(1.5)

errors: list[BaseException] = []


def accept_all() -> None:
    try:
        for _ in range(TOTAL):
            connection, _ = listener.accept()
            connection.close()
    except BaseException as error:  # Preserve worker failures for the main thread.
        errors.append(error)


def connect_many() -> None:
    try:
        for _ in range(CONNECTIONS_PER_WORKER):
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(address)
            client.close()
    except BaseException as error:
        errors.append(error)


accept_thread = threading.Thread(target=accept_all)
accept_thread.start()
workers = [threading.Thread(target=connect_many) for _ in range(WORKERS)]
for worker in workers:
    worker.start()
for worker in workers:
    worker.join()
accept_thread.join()
listener.close()

if errors:
    raise errors[0]
