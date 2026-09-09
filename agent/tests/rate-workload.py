#!/usr/bin/env python3
"""Emit a short burst of UDP sends after the sensor has attached."""

import socket
import time


time.sleep(1.5)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(100):
    sock.sendto(b"rate", ("127.0.0.1", 9))
sock.close()
