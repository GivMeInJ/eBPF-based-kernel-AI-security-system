#!/usr/bin/env python3
"""Open a FIFO, pause consumption, then drain it to simulate backpressure."""

import sys
import time


output = open(sys.argv[2], "wb") if len(sys.argv) > 2 else None
try:
    with open(sys.argv[1], "rb", buffering=0) as stream:
        time.sleep(2.5)
        while chunk := stream.read(65536):
            if output:
                output.write(chunk)
finally:
    if output:
        output.close()
