#!/usr/bin/env python3
"""Small schema-v1 fork/exec fixture regression; no build or live collector."""

import io
from pathlib import Path
import runpy
import struct


decoder = runpy.run_path(str(Path(__file__).resolve().parents[1] / "tools/decode-events.py"))
common, process, fork, frame = (decoder[name] for name in ("COMMON", "PROCESS", "FORK", "FRAME"))
assert common.size == 88 and process.size == 272 and fork.size == 24
assert common.size + process.size == 360 and decoder["MAX_EVENT_SIZE"] == 376
assert common.size + struct.calcsize("<IIiI") == 104  # EXEC filename unchanged.


def header(event_type, flags):
    return common.pack(100, 200, 300, 11, 10, 11, 10, 1, 0, 0, 0,
                       0, 376, flags, 1, event_type, b"fixture")


token = (1 << 40) + 123  # Preserve all 64 bits; child TID and TGID can differ.
body = fork.pack(11, 12, 0, 10, token) + bytes(288 - fork.size)
valid = header(1, decoder["FORK_CHILD_ID_VALID"]) + body
unknown = header(1, 0) + body  # Nonzero bytes without the flag remain unknown.
filename = b"/usr/bin/fixture"
execute = header(2, decoder["FORK_CHILD_ID_VALID"]) + process.pack(1, 12, 0, 0, filename) + bytes(16)
stream = io.BytesIO(b"".join(frame.pack(b"EBPF", 1, 1, 0, len(payload)) + payload
                             for payload in (valid, unknown, execute)))
typed, legacy, executed = list(decoder["frames"](stream))
assert typed["parent_pid"] == legacy["parent_pid"] == 11
assert typed["child_pid"] == legacy["child_pid"] == 12
assert typed["child_tgid"] == 10 and typed["child_task_start_ns"] == token
assert legacy["child_tgid"] is None and legacy["child_task_start_ns"] is None
assert struct.unpack_from("<I", valid, 96)[0] == 0
assert struct.unpack_from("<I", valid, 100)[0] == 10
assert struct.unpack_from("<Q", valid, 104)[0] == token
assert executed["filename"] == filename.decode() and "child_tgid" not in executed
print("fork identity fixtures passed (valid, unknown, 64-bit token, thread TGID, exec ABI)")
