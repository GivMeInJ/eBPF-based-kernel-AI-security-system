#!/usr/bin/env python3
"""Convert binary collector output to normalized syscall-histogram traces."""
import argparse
import json
import struct
from collections import Counter, defaultdict
from pathlib import Path

FRAME = struct.Struct("<4sBBHI")
COMMON = struct.Struct("<QQQ8IiIIHH16s")
SYSCALL = struct.Struct("<IIq")
HEALTH = struct.Struct("<QQQQQ")
SYSCALL_ENTER, HEALTH_EVENT = 4, 14


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--map", required=True, type=Path)
    parser.add_argument("--window", type=int, default=500)
    parser.add_argument("--min-len", type=int, default=50)
    parser.add_argument("--max-per-comm", type=int, default=400)
    args = parser.parse_args()

    number_map = {int(k): v for k, v in json.loads(args.map.read_text())["nr_to_feature_id"].items()}
    args.output.mkdir(parents=True, exist_ok=True)
    pending, comms, emitted, health = defaultdict(list), {}, Counter(), Counter()
    written = 0

    def flush(key):
        nonlocal written
        values, comm = pending[key], comms[key]
        if len(values) < args.min_len or emitted[comm] >= args.max_per_comm:
            return
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in comm)
        (args.output / f"normal-{safe}-{key[0]}-{key[1]}-{written:07d}.txt").write_text(" ".join(map(str, values)) + "\n")
        emitted[comm] += 1
        written += 1

    with args.input.open("rb") as stream:
        while header := stream.read(FRAME.size):
            if len(header) != FRAME.size:
                raise ValueError("truncated frame header")
            magic, wire, little, reserved, size = FRAME.unpack(header)
            if (magic, wire, little, reserved) != (b"EBPF", 1, 1, 0):
                raise ValueError("invalid binary frame")
            payload = stream.read(size)
            if len(payload) != size:
                raise ValueError("truncated frame payload")
            fields = COMMON.unpack_from(payload)
            if fields[15] == HEALTH_EVENT:
                health.update(dict(zip(("writer_queue_dropped", "writer_priority_dropped", "kernel_ringbuf_lost", "network_filtered", "network_rate_limited"), HEALTH.unpack_from(payload, COMMON.size))))
                continue
            if fields[15] != SYSCALL_ENTER:
                continue
            feature_id = number_map.get(SYSCALL.unpack_from(payload, COMMON.size)[0])
            if feature_id is None:
                continue
            key = (fields[4], fields[2])
            if key not in comms:
                comms[key] = fields[16].split(b"\0", 1)[0].decode("utf-8", "replace") or "unknown"
            pending[key].append(feature_id)
            if len(pending[key]) == args.window:
                flush(key)
                pending[key].clear()

    for key in pending:
        flush(key)
    if sum(health[k] for k in ("writer_queue_dropped", "writer_priority_dropped", "kernel_ringbuf_lost")):
        raise SystemExit(f"refusing lossy capture: {dict(health)}")
    print(f"wrote {written} traces from {len(comms)} process instances")


if __name__ == "__main__":
    main()
