#!/usr/bin/env python3
"""Audit recorded network metadata without printing endpoints or file contents."""
import argparse
from collections import Counter
import json
import struct

FRAME = struct.Struct('<4sBBHI')
U16, U32, S32, U64 = (struct.Struct(s) for s in ('<H', '<I', '<i', '<Q'))


def audit(path, timeline):
    intervals = [line.split() for line in open(timeline)]
    counts = Counter()
    incomplete = []
    buf = b''
    with open(path, 'rb') as stream:
        while chunk := stream.read(4 << 20):
            buf += chunk
            off = 0
            while off + FRAME.size <= len(buf):
                magic, wire, little, res, size = FRAME.unpack_from(buf, off)
                if (magic, wire, little, res) != (b'EBPF', 1, 1, 0) or not 88 <= size <= 376:
                    raise ValueError('invalid frame')
                p = off + FRAME.size
                if p + size > len(buf):
                    break
                kind = U16.unpack_from(buf, p + 70)[0]
                if 8 <= kind <= 13:
                    if size < 200:
                        raise ValueError('short network frame')
                    counts[kind] += 1
                    flags = U32.unpack_from(buf, p + 64)[0]
                    if not flags & 64:
                        ts = U64.unpack_from(buf, p)[0]
                        incomplete.append({
                            'type': kind, 'timestamp_ns': ts, 'flags': flags,
                            'result': S32.unpack_from(buf, p + 56)[0],
                            'family': U16.unpack_from(buf, p + 152)[0],
                            'unit': next((t[3] for t in intervals
                                          if int(t[0]) <= ts <= int(t[1])), None),
                        })
                off = p + size
            buf = buf[off:]
    if buf:
        raise ValueError('incomplete final frame')
    return {'network_counts': dict(counts), 'incomplete_socket_metadata': incomplete}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture')
    parser.add_argument('timeline')
    args = parser.parse_args()
    print(json.dumps(audit(args.capture, args.timeline)))
