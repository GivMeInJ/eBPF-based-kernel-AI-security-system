#!/usr/bin/env python3
"""Decode length-prefixed ebpf-agent binary frames into NDJSON."""

import argparse
import ipaddress
import json
import struct


FRAME = struct.Struct("<4sBBHI")
COMMON = struct.Struct("<QQQ8IiIIHH16s")
PROCESS = struct.Struct("<IIiI256s")
SYSCALL = struct.Struct("<IIq")
FILE = struct.Struct("<QQIIII256s")
NETWORK = struct.Struct("<QQQQqQIiIIHHHHHHB3x16s16s")
HEALTH = struct.Struct("<QQQQQ")

SCHEMA_VERSION = 1
MAX_EVENT_SIZE = 376

EVENT_NAMES = {
    1: "PROCESS_FORK",
    2: "PROCESS_EXEC",
    3: "PROCESS_EXIT",
    4: "SYSCALL_ENTER",
    5: "SYSCALL_EXIT",
    6: "FILE_OPEN",
    7: "FILE_UNLINK",
    8: "NETWORK_CONNECT",
    9: "NETWORK_BIND",
    10: "NETWORK_LISTEN",
    11: "NETWORK_ACCEPT",
    12: "NETWORK_UDP_SEND",
    13: "NETWORK_TCP_STATE",
    14: "HEALTH",
}

EVENT_SIZES = {
    **{event_type: 376 for event_type in range(1, 8)},
    **{event_type: 200 for event_type in range(8, 14)},
    14: 128,
}

DEST_VALID = 1 << 4
SOURCE_VALID = 1 << 5


class UnsupportedEvent(ValueError):
    """A well-framed event that this schema version does not understand."""


def c_string(value: bytes) -> str:
    return value.split(b"\0", 1)[0].decode("utf-8", errors="backslashreplace")


def ip_string(family: int, value: bytes, valid: bool):
    if not valid:
        return None
    size = 4 if family == 2 else 16 if family == 10 else 0
    return str(ipaddress.ip_address(value[:size])) if size else None


def decode_event(payload: bytes) -> dict:
    if len(payload) < COMMON.size:
        raise ValueError("short event payload")
    values = COMMON.unpack_from(payload)
    event_type = values[15]
    expected_size = EVENT_SIZES.get(event_type)
    if values[14] != SCHEMA_VERSION:
        raise UnsupportedEvent(f"unsupported schema version: {values[14]}")
    if expected_size is None:
        raise UnsupportedEvent(f"unknown event type: {event_type}")
    if values[12] != len(payload):
        raise ValueError("event size does not match frame payload")
    if len(payload) != expected_size:
        raise ValueError(
            f"invalid payload size for {EVENT_NAMES[event_type]}: {len(payload)}"
        )
    event = {
        "timestamp_ns": values[0],
        "cgroup_id": values[1],
        "task_start_ns": values[2],
        "pid": values[3],
        "tgid": values[4],
        "namespace_pid": values[5],
        "namespace_tgid": values[6],
        "ppid": values[7],
        "uid": values[8],
        "gid": values[9],
        "cpu": values[10],
        "result": values[11],
        "size": values[12],
        "flags": values[13],
        "schema_version": values[14],
        "event_type": EVENT_NAMES.get(values[15], f"UNKNOWN_{values[15]}"),
        "comm": c_string(values[16]),
    }
    flags = event["flags"]
    offset = COMMON.size

    if event_type in (1, 2, 3):
        parent, child, exit_code, _, filename = PROCESS.unpack_from(payload, offset)
        event.update(parent_pid=parent, child_pid=child)
        if event_type == 2:
            event["filename"] = c_string(filename)
        elif event_type == 3:
            event["exit_code_raw"] = exit_code
    elif event_type in (4, 5):
        syscall_id, _, return_value = SYSCALL.unpack_from(payload, offset)
        event["syscall_id"] = syscall_id
        if event_type == 5:
            event["return_value"] = return_value
    elif event_type in (6, 7):
        inode, directory_inode, device, open_flags, mode, operation, path = (
            FILE.unpack_from(payload, offset)
        )
        event.update(
            inode=inode,
            directory_inode=directory_inode,
            device=device,
            open_flags=open_flags,
            mode=mode,
            operation=operation,
            path=c_string(path),
        )
    elif 8 <= event_type <= 13:
        network = NETWORK.unpack_from(payload, offset)
        event.update(
            duration_ns=network[0],
            netns_id=network[1],
            netns_cookie=network[2],
            socket_cookie=network[3],
            retval=network[4],
            bytes_requested=network[5],
            sockfd=network[6],
            backlog=network[7],
            src_scope_id=network[8],
            dst_scope_id=network[9],
            family=network[10],
            socket_type=network[11],
            src_port=network[12],
            dst_port=network[13],
            old_state=network[14],
            new_state=network[15],
            protocol=network[16],
            src_ip=ip_string(network[10], network[17], bool(flags & SOURCE_VALID)),
            dst_ip=ip_string(network[10], network[18], bool(flags & DEST_VALID)),
        )
    elif event_type == 14:
        health = HEALTH.unpack_from(payload, offset)
        event.update(
            writer_queue_dropped=health[0],
            writer_priority_dropped=health[1],
            kernel_ringbuf_lost=health[2],
            network_filtered=health[3],
            network_rate_limited=health[4],
        )
    return event


def frames(stream):
    while True:
        header = stream.read(FRAME.size)
        if not header:
            return
        if len(header) != FRAME.size:
            raise ValueError("truncated frame header")
        magic, wire_version, little_endian, reserved, payload_size = FRAME.unpack(header)
        if magic != b"EBPF" or wire_version != 1 or little_endian != 1:
            raise ValueError("unsupported binary frame")
        if reserved != 0:
            raise ValueError("non-zero reserved frame field")
        if payload_size < COMMON.size or payload_size > MAX_EVENT_SIZE:
            raise ValueError(f"invalid frame payload size: {payload_size}")
        payload = stream.read(payload_size)
        if len(payload) != payload_size:
            raise ValueError("truncated frame payload")
        try:
            event = decode_event(payload)
        except UnsupportedEvent:
            continue
        yield event


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("--count", action="store_true")
    parser.add_argument("--event-type")
    arguments = parser.parse_args()

    with open(arguments.input, "rb") as stream:
        decoded = frames(stream)
        if arguments.event_type:
            decoded = (
                event
                for event in decoded
                if event.get("event_type") == arguments.event_type
            )
        if arguments.count:
            print(sum(1 for _ in decoded))
        else:
            for event in decoded:
                print(json.dumps(event, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
