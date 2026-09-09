#!/usr/bin/env python3
"""Generate deterministic, sanitized schema-v1 AI handoff sample frames."""

from __future__ import annotations

import argparse
import ipaddress
import json
import struct
from pathlib import Path


FRAME = struct.Struct("<4sBBHI")
COMMON = struct.Struct("<QQQ8IiIIHH16s")
PROCESS = struct.Struct("<IIiI256s")
SYSCALL = struct.Struct("<IIq")
FILE = struct.Struct("<QQIIII256s")
NETWORK = struct.Struct("<QQQQqQIiIIHHHHHHB3x16s16s")
HEALTH = struct.Struct("<QQQQQ")

SCHEMA_VERSION = 1
WIRE_VERSION = 1
HOST_EVENT_SIZE = 376
NETWORK_EVENT_SIZE = 200
HEALTH_EVENT_SIZE = 128

PATH_UNAVAILABLE = 1 << 0
PATH_TRUNCATED = 1 << 1
PARTIAL_PATH = 1 << 2
MISSING_ENTRY = 1 << 3
DEST_VALID = 1 << 4
SOURCE_VALID = 1 << 5
SOCKET_VALID = 1 << 6
COOKIE_VALID = 1 << 7
NETNS_COOKIE_VALID = 1 << 8
PROCESS_UNCERTAIN = 1 << 9
USERSPACE_GENERATED = 1 << 10

PROCESS_FORK = 1
PROCESS_EXEC = 2
PROCESS_EXIT = 3
SYSCALL_ENTER = 4
SYSCALL_EXIT = 5
FILE_OPEN = 6
FILE_UNLINK = 7
NETWORK_CONNECT = 8
NETWORK_BIND = 9
NETWORK_LISTEN = 10
NETWORK_ACCEPT = 11
NETWORK_UDP_SEND = 12
NETWORK_TCP_STATE = 13
HEALTH_EVENT = 14


def fixed_bytes(value: str, size: int) -> bytes:
    encoded = value.encode("utf-8")
    if len(encoded) >= size:
        encoded = encoded[: size - 1]
    return encoded + bytes(size - len(encoded))


def address(value: str) -> tuple[int, bytes]:
    parsed = ipaddress.ip_address(value)
    family = 2 if parsed.version == 4 else 10
    return family, parsed.packed + bytes(16 - len(parsed.packed))


def task_start(pid: int) -> int:
    return 0 if pid == 0 else 9_000_000_000 + pid * 1_000


def common(
    *,
    timestamp_ns: int,
    event_type: int,
    size: int,
    pid: int,
    ppid: int,
    uid: int,
    cgroup_id: int,
    task_start_ns: int,
    result: int = 0,
    flags: int = 0,
    comm: str,
) -> bytes:
    return COMMON.pack(
        timestamp_ns,
        cgroup_id,
        task_start_ns,
        pid,
        pid,
        pid,
        pid,
        ppid,
        uid,
        uid,
        2,
        result,
        size,
        flags,
        SCHEMA_VERSION,
        event_type,
        fixed_bytes(comm, 16),
    )


def host_record(header: bytes, payload: bytes) -> bytes:
    record = header + payload
    if len(record) > HOST_EVENT_SIZE:
        raise ValueError("host event exceeds schema-v1 size")
    return record + bytes(HOST_EVENT_SIZE - len(record))


def process_record(
    event_type: int,
    timestamp_ns: int,
    pid: int,
    ppid: int,
    comm: str,
    filename: str = "",
    exit_code: int = 0,
    parent_pid: int | None = None,
    child_pid: int | None = None,
) -> bytes:
    header = common(
        timestamp_ns=timestamp_ns,
        event_type=event_type,
        size=HOST_EVENT_SIZE,
        pid=pid,
        ppid=ppid,
        uid=1000,
        cgroup_id=4242,
        task_start_ns=task_start(pid),
        result=exit_code if event_type == PROCESS_EXIT else 0,
        comm=comm,
    )
    payload = PROCESS.pack(
        (pid if event_type == PROCESS_FORK else ppid)
        if parent_pid is None
        else parent_pid,
        pid if child_pid is None else child_pid,
        exit_code,
        0,
        fixed_bytes(filename, 256),
    )
    return host_record(header, payload)


def syscall_record(
    event_type: int,
    timestamp_ns: int,
    pid: int,
    ppid: int,
    syscall_id: int,
    return_value: int,
) -> bytes:
    header = common(
        timestamp_ns=timestamp_ns,
        event_type=event_type,
        size=HOST_EVENT_SIZE,
        pid=pid,
        ppid=ppid,
        uid=1000,
        cgroup_id=4242,
        task_start_ns=task_start(pid),
        result=return_value,
        comm="curl",
    )
    return host_record(header, SYSCALL.pack(syscall_id, 0, return_value))


def file_record(
    event_type: int,
    timestamp_ns: int,
    pid: int,
    ppid: int,
    comm: str,
    path: str,
    *,
    inode: int,
    directory_inode: int = 0,
    operation: int,
    flags: int = 0,
) -> bytes:
    header = common(
        timestamp_ns=timestamp_ns,
        event_type=event_type,
        size=HOST_EVENT_SIZE,
        pid=pid,
        ppid=ppid,
        uid=1000,
        cgroup_id=4242,
        task_start_ns=task_start(pid),
        flags=flags,
        comm=comm,
    )
    payload = FILE.pack(
        inode,
        directory_inode,
        2049,
        0,
        0,
        operation,
        fixed_bytes(path, 256),
    )
    return host_record(header, payload)


def network_record(
    event_type: int,
    timestamp_ns: int,
    pid: int,
    ppid: int,
    comm: str,
    source_ip: str,
    source_port: int,
    destination_ip: str,
    destination_port: int,
    *,
    protocol: int,
    return_value: int = 0,
    socket_type: int = 1,
    bytes_requested: int = 0,
    backlog: int = 0,
    old_state: int = 0,
    new_state: int = 0,
    process_uncertain: bool = False,
    source_valid: bool = True,
    destination_valid: bool = True,
    socket_cookie: int | None = None,
) -> bytes:
    family, source = address(source_ip)
    destination_family, destination = address(destination_ip)
    if family != destination_family:
        raise ValueError("sample endpoints must use the same address family")
    flags = SOCKET_VALID | COOKIE_VALID | NETNS_COOKIE_VALID
    if source_valid:
        flags |= SOURCE_VALID
    if destination_valid:
        flags |= DEST_VALID
    if process_uncertain:
        flags |= PROCESS_UNCERTAIN
    header = common(
        timestamp_ns=timestamp_ns,
        event_type=event_type,
        size=NETWORK_EVENT_SIZE,
        pid=pid,
        ppid=ppid,
        uid=1000,
        cgroup_id=4242,
        task_start_ns=task_start(pid),
        result=return_value,
        flags=flags,
        comm=comm,
    )
    payload = NETWORK.pack(
        120_000,
        4026531993,
        9001,
        7000 + pid if socket_cookie is None else socket_cookie,
        return_value,
        bytes_requested,
        5,
        backlog,
        0,
        0,
        family,
        socket_type,
        source_port,
        destination_port,
        old_state,
        new_state,
        protocol,
        source,
        destination,
    )
    record = header + payload
    if len(record) != NETWORK_EVENT_SIZE:
        raise ValueError("invalid generated network record size")
    return record


def health_record(
    timestamp_ns: int,
    queue_dropped: int,
    priority_dropped: int,
    ringbuf_lost: int,
    filtered: int,
    rate_limited: int,
) -> bytes:
    header = common(
        timestamp_ns=timestamp_ns,
        event_type=HEALTH_EVENT,
        size=HEALTH_EVENT_SIZE,
        pid=9000,
        ppid=1,
        uid=65534,
        cgroup_id=0,
        task_start_ns=task_start(9000),
        flags=USERSPACE_GENERATED,
        comm="ebpf-agent",
    )
    record = header + HEALTH.pack(
        queue_dropped,
        priority_dropped,
        ringbuf_lost,
        filtered,
        rate_limited,
    )
    if len(record) != HEALTH_EVENT_SIZE:
        raise ValueError("invalid generated health record size")
    return record


def build_samples() -> tuple[list[tuple[str, bytes]], list[dict[str, object]]]:
    base = 10_000_000_000
    events: list[tuple[str, bytes]] = []

    def add(scenario: str, record: bytes) -> None:
        events.append((scenario, record))

    add(
        "normal_web_service",
        process_record(PROCESS_FORK, base + 1, 1100, 1, "systemd", child_pid=1101),
    )
    add(
        "normal_web_service",
        process_record(PROCESS_EXEC, base + 2, 1101, 1, "nginx", "/usr/sbin/nginx"),
    )
    add(
        "normal_web_service",
        network_record(
            NETWORK_BIND, base + 3, 1101, 1, "nginx",
            "0.0.0.0", 443, "0.0.0.0", 0,
            protocol=6, destination_valid=False,
        ),
    )
    add(
        "normal_web_service",
        network_record(
            NETWORK_LISTEN, base + 4, 1101, 1, "nginx",
            "0.0.0.0", 443, "0.0.0.0", 0,
            protocol=6, backlog=128, source_valid=False,
            destination_valid=False,
        ),
    )
    add(
        "normal_web_service",
        network_record(
            NETWORK_ACCEPT, base + 5, 1101, 1, "nginx",
            "198.51.100.23", 53000, "192.0.2.10", 443, protocol=6,
        ),
    )
    add(
        "normal_web_service",
        file_record(
            FILE_OPEN, base + 6, 1101, 1, "nginx",
            "/var/log/nginx/access.log", inode=12001, operation=1,
        ),
    )
    add(
        "normal_web_service",
        process_record(PROCESS_EXIT, base + 7, 1101, 1, "nginx", exit_code=0),
    )

    add(
        "suspicious_shell_egress",
        process_record(PROCESS_EXEC, base + 20, 2201, 1101, "sh", "/bin/sh"),
    )
    add(
        "suspicious_shell_egress",
        process_record(
            PROCESS_EXEC, base + 21, 2202, 2201, "curl", "/usr/bin/curl"
        ),
    )
    add(
        "suspicious_shell_egress",
        syscall_record(SYSCALL_ENTER, base + 22, 2202, 2201, 257, 0),
    )
    add(
        "suspicious_shell_egress",
        file_record(
            FILE_OPEN, base + 23, 2202, 2201, "curl", "/etc/shadow",
            inode=13001, operation=1,
        ),
    )
    add(
        "suspicious_shell_egress",
        syscall_record(SYSCALL_EXIT, base + 24, 2202, 2201, 257, 3),
    )
    add(
        "suspicious_shell_egress",
        network_record(
            NETWORK_CONNECT, base + 25, 2202, 2201, "curl",
            "192.0.2.10", 41000, "203.0.113.10", 4444, protocol=6,
            socket_cookie=9202,
        ),
    )
    add(
        "suspicious_shell_egress",
        file_record(
            FILE_UNLINK, base + 26, 2202, 2201, "curl", "audit.log",
            inode=13002, directory_inode=900, operation=2, flags=PARTIAL_PATH,
        ),
    )

    add(
        "failed_connection",
        network_record(
            NETWORK_CONNECT, base + 40, 3301, 1, "python3",
            "0.0.0.0", 0, "203.0.113.20", 22, protocol=6,
            return_value=-111, source_valid=False,
        ),
    )
    add(
        "udp_dns_like",
        network_record(
            NETWORK_UDP_SEND, base + 50, 4401, 1, "resolver",
            "192.0.2.10", 53053, "203.0.113.53", 53, protocol=17,
            socket_type=2, bytes_requested=32, return_value=32,
        ),
    )
    add(
        "tcp_state_uncertain",
        network_record(
            NETWORK_TCP_STATE, base + 60, 0, 0, "",
            "192.0.2.10", 41000, "203.0.113.10", 4444, protocol=6,
            old_state=2, new_state=1, process_uncertain=True,
            socket_cookie=9202,
        ),
    )
    add("healthy_collection", health_record(base + 70, 0, 0, 0, 0, 0))
    add("degraded_collection", health_record(base + 80, 25, 1, 3, 40, 12))

    definitions = {
        "normal_web_service": (
            "normal",
            "정상 웹 서비스 시작, listen, 연결 수락 및 로그 접근",
        ),
        "suspicious_shell_egress": (
            "suspicious",
            "웹 서비스 자식 shell이 민감 파일에 접근하고 문서용 외부 주소 4444/tcp로 연결",
        ),
        "failed_connection": (
            "context_only",
            "연결 거부(-ECONNREFUSED)는 단독 악성 라벨이 아님",
        ),
        "udp_dns_like": (
            "normal",
            "문서용 DNS 형태 UDP 송신",
        ),
        "tcp_state_uncertain": (
            "context_only",
            "PID보다 socket_cookie로 연결해야 하는 TCP 상태 이벤트",
        ),
        "healthy_collection": (
            "telemetry",
            "수집 유실 없음",
        ),
        "degraded_collection": (
            "telemetry_degraded",
            "이 구간의 모델 판정 신뢰도를 낮추거나 경보해야 함",
        ),
    }

    scenarios: list[dict[str, object]] = []
    for scenario_id, (ground_truth, description) in definitions.items():
        lines = [index + 1 for index, (owner, _) in enumerate(events) if owner == scenario_id]
        scenarios.append(
            {
                "id": scenario_id,
                "ground_truth": ground_truth,
                "description": description,
                "line_start": min(lines),
                "line_end": max(lines),
                "event_count": len(lines),
            }
        )
    return events, scenarios


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    arguments = parser.parse_args()
    arguments.output_dir.mkdir(parents=True, exist_ok=True)

    events, scenarios = build_samples()
    binary = b"".join(
        FRAME.pack(b"EBPF", WIRE_VERSION, 1, 0, len(record)) + record
        for _, record in events
    )
    (arguments.output_dir / "events-v1.bin").write_bytes(binary)
    manifest = {
        "bundle_schema": 1,
        "event_schema_version": SCHEMA_VERSION,
        "sample_kind": "deterministic_sanitized_fixture",
        "labels_embedded_in_events": False,
        "timestamp_domain": "synthetic_monotonic_nanoseconds",
        "reserved_test_networks_only": True,
        "event_file": "events-v1.ndjson",
        "binary_file": "events-v1.bin",
        "scenarios": scenarios,
    }
    (arguments.output_dir / "scenario-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
