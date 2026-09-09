#!/usr/bin/env python3
"""Validate checksums, schema fixtures, and labels in an AI handoff bundle."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath


REQUIRED_FILES = {
    "AI_HANDOFF_GUIDE.md",
    "BUNDLE_MANIFEST.json",
    "SHA256SUMS",
    "bin/host-events-static",
    "docs/event-schema-v1.md",
    "docs/event-schema-v1.schema.json",
    "docs/VALIDATION_REPORT.md",
    "include/agent_events.h",
    "samples/events-v1.bin",
    "samples/events-v1.ndjson",
    "samples/scenario-manifest.json",
    "tools/decode-events.py",
    "tools/generate-handoff-samples.py",
    "tools/validate-handoff-bundle.py",
}

EVENT_TYPES = {
    "PROCESS_FORK",
    "PROCESS_EXEC",
    "PROCESS_EXIT",
    "SYSCALL_ENTER",
    "SYSCALL_EXIT",
    "FILE_OPEN",
    "FILE_UNLINK",
    "NETWORK_CONNECT",
    "NETWORK_BIND",
    "NETWORK_LISTEN",
    "NETWORK_ACCEPT",
    "NETWORK_UDP_SEND",
    "NETWORK_TCP_STATE",
    "HEALTH",
}

DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def validate_checksums(bundle: Path) -> None:
    checked: set[str] = set()
    for number, line in enumerate(
        (bundle / "SHA256SUMS").read_text(encoding="utf-8").splitlines(), 1
    ):
        expected, separator, relative = line.partition("  ")
        if not separator or len(expected) != 64:
            raise ValueError(f"malformed SHA256SUMS line {number}")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts:
            raise ValueError(f"unsafe checksum path: {relative}")
        path = bundle.joinpath(*pure.parts)
        if not path.is_file():
            raise ValueError(f"checksummed file missing: {relative}")
        if digest(path) != expected:
            raise ValueError(f"checksum mismatch: {relative}")
        checked.add(relative)

    expected_files = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    if checked != expected_files:
        missing = sorted(expected_files - checked)
        extra = sorted(checked - expected_files)
        raise ValueError(f"checksum coverage mismatch: missing={missing} extra={extra}")


def validate_samples(bundle: Path) -> int:
    decoder = bundle / "tools/decode-events.py"
    binary = bundle / "samples/events-v1.bin"
    expected_ndjson = bundle / "samples/events-v1.ndjson"
    decoded = subprocess.run(
        [sys.executable, str(decoder), str(binary)],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    if decoded != expected_ndjson.read_bytes():
        raise ValueError("binary decoder output differs from events-v1.ndjson")

    machine_schema = json.loads(
        (bundle / "docs/event-schema-v1.schema.json").read_text(encoding="utf-8")
    )
    if machine_schema.get("$id") != "urn:ebpf-agent:event-schema:v1":
        raise ValueError("unexpected machine-readable event schema ID")

    events = [
        json.loads(line)
        for line in expected_ndjson.read_text(encoding="utf-8").splitlines()
    ]
    try:
        import jsonschema
    except ModuleNotFoundError:
        jsonschema = None
    if jsonschema is not None:
        jsonschema.Draft202012Validator.check_schema(machine_schema)
        validator = jsonschema.Draft202012Validator(machine_schema)
        for index, event in enumerate(events, 1):
            errors = sorted(validator.iter_errors(event), key=lambda error: error.path)
            if errors:
                raise ValueError(
                    f"JSON schema failure at sample line {index}: {errors[0].message}"
                )
    if {event["event_type"] for event in events} != EVENT_TYPES:
        raise ValueError("sample does not cover every schema-v1 event type")
    forbidden = {"label", "ground_truth", "scenario", "is_malicious"}
    if any(forbidden & event.keys() for event in events):
        raise ValueError("ground-truth labels leaked into event records")

    identities: dict[int, tuple[int, int]] = {}
    for event in events:
        tgid = event["tgid"]
        if not tgid or event["event_type"] == "HEALTH":
            continue
        identity = (event["task_start_ns"], event["ppid"])
        previous = identities.setdefault(tgid, identity)
        if previous != identity:
            raise ValueError(f"inconsistent process identity for TGID {tgid}")

    forks = {
        event["child_pid"]
        for event in events
        if event["event_type"] == "PROCESS_FORK"
    }
    execs = {
        event["pid"] for event in events if event["event_type"] == "PROCESS_EXEC"
    }
    if not forks <= execs:
        raise ValueError("fork child is missing its correlated exec sample")

    suspicious_connect = next(
        event
        for event in events
        if event["event_type"] == "NETWORK_CONNECT"
        and event["dst_port"] == 4444
        and event["retval"] == 0
    )
    related_state = next(
        event
        for event in events
        if event["event_type"] == "NETWORK_TCP_STATE"
        and event["dst_port"] == 4444
    )
    if suspicious_connect["socket_cookie"] != related_state["socket_cookie"]:
        raise ValueError("connect/TCP-state socket_cookie correlation is broken")

    for event in events:
        for field in ("src_ip", "dst_ip"):
            value = event.get(field)
            if value in (None, "0.0.0.0", "::"):
                continue
            parsed = ipaddress.ip_address(value)
            if not any(parsed in network for network in DOCUMENTATION_NETWORKS):
                raise ValueError(f"non-documentation sample address: {value}")

    manifest = json.loads(
        (bundle / "samples/scenario-manifest.json").read_text(encoding="utf-8")
    )
    if manifest["labels_embedded_in_events"] is not False:
        raise ValueError("manifest must keep labels separate from events")
    covered: list[int] = []
    for scenario in manifest["scenarios"]:
        start = scenario["line_start"]
        end = scenario["line_end"]
        if start < 1 or end > len(events) or start > end:
            raise ValueError(f"invalid scenario line range: {scenario['id']}")
        if scenario["event_count"] != end - start + 1:
            raise ValueError(f"scenario count mismatch: {scenario['id']}")
        covered.extend(range(start, end + 1))
    if sorted(covered) != list(range(1, len(events) + 1)):
        raise ValueError("scenario ranges must cover every event exactly once")

    health = [event for event in events if event["event_type"] == "HEALTH"]
    if not any(
        event["writer_queue_dropped"] == 0
        and event["kernel_ringbuf_lost"] == 0
        for event in health
    ):
        raise ValueError("healthy HEALTH fixture missing")
    if not any(
        event["writer_queue_dropped"] > 0
        and event["kernel_ringbuf_lost"] > 0
        for event in health
    ):
        raise ValueError("degraded HEALTH fixture missing")
    return len(events)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    arguments = parser.parse_args()
    bundle = arguments.bundle.resolve()
    if not bundle.is_dir():
        raise ValueError(f"bundle directory not found: {bundle}")
    missing = sorted(
        relative
        for relative in REQUIRED_FILES
        if not bundle.joinpath(*PurePosixPath(relative).parts).is_file()
    )
    if missing:
        raise ValueError(f"required files missing: {missing}")

    metadata = json.loads(
        (bundle / "BUNDLE_MANIFEST.json").read_text(encoding="utf-8")
    )
    event_count = validate_samples(bundle)
    if metadata["sample_event_count"] != event_count:
        raise ValueError("BUNDLE_MANIFEST sample_event_count mismatch")
    validate_checksums(bundle)
    print(f"handoff bundle validation passed ({event_count} events)")


if __name__ == "__main__":
    main()
