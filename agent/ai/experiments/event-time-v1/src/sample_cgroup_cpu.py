"""Bounded, read-only CPU telemetry. Configured roles are not normal/attack labels."""
import argparse
import json
import math
from pathlib import Path
import time


def cpu_delta(before, after):
    elapsed = after["timestamp_ns"] - before["timestamp_ns"]
    used = after["usage_usec"] - before["usage_usec"]
    if before["identity"] != after["identity"] or elapsed <= 0 or used < 0:
        raise ValueError("cgroup identity/counter/clock changed")
    return {"interval_start_ns": before["timestamp_ns"], "interval_end_ns": after["timestamp_ns"],
            "cpu_usage_usec": used, "cpu_cores_mean": used * 1000 / elapsed}


def read_cpu(path):
    stat = path.stat()
    values = dict(line.split() for line in (path / "cpu.stat").read_text().splitlines())
    current = path.stat()
    if (stat.st_dev, stat.st_ino) != (current.st_dev, current.st_ino):
        raise ValueError("cgroup identity changed while reading")
    used = int(values["usage_usec"])
    if used < 0:
        raise ValueError("invalid cumulative CPU usage")
    return {"identity": (stat.st_dev, stat.st_ino), "usage_usec": used,
            "timestamp_ns": time.monotonic_ns()}


def sample(scopes, output, duration, interval):
    if not all(math.isfinite(v) and v > 0 for v in (duration, interval)):
        raise ValueError("duration and interval must be finite and positive")
    root = Path("/sys/fs/cgroup").resolve()
    paths = {}
    for item in scopes:
        role, path = item.split("=", 1)
        path = Path(path).resolve()
        if not role.isidentifier() or role in paths or not path.is_relative_to(root):
            raise ValueError("invalid/duplicate role or non-cgroup path")
        paths[role] = path
    if not paths:
        raise ValueError("at least one scope required")
    before = {role: read_cpu(path) for role, path in paths.items()}
    deadline = time.monotonic() + duration
    with Path(output).open("x", buffering=1) as stream:
        stream.write(json.dumps({"type": "metadata", "ground_truth": "unlabeled", "interval_seconds": interval,
                                 "duration_seconds": duration, "roles": {r: {"path": str(p), "cgroup_id": before[r]["identity"][1]} for r, p in paths.items()},
                                 "note": "Observed cgroup CPU including descendants, not per-task CPU or evidence of malicious intent. Linux CLOCK_MONOTONIC interval endpoints; no BPF clock alignment verified here."}) + "\n")
        while time.monotonic() < deadline:
            time.sleep(min(interval, max(0, deadline - time.monotonic())))
            for role, path in paths.items():
                try:
                    after = read_cpu(path)
                    record = {"type": "cpu_interval", "role": role, "cgroup_id": after["identity"][1],
                              "ground_truth": "unlabeled", **cpu_delta(before[role], after)}
                except (OSError, ValueError, KeyError) as exc:
                    stream.write(json.dumps({"type": "coverage_error", "role": role, "error": str(exc)}) + "\n")
                    raise
                stream.write(json.dumps(record) + "\n")
                before[role] = after
        stream.write(json.dumps({"type": "complete", "timestamp_ns": time.monotonic_ns()}) + "\n")


def self_check():
    a = {"identity": (1, 2), "timestamp_ns": 0, "usage_usec": 100}
    b = {"identity": (1, 2), "timestamp_ns": 1_000_000_000, "usage_usec": 2_000_100}
    assert cpu_delta(a, b)["cpu_cores_mean"] == 2.0
    for bad in ({**b, "usage_usec": 99}, {**b, "identity": (1, 3)}, {**b, "timestamp_ns": 0}):
        try:
            cpu_delta(a, bad)
        except ValueError:
            pass
        else:
            raise AssertionError("reset or invalid interval accepted")
    print("CPU delta, multicore usage and identity/counter reset checks passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", action="append", default=[])
    parser.add_argument("--output")
    parser.add_argument("--duration", type=float, default=1800)
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if args.self_check:
        self_check()
    elif not args.output:
        parser.error("--output is required")
    else:
        sample(args.scope, args.output, args.duration, args.interval)
