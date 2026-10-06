#!/usr/bin/env python3
"""Validate a closed raw capture, replay it, and publish its event-time NPZ last."""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from audit_network_capture import audit
from build_event_time_dataset import build, read_timeline


EVENT_NAMES = (
    "PROCESS_FORK", "PROCESS_EXEC", "PROCESS_EXIT", "SYSCALL_ENTER", "SYSCALL_EXIT",
    "FILE_OPEN", "FILE_UNLINK", "NETWORK_CONNECT", "NETWORK_BIND", "NETWORK_LISTEN",
    "NETWORK_ACCEPT", "NETWORK_UDP_SEND", "NETWORK_TCP_STATE", "HEALTH",
)
NETWORK_NAMES = dict(zip(range(8, 14), EVENT_NAMES[7:13]))
HEALTH_LOSS = ("writer_queue_dropped", "writer_priority_dropped",
               "kernel_ringbuf_lost", "network_rate_limited")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_collection(log, network_audit):
    def counter(pattern, name):
        matches = re.findall(pattern, log, re.M)
        require(len(matches) == 1, f"missing/duplicate collector counter: {name}")
        return int(matches[0])

    writer = {name: counter(r"^writer " + name + r" dropped=(\d+)\s*$", name)
              for name in ("queue", "priority")}
    require(not any(writer.values()), f"writer loss: {writer}")
    rows = re.findall(r"^\s+([A-Z_]+)\s+received=(\d+) lost=(\d+)\s*$", log, re.M)
    require(len(rows) == len(EVENT_NAMES) and {r[0] for r in rows} == set(EVENT_NAMES),
            "missing/duplicate collector event statistics")
    require(all(int(lost) == 0 for _, _, lost in rows), "collector event loss")
    received = {name: int(value) for name, value, _ in rows}
    network = {name: counter(r"^\s+" + name + r"\s+(\d+)\s*$", name)
               for name in ("map_update_failed", "socket_read_failed", "ringbuf_lost",
                            "user_read_failed", "filtered", "rate_limited")}
    require(all(value == 0 for name, value in network.items() if name != "socket_read_failed"),
            f"network loss/filtering: {network}")
    recorded = network_audit["network_counts"]
    require(all(kind in NETWORK_NAMES and type(value) is int and value >= 0
                for kind, value in recorded.items()), "invalid audited network counts")
    for kind, name in NETWORK_NAMES.items():
        require(recorded.get(kind, 0) == received[name], f"raw/collector count mismatch: {name}")
        require(kind in (8, 9) or received[name] == 0, f"unsupported network type: {name}")
    incomplete = network_audit["incomplete_socket_metadata"]
    require(len(incomplete) == network["socket_read_failed"],
            "socket metadata count does not match socket_read_failed")
    require(all(item["type"] in (8, 9) and not item["flags"] & 64 for item in incomplete),
            "unsupported incomplete socket metadata")
    return {"writer_dropped": writer, "received": received,
            "event_lost": {name: int(lost) for name, _, lost in rows}, "network_statistics": network,
            "socket_metadata_complete": not incomplete,
            "note": "Socket metadata absence is recorded separately; exact event counts and "
                    "zero event-loss counters are required. Missing socket fields remain unknown."}


def snapshot(paths):
    result = {}
    for path in paths:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_size > 0, f"invalid source file: {path}")
        result[path] = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    return result


def check_closed(sources):
    """Final counters precede fclose; also reject any still-open writable source FD."""
    proc = Path("/proc")
    require(proc.is_dir(), "source writer check requires Linux /proc")
    identities = {value[:2] for value in sources.values()}
    for fd in proc.glob("[0-9]*/fd/*"):
        try:
            info = fd.stat()
            if (info.st_dev, info.st_ino) not in identities:
                continue
            text = (fd.parent.parent / "fdinfo" / fd.name).read_text()
            flags = re.findall(r"^flags:\s+([0-7]+)$", text, re.M)
            require(len(flags) == 1 and int(flags[0], 8) & os.O_ACCMODE == os.O_RDONLY,
                    f"capture still has a writable source descriptor: {fd}")
        except (FileNotFoundError, ProcessLookupError):
            continue


def create(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                     "w", encoding="utf-8")


def check_health(base, start, end):
    health = []
    for path in (Path(str(base) + ".2"), Path(str(base) + ".1"), base):
        if not path.exists():
            continue
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                record = json.loads(line)
                if record.get("type") == "health":
                    require(type(record.get("timestamp_ns")) is int, "invalid HEALTH timestamp")
                    require(all(type(record.get(key)) is int and record[key] == 0
                                for key in HEALTH_LOSS), "HEALTH loss/missing counters")
                    health.append(record["timestamp_ns"])
    require(health and min(health) <= start and max(health) >= end,
            "missing pre/post-session HEALTH coverage")
    return {"records": len(health), "first_timestamp_ns": min(health),
            "last_timestamp_ns": max(health), "loss_counters": dict.fromkeys(HEALTH_LOSS, 0)}


def finalize(prefix, start, end, session_id):
    require(re.fullmatch(r"/whs/[A-Za-z0-9_./-]+", str(prefix)), "invalid /whs prefix")
    prefix = Path(prefix).resolve()
    require(Path("/whs").resolve() in prefix.parents, "prefix escapes /whs")
    require(type(start) is int and type(end) is int and 0 <= start < end, "invalid session bounds")
    require(isinstance(session_id, str) and re.fullmatch(r"[A-Za-z0-9_-]+", session_id),
            "invalid session ID")
    path = lambda suffix: Path(str(prefix) + suffix)
    raw, timeline, collector = (path(suffix) for suffix in (".bin", ".tsv", ".collector.log"))
    diagnostic, partial, final = (path(suffix) for suffix in
                                 (".diagnostic.jsonl", ".event_time.partial", ".event_time.npz"))
    outputs = [path(suffix) for suffix in (
        ".diagnostic.jsonl", ".diagnostic.jsonl.1", ".diagnostic.jsonl.2",
        ".replay.alerts.jsonl", ".replay.log", ".event_time.partial", ".event_time.npz",
        ".event_time.stats.partial", ".event_time.stats.json", ".network.audit.json", ".manifest.json")]
    lock = path(".finalize.lock")
    with create(lock):
        pass
    try:
        require(not any(os.path.lexists(p) for p in outputs), "finalization artifact already exists")
        sources = snapshot((raw, timeline, collector))
        check_closed(sources)
        intervals = read_timeline(timeline)
        require(len(intervals) == 93 and len({row[3] for row in intervals}) == 93,
                "expected 93 distinct completed timeline units")
        require(all(row[2] in ("normal", "attack", "precursor") for row in intervals),
                "unknown timeline unit")
        require(start <= intervals[0][0] and intervals[-1][1] <= end and
                all(a[1] <= b[0] for a, b in zip(intervals, intervals[1:])),
                "timeline overlaps or lies outside session bounds")
        network_audit = audit(raw, timeline)
        collection = check_collection(collector.read_text(), network_audit)
        require(snapshot(sources) == sources, "source files changed during audit")
        with create(diagnostic):
            pass
        with create(path(".replay.alerts.jsonl")) as out, create(path(".replay.log")) as errors:
            subprocess.run([sys.executable, "/whs/detect2.py", "--model", "/whs/model_bucket_data9",
                            "--map", "/whs/syscall_map_x86_64.json", "--input", str(raw), "--quiet",
                            "--threshold", "2", "--diagnostic-log", str(diagnostic)],
                           stdout=out, stderr=errors, check=True, umask=0o077)
        require(snapshot(sources) == sources, "source files changed during replay")
        stats = build(diagnostic, timeline, partial, session=session_id,
                      require_before_ns=start, require_after_ns=end)
        require(stats["normal"] > 0 and stats["attack"] > 0 and not stats["missing_units"] and
                stats["duplicate_buckets"] == stats["skipped_duplicate"] == stats["skipped_unknown"] ==
                stats["truncated_final_lines"] == 0, "dataset missing/unknown/duplicate buckets or units")
        health = check_health(diagnostic, start, end)
        check_closed(sources)
        require(snapshot(sources) == sources, "source files changed during finalization")
        manifest = {"session_id": session_id, "start_ns": start, "end_ns": end,
                    "source_stat": {str(p): list(values) for p, values in sources.items()},
                    "collector": collection, "health": health,
                    "incomplete_socket_metadata_count": len(network_audit["incomplete_socket_metadata"]),
                    "dataset": str(final), "note": "Optional unknown socket metadata is preserved; "
                    "this validation does not claim complete socket metadata or model performance."}
        for target, data in ((path(".event_time.stats.json"), stats),
                             (path(".network.audit.json"), network_audit), (path(".manifest.json"), manifest)):
            with create(target) as stream:
                json.dump(data, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
        require(snapshot(sources) == sources and not os.path.lexists(final),
                "source changed or final NPZ already exists")
        final.hardlink_to(partial)
        partial.unlink()
        return manifest
    finally:
        lock.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prefix")
    parser.add_argument("start_ns", type=int)
    parser.add_argument("end_ns", type=int)
    parser.add_argument("session_id", nargs="?")
    parser.add_argument("--session", help="session ID (alternative to fourth positional argument)")
    args = parser.parse_args()
    if args.session_id and args.session:
        parser.error("supply the session ID once")
    try:
        result = finalize(args.prefix, args.start_ns, args.end_ns, args.session_id or args.session)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
