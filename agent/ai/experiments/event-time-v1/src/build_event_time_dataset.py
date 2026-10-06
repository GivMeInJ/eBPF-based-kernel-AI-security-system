#!/usr/bin/env python3
"""Build an offline bucket dataset from detect2 diagnostics and a session timeline.

Timeline intervals and one-second buckets are half-open. When event bounds are
available, exactly one interval must cover all observed events; older records
require full-bucket coverage.
"""

import argparse
from collections import Counter
from contextlib import ExitStack
import json
import os
from pathlib import Path

import numpy as np

from aggregate import FEATURES


BUCKET_NS = 1_000_000_000  # detect2 diagnostic bucket width


def read_timeline(path):
    intervals = []
    with Path(path).open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            fields = line.rstrip("\r\n").split("\t")
            if len(fields) != 4:
                raise ValueError(f"{path}:{number}: expected start_ns, end_ns, class, unit")
            try:
                start, end = int(fields[0]), int(fields[1])
            except ValueError as exc:
                raise ValueError(f"{path}:{number}: invalid timestamp") from exc
            if start < 0 or end <= start or not fields[2] or not fields[3]:
                raise ValueError(f"{path}:{number}: invalid interval or label")
            intervals.append((start, end, fields[2], fields[3]))
    return sorted(intervals)


def read_buckets(base, counts):
    buckets = {}
    duplicates = set()
    earliest_ns = latest_ns = None
    paths = [Path(f"{base}.{suffix}") for suffix in (2, 1)] + [Path(base)]
    paths = [path for path in paths if path.is_file()]
    if not paths:
        raise FileNotFoundError(f"no diagnostic log found: {base}")
    # Open the whole rotation chain before parsing it. Descriptors remain on
    # their original files if the live logger renames them during the read.
    with ExitStack() as stack:
        identities = [(path, path.stat()) for path in paths]
        streams = [(path, stack.enter_context(path.open(encoding="utf-8")), before)
                   for path, before in identities]
        for path, stream, before in streams:
            opened, current = os.fstat(stream.fileno()), path.stat()
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or \
               (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError("diagnostic logs rotated while opening; retry session")
        for path, stream, _ in streams:  # oldest to newest
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError("JSON record must be an object")
                    bounds = None
                    if record.get("type") == "health":
                        counts["health_records"] += 1
                        timestamp = record.get("timestamp_ns")
                        if type(timestamp) is int and timestamp >= 0:
                            bounds = (timestamp, timestamp)
                    elif record.get("type") == "bucket":
                        start = record["bucket_ns"]
                        if type(start) is not int or start < 0 or start % BUCKET_NS:
                            raise ValueError("invalid bucket_ns")
                        first, last = record.get("first_event_ns"), record.get("last_event_ns")
                        bounds = ((first, last) if type(first) is int and type(last) is int
                                  and start <= first <= last < start + BUCKET_NS
                                  else (start, start))
                        counts["bucket_records"] += 1
                        if start in buckets:
                            counts["duplicate_buckets"] += 1
                            duplicates.add(start)
                        buckets[start] = record
                    else:
                        counts["other_records"] += 1
                    if bounds is not None:
                        earliest_ns = bounds[0] if earliest_ns is None else min(earliest_ns, bounds[0])
                        latest_ns = bounds[1] if latest_ns is None else max(latest_ns, bounds[1])
                except (KeyError, TypeError, ValueError) as exc:
                    if isinstance(exc, json.JSONDecodeError) and not line.endswith("\n"):
                        counts["truncated_final_lines"] += 1
                        continue
                    raise ValueError(f"{path}:{number}: {exc}") from exc
    return buckets, duplicates, earliest_ns, latest_ns


def build(base, timeline, out, session="", require_before_ns=None, require_after_ns=None):
    counts = Counter()
    buckets, duplicates, earliest_ns, latest_ns = read_buckets(base, counts)
    if require_before_ns is not None and (earliest_ns is None or earliest_ns > require_before_ns):
        raise ValueError(f"diagnostic coverage starts at {earliest_ns}, after required {require_before_ns}")
    if require_after_ns is not None and (latest_ns is None or latest_ns < require_after_ns):
        raise ValueError(f"diagnostic coverage ends at {latest_ns}, before required {require_after_ns}")
    intervals = read_timeline(timeline)
    X, labels, techniques, sessions = [], [], [], []
    timestamps = []
    accepted_units = set()
    active = []
    next_interval = 0
    for start, record in sorted(buckets.items()):
        if start in duplicates:
            counts["skipped_duplicate"] += 1
            continue
        try:
            row = np.asarray(record["features"], dtype=np.float32)
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"bucket_ns {start}: invalid features: {exc}") from exc
        if row.shape != (len(FEATURES),) or len(FEATURES) != 31 or not np.isfinite(row).all():
            raise ValueError(f"bucket_ns {start}: expected 31 finite float32 features")
        end = start + BUCKET_NS
        first, last = record.get("first_event_ns"), record.get("last_event_ns")
        if "first_event_ns" in record or "last_event_ns" in record:
            if (type(first) is not int or type(last) is not int
                    or not start <= first <= last < end):
                raise ValueError(f"bucket_ns {start}: invalid event bounds")
            span_start, span_end = first, last + 1
        else:
            span_start, span_end = start, end
        active = [interval for interval in active if interval[1] > start]
        while next_interval < len(intervals) and intervals[next_interval][0] < end:
            active.append(intervals[next_interval])
            next_interval += 1
        overlapping = [interval for interval in active
                       if interval[0] < span_end and interval[1] > span_start]
        if not overlapping:
            counts["skipped_unlabeled"] += 1
            continue
        if len(overlapping) != 1:
            counts["skipped_mixed"] += 1
            continue
        left, right, cls, unit = overlapping[0]
        if left > span_start or right < span_end:
            counts["skipped_boundary"] += 1
            continue
        if cls not in ("normal", "attack", "precursor"):
            counts["skipped_unknown"] += 1
            continue
        X.append(row)
        timestamps.append(start)
        labels.append("attack" if cls == "attack" else "normal")
        technique = unit[2:] if unit.startswith("t_") else unit
        techniques.append(f"precursor:{technique}" if cls == "precursor" else technique)
        sessions.append(session)
        accepted_units.add(unit)
        counts[cls] += 1
    matrix = np.stack(X) if X else np.empty((0, len(FEATURES)), dtype=np.float32)
    with open(out, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        np.savez_compressed(stream, X=matrix, labels=np.array(labels, dtype=str),
                            techniques=np.array(techniques, dtype=str),
                            sessions=np.array(sessions, dtype=str),
                            bucket_ns=np.array(timestamps, dtype=np.int64),
                            names=np.array(FEATURES))
    return {"bucket_ns": BUCKET_NS, "timeline_intervals": len(intervals),
            "unique_buckets": len(buckets), "kept": len(X),
            "earliest_timestamp_ns": earliest_ns, "latest_timestamp_ns": latest_ns,
            "missing_units": sorted({unit for _, _, _, unit in intervals} - accepted_units),
            **{key: counts[key] for key in (
                "bucket_records", "duplicate_buckets", "skipped_duplicate",
                "health_records", "other_records",
                "truncated_final_lines", "normal", "attack", "precursor", "skipped_unlabeled",
                "skipped_mixed", "skipped_boundary", "skipped_unknown")}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", help="detect2 diagnostic JSONL base path; also reads .2 and .1")
    parser.add_argument("timeline", help="headerless TSV: start_ns, end_ns, class, unit")
    parser.add_argument("out", help="output NPZ")
    parser.add_argument("--session", default="", help="optional session id")
    parser.add_argument("--require-before-ns", type=int, help="require diagnostic coverage at or before this time")
    parser.add_argument("--require-after-ns", type=int, help="require diagnostic coverage at or after this time")
    args = parser.parse_args()
    try:
        stats = build(args.log, args.timeline, args.out, args.session,
                      args.require_before_ns, args.require_after_ns)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(stats, sort_keys=True))


if __name__ == "__main__":
    main()
