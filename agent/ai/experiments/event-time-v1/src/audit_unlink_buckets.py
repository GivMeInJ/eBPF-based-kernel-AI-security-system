#!/usr/bin/env python3
"""Read-only unlink-attempt diagnostics from a closed .bin.zst capture; no scoring."""
import argparse
import json
import os
from pathlib import Path
import subprocess

import numpy as np

import extract as EX
from archive_raw_capture import _identity
from build_event_time_dataset import BUCKET_NS
from detect2 import EVENT_HEADER, MAX_EVENT_SIZE, MIN_EVENT_SIZES
from finalize_event_time_session import check_closed, snapshot


def statistics(values):
    return {"min": float(np.min(values)), "median": float(np.median(values)),
            "max": float(np.max(values)), "positive_buckets": int(np.count_nonzero(values > 0))}


def audit(capture, npz, expected_unlinks):
    capture, npz = Path(capture), Path(npz)
    if not capture.name.endswith(".bin.zst") or type(expected_unlinks) is not int or expected_unlinks < 0:
        raise ValueError("require a .bin.zst capture and nonnegative expected unlink count")
    sources = snapshot([capture, npz])  # Reject symlinks, empty files and non-regular files.
    check_closed(sources)
    with np.load(npz, allow_pickle=False) as data:
        bucket_ns, labels, techniques, sessions = (data[key] for key in
                                                   ("bucket_ns", "labels", "techniques", "sessions"))
    if (bucket_ns.ndim != 1 or not len(bucket_ns) or bucket_ns.dtype.kind not in "iu" or
            np.any(bucket_ns < 0) or np.any(bucket_ns % BUCKET_NS) or
            len(np.unique(bucket_ns)) != len(bucket_ns)):
        raise ValueError("invalid/duplicate NPZ bucket_ns")
    if any(a.ndim != 1 or len(a) != len(bucket_ns) for a in (labels, techniques, sessions)):
        raise ValueError("NPZ array length mismatch")
    if (not np.isin(labels, ("normal", "attack")).all() or not np.all(techniques != "") or
            len(np.unique(sessions)) != 1 or not np.all(sessions != "")):
        raise ValueError("invalid NPZ labels/techniques/session")
    index = {int(b): i for i, b in enumerate(bucket_ns)}
    attempts = np.zeros(len(bucket_ns), dtype=np.int64)
    unknown = np.zeros(len(bucket_ns), dtype=np.int64)
    scopes = [set() for _ in bucket_ns]
    total = outside = outside_unknown = frames = inode_zero = 0
    path_flags = {"partial_path": 0, "path_unavailable": 0, "path_truncated": 0}
    with os.fdopen(os.open(capture, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as raw:
        if _identity(os.fstat(raw.fileno())) != sources[capture]:
            raise ValueError("capture identity changed before reading")
        with subprocess.Popen(["zstd", "-q", "-d", "-c"], stdin=raw,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            try:
                buf = b""
                while chunk := process.stdout.read(EX.CHUNK):
                    buf += chunk
                    off = 0
                    while off + EX.FRAME.size <= len(buf):
                        magic, wire, little, reserved, size = EX.FRAME.unpack_from(buf, off)
                        if (magic, wire, little, reserved) != (b"EBPF", 1, 1, 0) or not EVENT_HEADER.size <= size <= MAX_EVENT_SIZE:
                            raise ValueError("invalid frame")
                        p = off + EX.FRAME.size
                        if p + size > len(buf):
                            break
                        ts, _, _, _, declared, schema, kind, _ = EVENT_HEADER.unpack_from(buf, p)
                        if schema != 1 or declared != size or size < MIN_EVENT_SIZES.get(kind, MAX_EVENT_SIZE + 1):
                            raise ValueError("invalid event schema/declared size/type/minimum size")
                        frames += 1
                        if kind == 7:
                            inode = EX.U64.unpack_from(buf, p + 88)[0]
                            directory_inode = EX.U64.unpack_from(buf, p + 96)[0]
                            device = EX.U32.unpack_from(buf, p + 104)[0]
                            operation = EX.U32.unpack_from(buf, p + 116)[0]
                            flags = EX.U32.unpack_from(buf, p + 64)[0]
                            if operation != 2:
                                raise ValueError("FILE_UNLINK has invalid operation")
                            total += 1
                            inode_zero += int(inode == 0)
                            for name, bit in (("partial_path", 4), ("path_unavailable", 1), ("path_truncated", 2)):
                                path_flags[name] += int(bool(flags & bit))
                            missing = device == 0 or directory_inode == 0
                            row = index.get(ts // BUCKET_NS * BUCKET_NS)
                            if row is None:
                                outside += 1
                                outside_unknown += int(missing)
                            else:
                                attempts[row] += 1
                                unknown[row] += int(missing)
                                if not missing:
                                    scopes[row].add((device, directory_inode))
                        off = p + size
                    buf = buf[off:]
                error = process.stderr.read().decode("utf-8", "replace")
                if process.wait() != 0:
                    raise ValueError(f"zstd decompression failed: {error.strip()}")
                if buf:
                    raise ValueError("incomplete final frame")
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
        if _identity(os.fstat(raw.fileno())) != sources[capture]:
            raise ValueError("capture identity changed while reading")
    if snapshot([capture, npz]) != sources:
        raise ValueError("source identity changed while reading")
    check_closed(sources)
    if total != expected_unlinks:
        raise ValueError(f"FILE_UNLINK count mismatch: recorded {total}, expected {expected_unlinks}")

    unique_scopes = np.array([len(keys) for keys in scopes], dtype=np.int64)
    features = {"unlink_attempts": attempts, "unique_directory_scopes": unique_scopes,
                "unknown_scope_attempts": unknown, "n_unlink_attempts_log": np.log1p(attempts),
                "n_unlink_directory_scopes_log": np.log1p(unique_scopes)}
    class_summary, per_technique = {}, {}
    for label in ("normal", "attack"):
        selected = labels == label
        class_summary[label] = {"buckets": int(np.count_nonzero(selected)),
                                "features": {name: statistics(v[selected]) for name, v in features.items()} if np.any(selected) else {}}
        per_technique[label] = {}
        for tech in sorted(set(techniques[selected].tolist())):
            rows = selected & (techniques == tech)
            per_technique[label][tech] = {"buckets": int(np.count_nonzero(rows)),
                                        "features": {name: statistics(v[rows]) for name, v in features.items()}}
    return {
        "capture": str(capture), "npz": str(npz), "session_id": str(sessions[0]),
        "source_stat": {str(p): list(identity) for p, identity in sources.items()},
        "bucket_ns": BUCKET_NS, "frames_validated": frames, "expected_file_unlink": expected_unlinks,
        "recorded_file_unlink": total, "matched_unlink_attempts": int(attempts.sum()),
        "dropped_outside_npz": outside, "matched_positive_buckets": int(np.count_nonzero(attempts)),
        "npz_buckets": len(bucket_ns), "unknown_scope_attempts": int(unknown.sum()) + outside_unknown,
        "matched_unknown_scope_attempts": int(unknown.sum()), "outside_unknown_scope_attempts": outside_unknown,
        "unlink_inode_zero": inode_zero, "path_metadata_flags": path_flags,
        "class_summary": class_summary, "per_technique": per_technique,
        "buckets": [{"bucket_ns": int(b), "label": str(labels[i]), "technique": str(techniques[i]),
                     **{name: float(v[i]) if name.endswith("_log") else int(v[i]) for name, v in features.items()}}
                    for i, b in enumerate(bucket_ns)],
        "note": "Diagnostic unlink attempts, not confirmed deletions. Directory scope uses nonzero (device, directory_inode) only; unavailable keys stay unknown. Partial basenames are never interpreted as full paths. Outside-NPZ events are counted but excluded from bucket features. No model tuning, scoring, NPZ write or live collection.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", help="closed .bin.zst capture; Linux /proc writer check required")
    parser.add_argument("npz", help="single-session NPZ supplying exact bucket_ns and labels")
    parser.add_argument("--expected-unlinks", type=int, required=True, help="collector FILE_UNLINK received count (e.g. 23082)")
    args = parser.parse_args()
    try:
        result = audit(args.capture, args.npz, args.expected_unlinks)
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
