"""Assert smoke test with real zstd streaming; Linux writer check is mocked only off Linux."""
from contextlib import nullcontext
from pathlib import Path
import struct
import subprocess
from tempfile import TemporaryDirectory
from unittest.mock import patch

import numpy as np

import audit_unlink_buckets as evaluator


def frame(ts, directory, device=8, *, inode=10, flags=4, schema=1, declared=376,
          operation=2, kind=7, size=376):
    event = bytearray(size)
    evaluator.EVENT_HEADER.pack_into(event, 0, ts, 123, 1, 0, declared, schema, kind, b"test")
    struct.pack_into("<I", event, 64, flags)
    if size >= 376:
        struct.pack_into("<QQI", event, 88, inode, directory, device)
        struct.pack_into("<I", event, 116, operation)
        event[120:125] = b"same\0"  # Identical partial basename must not merge directories.
    return evaluator.EX.FRAME.pack(b"EBPF", 1, 1, 0, size) + event


def test():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        capture, npz = root / "session.bin.zst", root / "session.npz"
        np.savez(npz, bucket_ns=np.array([0, 1_000_000_000, 3_000_000_000], dtype=np.int64),
                 labels=np.array(["normal", "attack", "normal"]),
                 techniques=np.array(["work", "wiper_sim", "idle"]), sessions=np.array(["S"] * 3))
        valid = b"".join([
            frame(100, 100), frame(200, 200), frame(300, 100, device=9),
            frame(1_100_000_000, 0, inode=0, flags=5),
            frame(1_200_000_000, 100, device=0), frame(2_000_000_000, 400),
        ])

        def run(raw=valid, expected=6):
            with capture.open("wb") as output:
                subprocess.run(["zstd", "-q", "-c"], input=raw, stdout=output, check=True)
            # The production CLI fails closed without Linux /proc.
            guard = nullcontext() if Path("/proc").is_dir() else patch.object(evaluator, "check_closed")
            with guard:
                return evaluator.audit(capture, npz, expected)

        result = run()
        assert result["recorded_file_unlink"] == result["expected_file_unlink"] == 6
        assert result["matched_unlink_attempts"] == 5 and result["dropped_outside_npz"] == 1
        assert result["unknown_scope_attempts"] == result["matched_unknown_scope_attempts"] == 2
        assert result["outside_unknown_scope_attempts"] == 0 and result["unlink_inode_zero"] == 1
        assert result["path_metadata_flags"] == {"partial_path": 6, "path_unavailable": 1, "path_truncated": 0}
        normal, attack, idle = result["buckets"]
        assert normal["unlink_attempts"] == normal["unique_directory_scopes"] == 3
        assert normal["n_unlink_attempts_log"] == normal["n_unlink_directory_scopes_log"] == np.log1p(3)
        assert attack["unlink_attempts"] == attack["unknown_scope_attempts"] == 2
        assert attack["unique_directory_scopes"] == attack["n_unlink_directory_scopes_log"] == 0
        assert idle["unlink_attempts"] == idle["unique_directory_scopes"] == 0
        assert result["class_summary"]["normal"]["features"]["unlink_attempts"] == {"min": 0.0, "median": 1.5, "max": 3.0, "positive_buckets": 1}
        assert result["per_technique"]["attack"]["wiper_sim"]["features"]["unknown_scope_attempts"]["max"] == 2
        assert "same" not in str(result)  # Never export or infer paths.

        def rejected(raw, message, expected=6):
            try:
                run(raw, expected)
            except ValueError as exc:
                assert message in str(exc), str(exc)
            else:
                raise AssertionError(f"accepted fault: {message}")

        rejected(valid, "count mismatch", expected=7)
        rejected(b"BAD!" + valid[4:], "invalid frame")
        rejected(valid[:-1], "incomplete final frame")
        rejected(valid + b"E", "incomplete final frame")
        rejected(frame(0, 100, schema=2), "invalid event schema")
        rejected(frame(0, 100, declared=375), "declared size")
        rejected(frame(0, 100, operation=1), "invalid operation")
        rejected(frame(0, 100, kind=15), "type/minimum size")
        rejected(frame(0, 100, size=120, declared=120), "minimum size")
        with np.load(npz, allow_pickle=False) as data:
            rows = {key: data[key] for key in data.files}
        rows["bucket_ns"][1] = 0
        np.savez(npz, **rows)
        rejected(valid, "invalid/duplicate NPZ bucket_ns")


if __name__ == "__main__":
    test()
    print("unlink streaming/frame/bucket/scope/unknown/reconciliation smoke checks passed")
