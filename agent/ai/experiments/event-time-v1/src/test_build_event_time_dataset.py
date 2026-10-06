"""Small end-to-end check of event-time labels and rotated diagnostic logs."""

import json
import os
from collections import Counter
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch

import numpy as np

from aggregate import FEATURES
from build_event_time_dataset import read_buckets


BN = 1_000_000_000


def bucket(index, value):
    return {"type": "bucket", "bucket_ns": index * BN,
            "ts": 999, "features": [value] * 31}


def write(path, *records):
    path.write_text("".join(json.dumps(record) + "\n" for record in records))


def test():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        base, timeline, out = root / "diagnostic.jsonl", root / "session.tsv", root / "dataset.npz"
        write(Path(f"{base}.2"), bucket(0, 1), bucket(3, 2))
        write(Path(f"{base}.1"), bucket(3, 3), bucket(1, 4))
        write(base, {"type": "health"}, bucket(2, 5), bucket(4, 6),
              bucket(5, 7), bucket(6, 8), bucket(7, 9), bucket(8, 10))
        timeline.write_text(
            f"0\t{2*BN}\tnormal\tw_idle\n"
            f"{2*BN+1}\t{4*BN}\tattack\tt_probe\n"
            f"{4*BN}\t{5*BN}\tunknown\tmystery\n"
            f"{5*BN}\t{6*BN}\tnormal\tw_work\n"
            f"{6*BN}\t{7*BN}\tattack\tt_other\n"
            f"{7*BN}\t{7*BN+BN//2}\tnormal\tw_half\n"
            f"{7*BN+BN//2}\t{8*BN}\tattack\tt_half\n")
        result = subprocess.run([sys.executable, str(Path(__file__).with_name(
            "build_event_time_dataset.py")), str(base), str(timeline), str(out),
            "--session", "s1"], text=True, capture_output=True, check=True)
        stats = json.loads(result.stdout)
        assert os.stat(out).st_mode & 0o777 == 0o600
        assert {key: stats[key] for key in ("kept", "duplicate_buckets", "skipped_duplicate", "health_records",
                "skipped_boundary", "skipped_mixed", "skipped_unknown",
                "skipped_unlabeled")} == {
            "kept": 4, "duplicate_buckets": 1, "skipped_duplicate": 1,
            "health_records": 1,
            "skipped_boundary": 1, "skipped_mixed": 1, "skipped_unknown": 1,
            "skipped_unlabeled": 1}
        assert stats["normal"] == 3 and stats["attack"] == 1
        with np.load(out) as data:
            assert data["X"].shape == (4, 31) and data["X"].dtype == np.float32
            assert np.isfinite(data["X"]).all()
            assert data["X"][:, 0].tolist() == [1, 4, 7, 8]
            assert data["labels"].tolist() == ["normal", "normal", "normal", "attack"]
            assert data["techniques"].tolist() == ["w_idle", "w_idle", "w_work", "other"]
            assert data["sessions"].tolist() == ["s1"] * 4
            assert data["bucket_ns"].shape == (4,)
            assert np.all(np.diff(data["bucket_ns"]) > 0)
            assert data["names"].tolist() == FEATURES
        write(base, bucket(9, float("nan")))
        invalid = subprocess.run([sys.executable, str(Path(__file__).with_name(
            "build_event_time_dataset.py")), str(base), str(timeline), str(out)],
            text=True, capture_output=True)
        assert invalid.returncode != 0 and "31 finite" in invalid.stderr
        write(base, {**bucket(9, 1), "features": [1] * 30})
        invalid = subprocess.run([sys.executable, str(Path(__file__).with_name(
            "build_event_time_dataset.py")), str(base), str(timeline), str(out)],
            text=True, capture_output=True)
        assert invalid.returncode != 0 and "31 finite" in invalid.stderr


def test_event_bounds():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        base, timeline, out = root / "diagnostic.jsonl", root / "session.tsv", root / "dataset.npz"
        write(base,
              {**bucket(0, 1), "first_event_ns": 120, "last_event_ns": 180},
              {**bucket(1, 2), "first_event_ns": BN+150, "last_event_ns": BN+180},
              {**bucket(2, 3), "first_event_ns": 2*BN+120, "last_event_ns": 2*BN+180},
              bucket(3, 4),
              {**bucket(4, 5), "first_event_ns": 4*BN+120, "last_event_ns": 4*BN+180})
        timeline.write_text(
            f"100\t200\tnormal\tw_short\n"
            f"300\t400\tattack\tt_later\n"
            f"{BN+100}\t{BN+200}\tnormal\tw_overlap\n"
            f"{BN+170}\t{BN+300}\tattack\tt_overlap\n"
            f"{2*BN+100}\t{2*BN+200}\tunknown\tmystery\n"
            f"{3*BN+100}\t{3*BN+200}\tnormal\tw_legacy\n"
            f"{4*BN+100}\t{4*BN+200}\tprecursor\tt_scan\n")
        result = subprocess.run([sys.executable, str(Path(__file__).with_name(
            "build_event_time_dataset.py")), str(base), str(timeline), str(out)],
            text=True, capture_output=True, check=True)
        stats = json.loads(result.stdout)
        assert {key: stats[key] for key in ("kept", "skipped_mixed", "skipped_unknown",
                "skipped_boundary")} == {
            "kept": 2, "skipped_mixed": 1, "skipped_unknown": 1,
            "skipped_boundary": 1}
        assert stats["precursor"] == 1
        with np.load(out) as data:
            assert data["X"][:, 0].tolist() == [1, 5]
            assert data["labels"].tolist() == ["normal", "normal"]
            assert data["techniques"].tolist() == ["w_short", "precursor:scan"]


def test_missing_units():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        base, timeline, out = root / "diagnostic.jsonl", root / "session.tsv", root / "dataset.npz"
        write(base, bucket(0, 1), bucket(1, 2))
        with base.open("a") as stream:
            stream.write('{"type":"bucket","bucket_ns":3000000000')
        timeline.write_text(
            f"0\t{BN}\tnormal\tw_kept\n"
            f"{BN}\t{BN+BN//2}\tattack\tt_skipped\n"
            f"{3*BN}\t{4*BN}\tattack\tt_truncated\n")
        result = subprocess.run([sys.executable, str(Path(__file__).with_name(
            "build_event_time_dataset.py")), str(base), str(timeline), str(out)],
            text=True, capture_output=True, check=True)
        stats = json.loads(result.stdout)
        assert stats["kept"] == 1
        assert stats["skipped_boundary"] == stats["truncated_final_lines"] == 1
        assert stats["missing_units"] == ["t_skipped", "t_truncated"]


def test_rotation_coverage():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        base, timeline, out = root / "diagnostic.jsonl", root / "session.tsv", root / "dataset.npz"
        oldest = Path(f"{base}.2")
        write(oldest, {"type": "health", "timestamp_ns": 100})
        write(Path(f"{base}.1"), {**bucket(2, 1),
                                   "first_event_ns": 2*BN+10, "last_event_ns": 2*BN+20})
        write(base, bucket(3, 2))
        timeline.write_text(f"0\t{4*BN}\tnormal\tw_all\n")
        command = [sys.executable, str(Path(__file__).with_name("build_event_time_dataset.py")),
                   str(base), str(timeline), str(out)]
        required = ["--require-before-ns", "100", "--require-after-ns", str(3*BN)]
        result = subprocess.run(command + required, text=True, capture_output=True, check=True)
        stats = json.loads(result.stdout)
        assert (stats["earliest_timestamp_ns"], stats["latest_timestamp_ns"]) == (100, 3*BN)
        oldest.write_text("")
        result = subprocess.run(command + required, text=True, capture_output=True)
        assert result.returncode != 0 and "coverage starts" in result.stderr
        base.write_text("")
        result = subprocess.run(command + required[2:], text=True, capture_output=True)
        assert result.returncode != 0 and "coverage ends" in result.stderr
        result = subprocess.run(command, text=True, capture_output=True, check=True)
        stats = json.loads(result.stdout)
        assert (stats["earliest_timestamp_ns"], stats["latest_timestamp_ns"]) == (2*BN+10, 2*BN+20)


def test_rotation_during_open():
    with TemporaryDirectory() as directory:
        base = Path(directory) / "diagnostic.jsonl"
        write(base, bucket(0, 1))
        original_open = Path.open

        def rotate(path, *args, **kwargs):
            if path == base:
                base.rename(base.with_suffix(".old"))
                with original_open(base, "w", encoding="utf-8") as stream:
                    stream.write(json.dumps(bucket(1, 2)) + "\n")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", rotate):
            try:
                read_buckets(str(base), Counter())
            except ValueError as exc:
                assert "rotated while opening" in str(exc)
            else:
                raise AssertionError("rotation between stat and open was accepted")


if __name__ == "__main__":
    test()
    test_event_bounds()
    test_missing_units()
    test_rotation_coverage()
    test_rotation_during_open()
    print("ok")
