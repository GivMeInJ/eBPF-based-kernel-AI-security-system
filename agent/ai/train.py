#!/usr/bin/env python3
"""Train a normal-only IsolationForest and create a deployable model bundle."""
import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest


def start_time(path):
    return int(path.stem.rsplit("-", 2)[1])


def features(paths, vocab_size):
    matrix = np.zeros((len(paths), vocab_size), dtype=np.float32)
    for row, path in enumerate(paths):
        values = np.fromstring(path.read_text(), dtype=np.int64, sep=" ")
        values = values[(values >= 0) & (values < vocab_size)]
        counts = np.bincount(values, minlength=vocab_size)
        matrix[row] = counts / counts.sum()
    return matrix


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("traces", type=Path)
    parser.add_argument("--map", required=True, type=Path)
    parser.add_argument("--output", default=Path("model"), type=Path)
    parser.add_argument("--fpr", type=float, default=0.005)
    args = parser.parse_args()

    syscall_map = json.loads(args.map.read_text())
    paths = sorted(args.traces.glob("*.txt"), key=start_time)
    if len(paths) < 200:
        raise SystemExit("need at least 200 normal traces")
    split = int(len(paths) * 0.8)
    train = features(paths[:split], syscall_map["vocab_size"])
    test = features(paths[split:], syscall_map["vocab_size"])
    model = IsolationForest(n_estimators=300, random_state=42, n_jobs=-1).fit(train)
    anomaly_score = -model.score_samples(test)
    threshold = float(np.quantile(anomaly_score, 1 - args.fpr))
    actual_fpr = float((anomaly_score >= threshold).mean())

    args.output.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output / "model.pkl")
    (args.output / "syscall_map_x86_64.json").write_text(json.dumps(syscall_map, indent=2) + "\n")
    (args.output / "meta.json").write_text(json.dumps({
        "model": "IsolationForest", "sklearn_version": sklearn.__version__,
        "vocab_size": syscall_map["vocab_size"], "window": 500,
        "train_normal_traces": len(train), "test_normal_traces": len(test),
        "threshold": threshold, "requested_fpr": args.fpr, "measured_fpr": actual_fpr,
    }, indent=2) + "\n")
    print(f"saved {args.output}; future-normal FPR={actual_fpr:.3%}, threshold={threshold:.6f}")


if __name__ == "__main__":
    main()
