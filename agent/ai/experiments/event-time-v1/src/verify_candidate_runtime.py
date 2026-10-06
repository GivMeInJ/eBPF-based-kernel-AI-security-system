#!/usr/bin/env python3
"""Compare a trusted candidate's held-out NPZ against its runtime diagnostic replay."""
import argparse
from collections import Counter
import json
import math
from pathlib import Path

import numpy as np

from aggregate import FEATURES
from build_event_time_dataset import BUCKET_NS, read_buckets
from feature_schema import STABLE_EXCLUDED, apply_feature_mask


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(model_dir, npz, diagnostic):
    import joblib
    from evaluate_event_time import counts

    model_dir = Path(model_dir)
    meta = json.loads((model_dir / "meta.json").read_text())
    names, excluded, threshold = (meta[key] for key in
                                  ("feature_names", "excluded_features", "threshold"))
    require(len(FEATURES) == 31 and names == FEATURES, "candidate raw feature schema mismatch")
    require(isinstance(excluded, list) and len(excluded) == 5 and
            set(excluded) == set(STABLE_EXCLUDED), "candidate must exclude exactly the five stable exclusions")
    require(meta["feature_schema"] == "event_time_stable_v1" and meta["bucket_sec"] == 1.0,
            "candidate schema/bucket width mismatch")
    require(meta["target_fpr"] == 0.005, "candidate target FPR must be 0.005")
    require(type(threshold) in (int, float) and math.isfinite(threshold), "invalid candidate threshold")
    require(meta["held_out_test"]["threshold"] == threshold, "saved test threshold mismatch")
    with np.load(npz, allow_pickle=False) as data:
        X, labels, techniques, sessions, bucket_ns, npz_names = (
            data[key] for key in ("X", "labels", "techniques", "sessions", "bucket_ns", "names"))
    require(npz_names.ndim == 1 and npz_names.tolist() == names, "NPZ feature name/order mismatch")
    require(X.ndim == 2 and X.shape[1] == 31 and len(X) > 0 and np.isfinite(X).all(),
            "invalid NPZ feature matrix")
    require(all(a.ndim == 1 and len(a) == len(X) for a in (labels, techniques, sessions, bucket_ns)),
            "NPZ array length mismatch")
    require(np.isin(labels, ("normal", "attack")).all(), "invalid NPZ labels")
    ids = np.unique(sessions).tolist()
    require(len(ids) == 1 and isinstance(ids[0], str) and ids[0], "NPZ must contain one session")
    split = meta["split_ids"]
    require(split["test"] == ids and ids[0] not in split["training"] + split["calibration"],
            "held-out session ID mismatch/overlap")
    require(bucket_ns.dtype.kind in "iu" and np.all(bucket_ns >= 0) and
            np.all(bucket_ns % BUCKET_NS == 0) and len(np.unique(bucket_ns)) == len(bucket_ns),
            "invalid/duplicate NPZ bucket IDs")
    counters = Counter()
    buckets, duplicates, _, _ = read_buckets(diagnostic, counters)
    require(not duplicates and counters["truncated_final_lines"] == 0, "duplicate/truncated runtime diagnostics")
    require(all(int(b) in buckets for b in bucket_ns), "missing runtime buckets")
    records = [buckets[int(b)] for b in bucket_ns]
    runtime_X = np.asarray([r["features"] for r in records], dtype=np.float32)
    require(runtime_X.shape == X.shape and np.isfinite(runtime_X).all(), "invalid runtime feature matrix")
    expected = apply_feature_mask(X, names, excluded)
    observed = apply_feature_mask(runtime_X, names, excluded)
    require(expected.shape[1] == 26 and np.array_equal(expected, observed), "projected runtime features differ")
    model = joblib.load(model_dir / "bucket_model.pkl")
    require(getattr(model, "n_features_in_", None) == 26 and list(model.classes_) == [0, 1],
            "candidate model feature count/classes mismatch")
    scores = np.asarray(model.predict_proba(observed))[:, 1]
    require(scores.shape == (len(X),) and np.isfinite(scores).all() and
            np.all((scores >= 0) & (scores <= 1)), "invalid candidate probabilities")
    hits = scores >= threshold
    for record, score, hit in zip(records, scores, hits):
        require(record["threshold"] == round(threshold, 4), "runtime threshold mismatch")
        require(type(record["score"]) in (int, float) and math.isfinite(record["score"]) and
                abs(record["score"] - float(score)) <= 0.000051, "runtime rounded score mismatch")
        require(record["verdict"] == ("ALERT" if hit else "normal"), "runtime verdict mismatch")
    totals = counts((labels == "attack").astype(int), hits, techniques)
    require(all(totals[key] == meta["held_out_test"][key] for key in ("tp", "fp", "tn", "fn", "total")),
            "runtime totals differ from saved held-out test")
    return {"session_id": ids[0], "matched_buckets": len(X),
            "extra_runtime_buckets": len(buckets) - len(X), "projected_features": 26,
            "threshold": threshold, **{key: totals[key] for key in ("tp", "fp", "tn", "fn", "total")},
            "note": "Integration agreement on held-out buckets; no threshold tuning or new performance estimate."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model_dir")
    parser.add_argument("held_out_npz")
    parser.add_argument("diagnostic", help="replay JSONL base path; also reads .2 and .1")
    args = parser.parse_args()
    try:
        result = verify(args.model_dir, args.held_out_npz, args.diagnostic)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
