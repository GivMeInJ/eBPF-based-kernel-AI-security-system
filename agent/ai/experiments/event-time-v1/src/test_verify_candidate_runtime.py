"""Runnable synthetic integration check; no training or replay process is started."""
import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import joblib
import numpy as np

from aggregate import FEATURES
from feature_schema import STABLE_EXCLUDED
from verify_candidate_runtime import verify


class Model:
    n_features_in_ = 26
    classes_ = np.array([0, 1])

    def predict_proba(self, X):
        return np.column_stack((1 - X[:, 0].astype(float), X[:, 0].astype(float)))


def test():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        model_dir = root / "candidate"
        model_dir.mkdir()
        joblib.dump(Model(), model_dir / "bucket_model.pkl")
        threshold = float(np.nextafter(0.5, np.inf))
        meta = {"feature_names": FEATURES, "excluded_features": list(STABLE_EXCLUDED),
                "feature_schema": "event_time_stable_v1", "bucket_sec": 1.0, "target_fpr": 0.005,
                "threshold": threshold, "split_ids": {"training": ["A", "B"], "calibration": ["C"], "test": ["D"]},
                "held_out_test": {"threshold": threshold, "tp": 1, "fp": 0, "tn": 2, "fn": 1, "total": 4}}
        X = np.zeros((4, 31), dtype=np.float32)
        X[:, 0] = [0.1, 0.5, 0.8, 0.2]
        rows = {"X": X, "labels": np.array(["normal", "normal", "attack", "attack"]),
                "techniques": np.array(["normal", "normal", "attack", "attack"]),
                "sessions": np.array(["D"] * 4), "names": np.array(FEATURES),
                "bucket_ns": np.arange(1, 5, dtype=np.int64) * 1_000_000_000}
        records = [{"type": "bucket", "bucket_ns": int(b), "features": x.tolist(),
                    "score": round(float(x[0]), 4), "threshold": round(threshold, 4),
                    "verdict": "ALERT" if float(x[0]) >= threshold else "normal"}
                   for b, x in zip(rows["bucket_ns"], X)]
        diagnostic = root / "replay.jsonl"
        npz = root / "held_out.npz"

        def run(changed_records=records, changed_meta=meta, changed_rows=rows):
            (model_dir / "meta.json").write_text(json.dumps(changed_meta))
            np.savez(npz, **changed_rows)
            Path(str(diagnostic) + ".1").write_text("".join(json.dumps(r) + "\n" for r in changed_records[:2]))
            diagnostic.write_text("".join(json.dumps(r) + "\n" for r in changed_records[2:]))
            return verify(model_dir, npz, diagnostic)

        def rejected(message, **kwargs):
            try:
                run(**kwargs)
            except ValueError as exc:
                assert message in str(exc), str(exc)
            else:
                raise AssertionError(f"accepted fault: {message}")

        result = run()
        assert result["matched_buckets"] == 4 and result["projected_features"] == 26
        assert {k: result[k] for k in ("tp", "fp", "tn", "fn")} == {"tp": 1, "fp": 0, "tn": 2, "fn": 1}
        changed = copy.deepcopy(records)
        changed[0]["features"][FEATURES.index("frac_missing")] = 999
        assert run(changed_records=changed) == result
        changed[0]["features"][0] += 0.01
        rejected("projected runtime features", changed_records=changed)
        changed = copy.deepcopy(records)
        changed[1]["verdict"] = "ALERT"  # Rounded score/threshold are both .5; full precision verdict is normal.
        rejected("runtime verdict", changed_records=changed)
        changed = copy.deepcopy(records)
        changed[1]["score"] += 0.000052
        rejected("rounded score", changed_records=changed)
        rejected("missing runtime", changed_records=records[:-1])
        rejected("duplicate/truncated", changed_records=records + [records[0]])
        changed = copy.deepcopy(meta)
        changed["split_ids"]["test"] = ["C"]
        rejected("session ID", changed_meta=changed)
        changed = copy.deepcopy(meta)
        changed["held_out_test"]["fn"] += 1
        rejected("runtime totals", changed_meta=changed)
        changed = copy.deepcopy(rows)
        changed["bucket_ns"][1] = changed["bucket_ns"][0]
        rejected("duplicate NPZ", changed_rows=changed)
        changed = copy.deepcopy(rows)
        changed["names"][[0, 1]] = changed["names"][[1, 0]]
        rejected("name/order", changed_rows=changed)


if __name__ == "__main__":
    test()
    print("candidate runtime join/schema/projection/score/verdict/totals checks passed")
