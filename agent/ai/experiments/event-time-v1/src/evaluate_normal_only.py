#!/usr/bin/env python3
"""Fixed exploratory normal-only anomaly evaluation; no model export or deployment."""
import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from aggregate import FEATURES
from evaluate_unseen_groups import GROUPS, REGIMES, TARGET_FPR, summarize
from feature_schema import STABLE_EXCLUDED, apply_feature_mask


PROTOCOL = {
    "protocol": "event_time_normal_only_isolation_forest_v1",
    "session_split": "Exactly six unique single-session NPZs sorted by session ID: first four training pool, penultimate normal-only calibration, last full test.",
    "training_regimes": REGIMES,
    "training": "Fit only normal rows from the first two or all four training sessions; exclude every attack row.",
    "calibration": "Threshold from only penultimate-session normals; no calibration attacks or test data used for fitting/tuning.",
    "test": "Score every held-out row once per regime; report full-session metrics plus each attack group against all test normals.",
    "groups": GROUPS,
    "isolation_forest": {"n_estimators": 300, "random_state": 42, "max_samples": "auto",
                         "max_features": 1.0, "bootstrap": False, "contamination": "auto", "n_jobs": 1},
    "score": "-score_samples; larger is more anomalous; alert when score >= calibrated threshold",
    "target_fpr": TARGET_FPR,
    "raw_feature_names": FEATURES,
    "excluded_features": list(STABLE_EXCLUDED),
    "projected_features": 26,
    "note": "Exploratory evaluation on a previously seen controlled local dummy corpus. All attack rows are excluded from training, but this is not an untouched blind test or proof of real-world zero-day detection. DR/FPR are bucket-level, not incident-level. No model export, runtime change or deployment.",
}


def evaluate(paths):
    import sklearn
    from sklearn.ensemble import IsolationForest
    from evaluate_event_time import read_data, normal_cutoff, counts

    if len(paths) != 6:
        raise ValueError("exactly six single-session NPZ files are required")
    X, labels, techniques, sessions, names = read_data(paths, (), single_session_files=True)
    if len(FEATURES) != 31 or names != FEATURES:
        raise ValueError("expected the exact 31 raw feature names/order")
    X = apply_feature_mask(X, names, STABLE_EXCLUDED)
    if X.shape[1] != 26:
        raise ValueError("expected 26 projected features")
    ids = sorted(np.unique(sessions).tolist())
    if len(ids) != 6:
        raise ValueError("exactly six unique sessions are required")
    split = {"training": ids[:4], "calibration": [ids[4]], "test": [ids[5]]}
    known = {tech for group in GROUPS.values() for tech in group}
    unexpected = set(techniques[labels == 1].tolist()) - known
    if unexpected:
        raise ValueError(f"unexpected attack techniques: {sorted(unexpected)}")
    calibration = sessions == ids[4]
    normal_calibration = calibration & (labels == 0)
    test = sessions == ids[5]
    if not np.any(normal_calibration):
        raise ValueError("calibration session has no normal rows")
    if set(labels[test].tolist()) != {0, 1}:
        raise ValueError("test needs normal and attack rows")
    for group, targets in GROUPS.items():
        if not np.any(test & (labels == 1) & np.isin(techniques, targets)):
            raise ValueError(f"{group}: test has no target attack rows")
    normal_training = {}
    for regime, n_sessions in REGIMES.items():
        selected = np.isin(sessions, ids[:n_sessions]) & (labels == 0)
        if not np.any(selected):
            raise ValueError(f"{regime}: training has no normal rows")
        normal_training[regime] = selected

    source_dir = Path(__file__).resolve().parent
    sources = (Path(__file__).name, "evaluate_event_time.py", "evaluate_unseen_groups.py",
               "feature_schema.py", "aggregate.py")
    result = {
        "protocol": PROTOCOL, "split_ids": split, "session_partitions_disjoint": True,
        "versions": {"numpy": np.__version__, "sklearn": sklearn.__version__},
        "source_sha256": {name: hashlib.sha256((source_dir / name).read_bytes()).hexdigest() for name in sources},
        "input_sha256": {str(Path(path).resolve()): hashlib.sha256(Path(path).read_bytes()).hexdigest()
                         for path in sorted(paths, key=str)},
        "calibration_normal_rows_used": summarize(labels[normal_calibration], techniques[normal_calibration]),
        "calibration_attack_rows_excluded": summarize(labels[calibration & (labels == 1)], techniques[calibration & (labels == 1)]),
        "regimes": {},
    }
    for regime, normal_train in normal_training.items():
        train_attacks = np.isin(sessions, ids[:REGIMES[regime]]) & (labels == 1)
        model = IsolationForest(**PROTOCOL["isolation_forest"]).fit(X[normal_train])
        normal_scores = -model.score_samples(X[normal_calibration])
        threshold = normal_cutoff(normal_scores, TARGET_FPR)
        scores = -model.score_samples(X[test])
        hits = scores >= threshold
        test_labels, test_techniques = labels[test], techniques[test]
        groups = {}
        for group, targets in GROUPS.items():
            selected = (test_labels == 0) | np.isin(test_techniques, targets)
            groups[group] = {"target_techniques": list(targets),
                             "test_rows": summarize(test_labels[selected], test_techniques[selected]),
                             **counts(test_labels[selected], hits[selected], test_techniques[selected])}
        result["regimes"][regime] = {
            "training_session_ids": ids[:REGIMES[regime]],
            "training_normal_rows_used": summarize(labels[normal_train], techniques[normal_train]),
            "training_attack_rows_excluded": summarize(labels[train_attacks], techniques[train_attacks]),
            "threshold": threshold, "calibration_normal_fpr": float(np.mean(normal_scores >= threshold)),
            "test_rows": summarize(test_labels, test_techniques),
            "held_out_test": counts(test_labels, hits, test_techniques), "groups": groups,
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("npz", nargs="*", help="exactly six single-session NPZ files")
    parser.add_argument("--protocol-only", action="store_true", help="print the fixed protocol before predictions")
    args = parser.parse_args()
    if args.protocol_only and args.npz:
        parser.error("--protocol-only does not take NPZ inputs")
    try:
        result = PROTOCOL if args.protocol_only else evaluate(args.npz)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
