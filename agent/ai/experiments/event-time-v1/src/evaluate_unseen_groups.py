#!/usr/bin/env python3
"""Fixed leave-attack-group-out diagnostic on six single-session event-time NPZs."""
import argparse
from collections import Counter
import json

import numpy as np

from aggregate import FEATURES
from feature_schema import STABLE_EXCLUDED, apply_feature_mask


GROUPS = {
    "exfiltration": ("bulk_exfil", "dns_exfil"),
    "destructive_files": ("ransom_sim", "wiper_sim"),
    "remote_shell": ("reverse_shell",),
    "resource_abuse": ("resource_hijack",),
}
TARGET_FPR = 0.005
REGIMES = {"v1_like_first2": 2, "v2_like_all4": 4}
PROTOCOL = {
    "protocol": "event_time_leave_attack_group_out_v1",
    "groups": GROUPS,
    "session_split": "Exactly six unique sessions sorted by ID: first four form the training pool, penultimate calibrates, last tests.",
    "training_regimes": REGIMES,
    "training": "Remove every target-group attack row; fit only retained training-session rows.",
    "calibration": "Use only calibration-session normal rows; exclude all calibration attacks.",
    "test": "Use all test-session normals and only target-group attacks; never tune on test rows.",
    "rf": {"n_estimators": 300, "max_features": "sqrt", "class_weight": "balanced", "random_state": 42},
    "target_fpr": TARGET_FPR,
    "raw_feature_names": FEATURES,
    "excluded_features": list(STABLE_EXCLUDED),
    "projected_features": 26,
    "note": "Controlled local dummy leave-attack-group-out evaluation; not proof of unknown real-world zero-day detection. DR/FPR are bucket-level, not incident-level. Previously inspected sessions are not an untouched blind test. Both regimes omit the target group; the deployed RF that saw all attack types is not an unseen baseline. No model export or deployment.",
}


def summarize(labels, techniques):
    return {"total": len(labels),
            "label_counts": {"normal": int(np.count_nonzero(labels == 0)),
                             "attack": int(np.count_nonzero(labels == 1))},
            "technique_counts": dict(sorted(Counter(techniques.tolist()).items()))}


def evaluate(paths):
    from evaluate_event_time import read_data, fit_rf, normal_cutoff, attack_scores, counts

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
    train_ids, cal_ids, test_ids = (set(split[key]) for key in ("training", "calibration", "test"))
    if train_ids & cal_ids or train_ids & test_ids or cal_ids & test_ids:
        raise ValueError("overlapping session partitions")
    known = {tech for group in GROUPS.values() for tech in group}
    unexpected = set(techniques[labels == 1].tolist()) - known
    if unexpected:
        raise ValueError(f"unexpected attack techniques: {sorted(unexpected)}")
    calibration = sessions == ids[4]
    normal_calibration = calibration & (labels == 0)
    test_session = sessions == ids[5]
    if not np.any(normal_calibration):
        raise ValueError("calibration session has no normal rows")

    # Validate every group before any fitting or scoring.
    selections = {}
    for group, targets in GROUPS.items():
        target_attack = (labels == 1) & np.isin(techniques, targets)
        test = test_session & ((labels == 0) | target_attack)
        if set(labels[test].tolist()) != {0, 1}:
            raise ValueError(f"{group}: test needs normal and target attack rows")
        selections[group] = {}
        for regime, n_sessions in REGIMES.items():
            train = np.isin(sessions, ids[:n_sessions])
            removed = train & target_attack
            retained = train & ~target_attack
            if np.any(np.isin(techniques[retained], targets)):
                raise ValueError(f"{group}/{regime}: target technique remains in training")
            if set(labels[retained].tolist()) != {0, 1}:
                raise ValueError(f"{group}/{regime}: retained training needs normal and other attack rows")
            selections[group][regime] = (removed, retained, test)

    result = {"protocol": PROTOCOL, "split_ids": split, "session_partitions_disjoint": True,
              "calibration_normal_rows_used": summarize(labels[normal_calibration], techniques[normal_calibration]),
              "calibration_attack_rows_excluded": summarize(labels[calibration & (labels == 1)], techniques[calibration & (labels == 1)]),
              "groups": {}}
    for group, regimes in selections.items():
        result["groups"][group] = {"target_techniques": list(GROUPS[group]), "regimes": {}}
        for regime, (removed, retained, test) in regimes.items():
            model = fit_rf(X[retained], labels[retained])
            normal_scores = attack_scores(model, X[normal_calibration])
            threshold = normal_cutoff(normal_scores, TARGET_FPR)
            hits = attack_scores(model, X[test]) >= threshold
            result["groups"][group]["regimes"][regime] = {
                "training_session_ids": ids[:REGIMES[regime]], "target_absent_from_training": True,
                "training_removed": summarize(labels[removed], techniques[removed]),
                "training_retained": summarize(labels[retained], techniques[retained]),
                "test_rows": summarize(labels[test], techniques[test]),
                "test_other_attack_rows_excluded": int(np.count_nonzero(test_session & ~test)),
                "threshold": threshold, "calibration_normal_fpr": float(np.mean(normal_scores >= threshold)),
                **counts(labels[test], hits, techniques[test]),
            }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("npz", nargs="*", help="exactly six single-session NPZ files")
    parser.add_argument("--protocol-only", action="store_true", help="print the fixed protocol before evaluating")
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
