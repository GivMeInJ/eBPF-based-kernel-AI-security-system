#!/usr/bin/env python3
"""Offline, nested session holdout comparison on simulated event-time bucket labels."""

import argparse
import json
import math
import os
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from feature_schema import STABLE_EXCLUDED, apply_feature_mask


EVALUATION_NOTE = "Simulated event-time bucket labels; DR/FPR are bucket-level, not incident-level."
DEPLOYED_REPLAY_NOTE = (
    "Old model replay uses all raw columns, including filesystem state at feature extraction; "
    "these are not verified live metrics."
)


def attack_scores(model, X):
    classes = list(model.classes_)
    return (model.predict_proba(X)[:, classes.index(1)] if 1 in classes
            else np.zeros(len(X)))


def fit_rf(X, labels):
    return RandomForestClassifier(n_estimators=300, max_features="sqrt",
                                  class_weight="balanced", random_state=42).fit(X, labels)


def normal_cutoff(scores, target_fpr):
    """Smallest score cutoff with empirical calibration FPR <= target_fpr."""
    if not len(scores):
        raise ValueError("no normal out-of-fold scores for threshold selection")
    ordered = np.sort(scores)
    allowed_fp = math.floor(target_fpr * len(ordered))
    return float(np.nextafter(ordered[-allowed_fp - 1], np.inf))


def counts(labels, predicted, techniques):
    attack = labels == 1
    tp = int(np.count_nonzero(attack & predicted))
    fp = int(np.count_nonzero(~attack & predicted))
    tn = int(np.count_nonzero(~attack & ~predicted))
    fn = int(np.count_nonzero(attack & ~predicted))
    by_technique = {}
    for name in sorted(set(techniques[attack])):
        selected = attack & (techniques == name)
        found = int(np.count_nonzero(selected & predicted))
        total = int(np.count_nonzero(selected))
        by_technique[name] = {"total": total, "tp": found, "fn": total - found,
                              "dr": found / total}
    false_positive_by_technique = {}
    for name in sorted(set(techniques[~attack])):
        selected = ~attack & (techniques == name)
        false_positive_by_technique[name] = {
            "total": int(np.count_nonzero(selected)),
            "fp": int(np.count_nonzero(selected & predicted))}
    return {"dr": tp / (tp + fn) if tp + fn else None,
            "fpr": fp / (fp + tn) if fp + tn else None,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "total": len(labels), "per_technique": by_technique,
            "false_positive_by_technique": false_positive_by_technique}


def read_data(paths, excluded, single_session_files=False):
    minimum = 4 if single_session_files else 3
    if len(paths) < minimum:
        raise ValueError(f"at least {minimum} event_time NPZ files are required")
    parts = []
    expected_names = None
    seen_sessions = set()
    for path in paths:
        with np.load(path, allow_pickle=False) as data:
            X, labels, techniques, sessions, names = (
                data[key] for key in ("X", "labels", "techniques", "sessions", "names"))
        if names.ndim != 1 or not len(names) or X.ndim != 2 or X.shape[1] != len(names):
            raise ValueError(f"{path}: invalid feature shape or names")
        if expected_names is None:
            expected_names = names.tolist()
        elif names.tolist() != expected_names:
            raise ValueError(f"{path}: feature name/order mismatch")
        if any(a.ndim != 1 or len(a) != len(X) for a in (labels, techniques, sessions)):
            raise ValueError(f"{path}: X and label array lengths differ")
        if not np.isfinite(X).all() or not np.isin(labels, ("normal", "attack")).all():
            raise ValueError(f"{path}: invalid features or labels")
        if not np.all(sessions != "") or not np.all(techniques != ""):
            raise ValueError(f"{path}: empty session or technique")
        if single_session_files:
            file_sessions = set(sessions.tolist())
            if len(file_sessions) != 1:
                raise ValueError(f"{path}: export requires one session per NPZ file")
            if seen_sessions & file_sessions:
                raise ValueError(f"{path}: overlapping session partitions")
            seen_sessions.update(file_sessions)
        keep = ~np.isin(techniques, tuple(excluded))
        parts.append((X[keep], labels[keep] == "attack", techniques[keep], sessions[keep]))
    X, labels, techniques, sessions = (np.concatenate([part[i] for part in parts])
                                       for i in range(4))
    if len(np.unique(sessions)) < minimum:
        raise ValueError(f"at least {minimum} sessions must remain after exclusions")
    # RF bootstrap indices depend on row order; preserve rows within each session.
    order = np.argsort(sessions, kind="stable")
    X, labels, techniques, sessions = (a[order] for a in (X, labels, techniques, sessions))
    return X, labels.astype(int), techniques, sessions, expected_names


def export_candidate_model(X, labels, techniques, sessions, names, excluded, target_fpr,
                           directory):
    """Fit once; calibration and test sessions never enter candidate training."""
    import joblib
    import sklearn

    directory = Path(directory)
    if directory.exists():
        raise FileExistsError(f"candidate directory already exists: {directory}")
    ids = sorted(np.unique(sessions).tolist())
    if len(ids) < 4:
        raise ValueError("candidate export requires at least 4 unique sessions")
    split_ids = {"training": ids[:-2], "calibration": [ids[-2]], "test": [ids[-1]]}
    train = np.isin(sessions, split_ids["training"])
    calibration = sessions == ids[-2]
    test = sessions == ids[-1]
    normal_calibration = calibration & (labels == 0)
    if set(labels[train].tolist()) != {0, 1}:
        raise ValueError("candidate training must contain both normal and attack buckets")
    if not np.any(normal_calibration):
        raise ValueError("candidate calibration session has no normal buckets")
    model = fit_rf(X[train], labels[train])
    scores = attack_scores(model, X[normal_calibration])
    threshold = normal_cutoff(scores, target_fpr)
    sample_counts = {}
    for name, selected in (("training", train), ("calibration", calibration), ("test", test)):
        attack = int(np.count_nonzero(labels[selected]))
        total = int(np.count_nonzero(selected))
        sample_counts[name] = {"total": total, "normal": total - attack, "attack": attack}
    meta = {
        "kind": "bucket", "bucket_sec": 1.0, "feature_names": names,
        "excluded_features": excluded, "feature_schema": "event_time_stable_v1",
        "threshold": threshold, "target_fpr": target_fpr, "split_ids": split_ids,
        "versions": {"numpy": np.__version__, "sklearn": sklearn.__version__,
                     "joblib": joblib.__version__}, "sample_counts": sample_counts,
        "calibration": {"normal_buckets_used": len(scores),
                        "normal_fpr": float(np.mean(scores >= threshold)),
                        "threshold_source": "calibration-session normal scores only"},
        "held_out_test": {"threshold": threshold,
                          **counts(labels[test], attack_scores(model, X[test]) >= threshold,
                                   techniques[test])},
        "note": EVALUATION_NOTE,
    }
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    with os.fdopen(os.open(directory / "bucket_model.pkl",
                           os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        joblib.dump(model, stream)
    with os.fdopen(os.open(directory / "meta.json",
                           os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w",
                   encoding="utf-8") as stream:
        json.dump(meta, stream, ensure_ascii=False, indent=2)
    return meta


def evaluate(paths, target_fpr=0.01, exclude_techniques=(), model_dir=None,
             excluded_features=STABLE_EXCLUDED, export_candidate=None):
    if not 0 <= target_fpr < 1 or not math.isfinite(target_fpr):
        raise ValueError("target FPR must be finite and in [0, 1)")
    X, labels, techniques, sessions, names = read_data(
        paths, exclude_techniques, single_session_files=export_candidate is not None)
    excluded = [name for name in names if name in excluded_features]
    masked_X = apply_feature_mask(X, names, excluded)
    deployed = None
    if model_dir is not None:
        import joblib

        model_dir = Path(model_dir)
        with (model_dir / "meta.json").open(encoding="utf-8") as stream:
            meta = json.load(stream)
        if meta["feature_names"] != names:
            raise ValueError("deployed model feature name/order mismatch")
        deployed = joblib.load(model_dir / "bucket_model.pkl")
        if deployed.n_features_in_ != len(names) or list(deployed.classes_) != [0, 1]:
            raise ValueError("deployed model feature count or class order mismatch")

    result = {"note": EVALUATION_NOTE, "target_fpr": target_fpr,
              "excluded_techniques": sorted(set(exclude_techniques)),
              "excluded_features": excluded}
    if deployed is not None:
        result["deployed_replay_note"] = DEPLOYED_REPLAY_NOTE
    if export_candidate is not None:
        meta = export_candidate_model(masked_X, labels, techniques, sessions, names,
                                      excluded, target_fpr, export_candidate)
        row = {"session": meta["split_ids"]["test"][0], "new_rf": meta["held_out_test"]}
        if deployed is not None:
            test = sessions == row["session"]
            row["deployed_rf"] = {"threshold": 0.67,
                                  **counts(labels[test], attack_scores(deployed, X[test]) >= 0.67,
                                           techniques[test])}
        return {**result, "candidate_dir": str(export_candidate), "candidate": meta,
                "sessions": [row]}

    results = []
    for held_out in sorted(np.unique(sessions)):
        train = sessions != held_out
        test = ~train
        normal_oof = []
        for inner in np.unique(sessions[train]):
            inner_train = train & (sessions != inner)
            inner_normal = train & (sessions == inner) & (labels == 0)
            if np.any(inner_normal):
                model = fit_rf(masked_X[inner_train], labels[inner_train])
                normal_oof.append(attack_scores(model, masked_X[inner_normal]))
        if not normal_oof:
            raise ValueError(f"{held_out}: no training-session normal buckets")
        threshold = normal_cutoff(np.concatenate(normal_oof), target_fpr)
        fresh = fit_rf(masked_X[train], labels[train])
        row = {"session": str(held_out),
               "new_rf": {"threshold": threshold,
                          **counts(labels[test], attack_scores(fresh, masked_X[test]) >= threshold,
                                   techniques[test])}}
        if deployed is not None:
            row["deployed_rf"] = {"threshold": 0.67,
                                  **counts(labels[test], attack_scores(deployed, X[test]) >= 0.67,
                                           techniques[test])}
        results.append(row)
    return {**result, "sessions": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("npz", nargs="+", help="three or more event_time NPZ files")
    parser.add_argument("--model-dir", help="optional deployed model directory")
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument("--export-candidate", metavar="DIR",
                        help="export candidate using >=4 single-session files; sorted final two "
                             "sessions are calibration and held-out test; refuse overwrite")
    parser.add_argument("--exclude-techniques", nargs="+", default=[], metavar="NAME",
                        help="exact technique names to remove before fitting or evaluation")
    args = parser.parse_args()
    try:
        result = evaluate(args.npz, args.target_fpr, args.exclude_techniques, args.model_dir,
                          export_candidate=args.export_candidate)
    except (OSError, KeyError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
