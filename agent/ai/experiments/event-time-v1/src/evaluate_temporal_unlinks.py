#!/usr/bin/env python3
"""Fixed exploratory temporal unlink comparison; no export or live changes."""
import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from archive_raw_capture import _identity
from aggregate import FEATURES
from evaluate_normal_only import PROTOCOL as NORMAL_PROTOCOL
from evaluate_unseen_groups import GROUPS, PROTOCOL as RF_PROTOCOL, TARGET_FPR, summarize
from feature_schema import STABLE_EXCLUDED, apply_feature_mask
from temporal_unlinks import TEMPORAL_NAMES

PROTOCOL = {
    "protocol": "event_time_temporal_unlinks_v1",
    "session_split": "Exactly six single-session NPZ/audit pairs, sorted session IDs: first four train, fifth calibrates, sixth tests.",
    "arms": {"baseline26": 26, "augmented34": 34},
    "temporal_feature_names": list(TEMPORAL_NAMES),
    "temporal": "Per session, label-free and before joining: current log1p unlink attempts/directory scopes; log1p sum attempts and active-second fraction in inclusive causal 5/30/60-second windows. Never reset on label, technique or unit.",
    "history_seconds": 60,
    "outside_npz_unlinks": "Require zero: incomplete history fails closed.",
    "warmup": "Exclude b < session minimum bucket + 59 seconds in both arms.",
    "normal_only_training": "First four sessions: normals only, excluding ANY row whose inclusive [b-59s,b] history contains ANY attack bucket.",
    "calibration": "Fifth-session normals with no ANY-attack bucket in inclusive [b-59s,b]; fail if none remain, never relax the rule.",
    "normal_only_test": "All warmed-up sixth-session rows; no label-based history purge.",
    "rf_training": "Four semantic group-heldout diagnostics: first four sessions, remove target attacks and purge every retained row whose inclusive [b-59s,b] history contains an excluded-group attack bucket.",
    "rf_test": "All warmed-up test normals plus target-group attacks; no label-based history purge.",
    "identical_rows": "Both arms share exactly the same training, calibration and test masks for each diagnostic.",
    "isolation_forest": NORMAL_PROTOCOL["isolation_forest"],
    "rf": RF_PROTOCOL["rf"], "target_fpr": TARGET_FPR, "groups": GROUPS,
    "raw_feature_names": FEATURES, "excluded_features": list(STABLE_EXCLUDED),
    "normal_context_breakdown_note": "Added after the first result for post-hoc error analysis, not tuning. Reuses unchanged test predictions; clean-history versus past-attack-overlap normal rows are descriptive contexts, never test filters. The comparison is exploratory, not a pre-registered blind test.",
    "note": "Fixed before predictions; no tuning from results. Previously inspected controlled dummy corpus, exploratory bucket-level metrics, not a blind test or proof of real-world zero-day detection. Missing NPZ seconds contribute no observed unlink activity; any outside-NPZ unlink attempt fails closed because history would be incomplete. No export, deployment or live collection.",
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def join_audit(audit, session, buckets, labels, techniques):
    """Validate a bijection, then return temporal values in NPZ row order."""
    from temporal_unlinks import temporal_features

    if audit["session_id"] != session or audit["bucket_ns"] != 1_000_000_000:
        raise ValueError("audit session ID/bucket width mismatch")
    rows = audit["buckets"]
    if audit["npz_buckets"] != len(buckets) or len(rows) != len(buckets):
        raise ValueError("audit/NPZ bucket count mismatch")
    if (buckets.ndim != 1 or buckets.dtype.kind not in "iu" or np.any(buckets < 0)
            or np.any(buckets % 1_000_000_000) or len(np.unique(buckets)) != len(buckets)):
        raise ValueError("invalid/duplicate NPZ bucket_ns")
    index = {}
    for i, row in enumerate(rows):
        bucket = row["bucket_ns"]
        if type(bucket) is not int or bucket < 0 or bucket % 1_000_000_000 or bucket in index:
            raise ValueError("invalid/duplicate audit bucket_ns")
        index[bucket] = i
        for field in ("unlink_attempts", "unique_directory_scopes", "unknown_scope_attempts"):
            if type(row[field]) is not int or row[field] < 0:
                raise ValueError(f"invalid audit {field}")
        if row["unique_directory_scopes"] + row["unknown_scope_attempts"] > row["unlink_attempts"]:
            raise ValueError("audit scopes exceed unlink attempts")
    if set(index) != set(buckets.tolist()):
        raise ValueError("audit/NPZ exact bucket join mismatch")
    order = [index[int(b)] for b in buckets]
    for i, j in enumerate(order):
        if rows[j]["label"] != labels[i] or rows[j]["technique"] != techniques[i]:
            raise ValueError("audit/NPZ label or technique mismatch")
    attempts = sum(row["unlink_attempts"] for row in rows)
    unknown = sum(row["unknown_scope_attempts"] for row in rows)
    if (audit["matched_unlink_attempts"] != attempts or
            audit["recorded_file_unlink"] != audit["expected_file_unlink"] or
            audit["recorded_file_unlink"] != attempts + audit["dropped_outside_npz"] or
            audit["matched_unknown_scope_attempts"] != unknown):
        raise ValueError("audit unlink count mismatch")
    temporal = temporal_features(audit)  # Whole session, before any row selection.
    if temporal.shape != (len(rows), 8) or not np.isfinite(temporal).all():
        raise ValueError("expected eight finite temporal features per audit bucket")
    return temporal[order]


def evaluate(paths, audit_paths):
    import sklearn
    from sklearn.ensemble import IsolationForest
    from evaluate_event_time import read_data, fit_rf, normal_cutoff, attack_scores, counts
    from temporal_unlinks import HISTORY_SECONDS, TEMPORAL_NAMES, history_clean

    if len(paths) != 6 or len(audit_paths) != 6:
        raise ValueError("exactly six NPZs and six audit JSONs are required")
    if HISTORY_SECONDS != 60 or len(TEMPORAL_NAMES) != 8:
        raise ValueError("temporal API must provide fixed 60-second history/eight features")
    inputs = [Path(p) for p in (*paths, *audit_paths)]
    snapshots = {str(p.resolve()): list(_identity(p.stat())) for p in inputs}
    hashes = {str(p.resolve()): sha(p) for p in inputs}
    X, labels, techniques, sessions, names = read_data(paths, (), single_session_files=True)
    if names != FEATURES or len(names) != 31:
        raise ValueError("expected exact 31 raw feature names/order")
    baseline = apply_feature_mask(X, names, STABLE_EXCLUDED)
    ids = sorted(np.unique(sessions).tolist())
    if len(ids) != 6 or baseline.shape[1] != 26:
        raise ValueError("expected six unique sessions and 26 projected features")
    known = {t for group in GROUPS.values() for t in group}
    if set(techniques[labels == 1].tolist()) - known:
        raise ValueError("unexpected attack techniques")
    audits = {}
    for path in audit_paths:
        audit = json.loads(Path(path).read_text())
        sid = audit["session_id"]
        if sid in audits or sid not in ids:
            raise ValueError("duplicate/unknown audit session ID")
        audits[sid] = audit
    temporal = np.empty((len(X), 8))
    warmed = np.zeros(len(X), dtype=bool)
    clean = warmed.copy()
    group_clean = {g: warmed.copy() for g in GROUPS}
    for path in paths:
        with np.load(path, allow_pickle=False) as data:
            sid = str(data["sessions"][0])
            buckets = data["bucket_ns"]
            selected = sessions == sid
            if (not np.array_equal(data["labels"] == "attack", labels[selected]) or
                    not np.array_equal(data["techniques"], techniques[selected]) or
                    not np.array_equal(data["sessions"], sessions[selected]) or
                    not np.array_equal(apply_feature_mask(data["X"], data["names"], STABLE_EXCLUDED), baseline[selected])):
                raise ValueError("NPZ rows changed or timestamp load is misaligned")
            audit = audits[sid]
            # Audit paths may refer to the remote capture host; preserve those identities.
            identity = audit["source_stat"][audit["npz"]]
            if len(identity) != 5 or identity[2] != Path(path).stat().st_size:
                raise ValueError("audit NPZ source size mismatch")
            recorded_hash = audit.get("npz_sha256")
            if (not isinstance(recorded_hash, str) or len(recorded_hash) != 64 or
                    any(c not in "0123456789abcdefABCDEF" for c in recorded_hash)):
                raise ValueError("audit requires a 64-hex npz_sha256")
            if recorded_hash.lower() != hashes[str(Path(path).resolve())]:
                raise ValueError("audit NPZ source hash mismatch")
            temporal[selected] = join_audit(audit, sid, buckets, data["labels"], data["techniques"])
        local_labels, local_techniques = labels[selected], techniques[selected]
        warmed[selected] = history_clean(buckets, local_labels, np.zeros(len(buckets), dtype=bool))
        clean[selected] = history_clean(buckets, local_labels, local_labels == 1)
        for group, targets in GROUPS.items():
            forbidden = (local_labels == 1) & np.isin(local_techniques, targets)
            group_clean[group][selected] = history_clean(buckets, local_labels, forbidden)
    arms = {"baseline26": baseline, "augmented34": np.column_stack((baseline, temporal))}
    pool = np.isin(sessions, ids[:4])
    calibration = sessions == ids[4]
    test_session = sessions == ids[5]
    cal_candidates = calibration & (labels == 0)
    cal = cal_candidates & clean
    normal_candidates = pool & (labels == 0)
    normal_train = normal_candidates & clean
    full_test = test_session & warmed
    if not np.any(cal):
        raise ValueError("calibration has no clean-history normal rows; rule not relaxed")
    if not np.any(normal_train):
        raise ValueError("training has no clean-history normal rows; rule not relaxed")
    selections = {}
    for group, targets in GROUPS.items():
        target = (labels == 1) & np.isin(techniques, targets)
        retained = pool & ~target
        train = retained & group_clean[group]
        test = full_test & ((labels == 0) | target)
        if set(labels[train].tolist()) != {0, 1}:
            raise ValueError(f"{group}: purged training needs normal and other attack rows")
        if set(labels[test].tolist()) != {0, 1}:
            raise ValueError(f"{group}: warmed test needs normal and target attack rows")
        selections[group] = (train, test, retained, target)
    def summary(mask):
        return summarize(labels[mask], techniques[mask])

    source_dir = Path(__file__).resolve().parent
    sources = (Path(__file__).name, "temporal_unlinks.py", "evaluate_normal_only.py",
               "evaluate_unseen_groups.py", "evaluate_event_time.py", "feature_schema.py", "aggregate.py",
               "archive_raw_capture.py")
    result = {
        "protocol": PROTOCOL, "temporal_feature_names": list(TEMPORAL_NAMES),
        "split_ids": {"training": ids[:4], "calibration": [ids[4]], "test": [ids[5]]},
        "session_partitions_disjoint": True, "identical_arm_rows": True,
        "versions": {"numpy": np.__version__, "sklearn": sklearn.__version__},
        "source_sha256": {name: sha(source_dir / name) for name in sources},
        "input_sha256": hashes, "input_snapshots": snapshots,
        "audit_source_stat": {sid: audits[sid]["source_stat"] for sid in ids},
        "warmup_excluded": {sid: summary((sessions == sid) & ~warmed) for sid in ids},
        "calibration_normal_rows_used": summary(cal),
        "calibration_attack_rows_excluded": summary(calibration & (labels == 1)),
        "calibration_normal_warmup_excluded": summary(cal_candidates & ~warmed),
        "calibration_normal_history_excluded": summary(cal_candidates & warmed & ~clean),
        "training_normal_rows_used": summary(normal_train),
        "training_attack_rows_excluded": summary(pool & (labels == 1)),
        "training_normal_warmup_excluded": summary(normal_candidates & ~warmed),
        "training_normal_history_excluded": summary(normal_candidates & warmed & ~clean),
        "normal_input_sha256": {arm: {part: hashlib.sha256(np.ascontiguousarray(values[mask]).tobytes()).hexdigest()
                                      for part, mask in (("training", normal_train), ("calibration", cal))}
                                for arm, values in arms.items()},
        "normal_only": {}, "group_heldout": {},
    }
    def score(model, values, test, anomaly=False):
        scorer = (lambda v: -model.score_samples(v)) if anomaly else (lambda v: attack_scores(model, v))
        normal_scores = scorer(values[cal])
        threshold = normal_cutoff(normal_scores, TARGET_FPR)
        hits = scorer(values[test]) >= threshold
        normals = labels[test] == 0
        contexts = {"clean_history": normals & clean[test],
                    "past_attack_overlap": normals & ~clean[test]}
        breakdown = {}
        for context, selected in contexts.items():
            total = int(np.count_nonzero(selected))
            fp = int(np.count_nonzero(hits & selected))
            breakdown[context] = {"total": total, "fp": fp, "fpr": fp / total if total else None}
        return {"threshold": threshold, "calibration_normal_fpr": float(np.mean(normal_scores >= threshold)),
                "test_rows": summary(test), "normal_context_breakdown": breakdown,
                **counts(labels[test], hits, techniques[test])}, hits

    for arm, values in arms.items():
        model = IsolationForest(**PROTOCOL["isolation_forest"]).fit(values[normal_train])
        metrics, hits = score(model, values, full_test, anomaly=True)
        test_labels, test_techniques = labels[full_test], techniques[full_test]
        metrics["groups"] = {}
        for group, targets in GROUPS.items():
            selected = (test_labels == 0) | ((test_labels == 1) & np.isin(test_techniques, targets))
            metrics["groups"][group] = counts(test_labels[selected], hits[selected], test_techniques[selected])
        result["normal_only"][arm] = metrics
    for group, (train, test, retained, target) in selections.items():
        result["group_heldout"][group] = {
            "target_techniques": list(GROUPS[group]), "target_absent_from_training": True,
            "training_target_rows_excluded": summary(pool & target),
            "training_retained": summary(train),
            "training_retained_warmup_excluded": summary(retained & ~warmed),
            "training_retained_history_excluded": summary(retained & warmed & ~group_clean[group]),
            "test_other_attack_rows_excluded": summary(full_test & (labels == 1) & ~target),
            "arms": {arm: score(fit_rf(values[train], labels[train]), values, test)[0]
                     for arm, values in arms.items()},
        }
    if any(sha(p) != hashes[str(p.resolve())] or
           list(_identity(p.stat())) != snapshots[str(p.resolve())] for p in inputs):
        raise ValueError("input changed during evaluation")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("npz", nargs="*")
    parser.add_argument("--audits", nargs="+", default=[])
    parser.add_argument("--protocol-only", action="store_true", help="print fixed protocol before predictions")
    args = parser.parse_args()
    if args.protocol_only and (args.npz or args.audits):
        parser.error("--protocol-only takes no inputs")
    try:
        result = PROTOCOL if args.protocol_only else evaluate(args.npz, args.audits)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
