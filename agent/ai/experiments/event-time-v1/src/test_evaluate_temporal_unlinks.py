"""Runnable fixed-protocol/history/join checks with estimator stand-ins."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import ModuleType
from unittest.mock import patch

import numpy as np

if importlib.util.find_spec("sklearn") is None:
    sklearn = ModuleType("sklearn")
    sklearn.__version__ = "test-stand-in"
    ensemble = ModuleType("sklearn.ensemble")
    ensemble.RandomForestClassifier = ensemble.IsolationForest = object
    sklearn.ensemble = ensemble
    sys.modules.update({"sklearn": sklearn, "sklearn.ensemble": ensemble})

import sklearn
import evaluate_event_time as shared
import evaluate_temporal_unlinks as evaluator
from archive_raw_capture import _identity


def test():
    fits, scored = [], []

    class Forest:
        def __init__(self, **params):
            self.anomaly = "contamination" in params
            assert params == evaluator.PROTOCOL["isolation_forest" if self.anomaly else "rf"]
            self.classes_ = [0, 1]

        def fit(self, X, y=None):
            assert np.all(X[:, 0] < 4)
            if self.anomaly:
                assert np.all(X[:, 2] == 0)
            else:
                assert np.array_equal(y, X[:, 2])
            fits.append(X.copy())
            return self

        def score_samples(self, X):
            scored.append(X.copy())
            assert np.all(X[:, 0] == (4 if len(scored) % 2 else 5))
            if len(scored) % 2:
                assert np.all(X[:, 2] == 0)
            # Two test false positives exercise both normal-history contexts.
            return -np.where((X[:, 0] == 5) & np.isin(X[:, 1], [59, 61]), 1, X[:, 2]).astype(float)

        def predict_proba(self, X):
            score = -self.score_samples(X)
            return np.column_stack((1 - score, score))

    with TemporaryDirectory() as directory:
        root = Path(directory)
        paths = [root / f"{sid}.npz" for sid in "ABCDEF"]
        audit_paths = [root / f"{sid}.json" for sid in "ABCDEF"]
        targets = [t for ts in evaluator.GROUPS.values() for t in ts]
        times = [0, 59]
        labels = ["normal", "normal"]
        techniques = ["work", "work"]
        for i, technique in enumerate(targets):
            times += [60 + i * 120, 61 + i * 120, 119 + i * 120, 120 + i * 120]
            labels += ["attack", "normal", "normal", "normal"]
            techniques += [technique, "work", "work", "work"]
        order = np.arange(len(times))[::-1]  # No assumption of ascending NPZ or audit rows.
        times = np.array(times, dtype=np.int64)[order]
        labels = np.array(labels)[order]
        techniques = np.array(techniques)[order]
        audits = []
        for index, sid in enumerate("ABCDEF"):
            X = np.zeros((len(times), 31))
            X[:, 0], X[:, 1], X[:, 2] = index, times, labels == "attack"
            np.savez(paths[index], X=X, names=np.array(evaluator.FEATURES), labels=labels,
                     techniques=techniques, sessions=np.array([sid] * len(times)), bucket_ns=times * 10**9)
            rows = [{"bucket_ns": int(t * 10**9), "label": str(label), "technique": str(tech),
                     "unlink_attempts": 2, "unique_directory_scopes": 1, "unknown_scope_attempts": 0}
                    for t, label, tech in zip(times, labels, techniques)]
            audit = {"session_id": sid, "bucket_ns": 10**9, "npz_buckets": len(times),
                     "npz": str(paths[index]), "source_stat": {str(paths[index]): list(_identity(paths[index].stat()))},
                     "npz_sha256": evaluator.sha(paths[index]),
                     "buckets": rows[::2] + rows[1::2], "dropped_outside_npz": 0,
                     "matched_unlink_attempts": 2 * len(times), "matched_unknown_scope_attempts": 0,
                     "recorded_file_unlink": 2 * len(times), "expected_file_unlink": 2 * len(times)}
            audits.append(audit)
            audit_paths[index].write_text(json.dumps(audit))

        def run():
            fits.clear()
            scored.clear()
            with patch.object(sklearn.ensemble, "IsolationForest", Forest), patch.object(shared, "RandomForestClassifier", Forest):
                return evaluator.evaluate(paths[::-1], audit_paths[::-1])

        def eligible(forbidden):
            return np.array([t >= 59 and not any(t - 59 <= attack <= t for attack in times[forbidden])
                             for t in times])

        def training_rows(local_mask):
            return np.concatenate([np.column_stack((np.full(np.count_nonzero(local_mask), i),
                                                   times[local_mask], (labels[local_mask] == "attack")))
                                   for i in range(4)])

        result = run()
        assert len(fits) == 10 and len(scored) == 20
        clean = eligible(labels == "attack")
        normal_mask = (labels == "normal") & clean
        assert np.array_equal(fits[0][:, :3], training_rows(normal_mask))
        for group_index, (group, excluded) in enumerate(evaluator.GROUPS.items()):
            forbidden = (labels == "attack") & np.isin(techniques, excluded)
            retained = ~forbidden & eligible(forbidden)
            first = 2 + group_index * 2
            assert np.array_equal(fits[first][:, :3], training_rows(retained))
            metrics = result["group_heldout"][group]
            assert metrics["training_retained_history_excluded"]["total"] == 4 * 2 * len(excluded)
            assert metrics["arms"]["baseline26"]["tn"] == np.count_nonzero((labels == "normal") & (times >= 59)) - 2
        for i in range(0, 10, 2):
            assert fits[i].shape[1] == 26 and fits[i + 1].shape[1] == 34
            assert np.array_equal(fits[i], fits[i + 1][:, :26])
            assert np.array_equal(scored[2 * i], scored[2 * i + 2][:, :26])
            assert np.array_equal(scored[2 * i + 1], scored[2 * i + 3][:, :26])
            assert np.array_equal(scored[2 * i][:, 1], times[normal_mask])
        assert result["normal_only"]["baseline26"]["total"] == len(times) - 1
        assert result["calibration_normal_history_excluded"]["total"] == 12
        assert result["calibration_normal_rows_used"]["total"] == 7
        assert result["warmup_excluded"]["F"]["total"] == 1
        metrics = list(result["normal_only"].values()) + [
            arm for group in result["group_heldout"].values() for arm in group["arms"].values()]
        for row in metrics:
            breakdown = row["normal_context_breakdown"]
            assert breakdown == {"clean_history": {"total": 7, "fp": 1, "fpr": 1 / 7},
                                 "past_attack_overlap": {"total": 12, "fp": 1, "fpr": 1 / 12}}
            assert sum(c["total"] for c in breakdown.values()) == row["tn"] + row["fp"]
            assert sum(c["fp"] for c in breakdown.values()) == row["fp"]
            assert row["fpr"] == 2 / 19
        assert "after the first result" in result["protocol"]["normal_context_breakdown_note"]
        for sid in "ABCDEF":
            assert result["audit_source_stat"][sid] == audits["ABCDEF".index(sid)]["source_stat"]
        for name, digest in result["source_sha256"].items():
            assert digest == evaluator.sha(Path(evaluator.__file__).parent / name)

        # Mutating a future test bucket leaves all earlier joined inputs and all fits/calibration unchanged.
        previous_fits, previous_scores = copy.deepcopy(fits), copy.deepcopy(scored)
        old = evaluator.join_audit(audits[5], "F", times * 10**9, labels, techniques)
        future = max(audits[5]["buckets"], key=lambda r: r["bucket_ns"])
        future["unlink_attempts"] += 10
        for key in ("matched_unlink_attempts", "recorded_file_unlink", "expected_file_unlink"):
            audits[5][key] += 10
        new = evaluator.join_audit(audits[5], "F", times * 10**9, labels, techniques)
        assert np.array_equal(old[times < times.max()], new[times < times.max()])
        audit_paths[5].write_text(json.dumps(audits[5]))
        run()
        assert all(np.array_equal(a, b) for a, b in zip(previous_fits, fits))
        assert all(np.array_equal(previous_scores[i], scored[i]) for i in range(0, 20, 2))

        def rejected(mutator, message):
            broken = copy.deepcopy(audits[4])
            mutator(broken)
            audit_paths[4].write_text(json.dumps(broken))
            try:
                run()
            except ValueError as exc:
                assert message in str(exc), str(exc)
            else:
                raise AssertionError("accepted bad join/history")
            assert not fits and not scored
            audit_paths[4].write_text(json.dumps(audits[4]))

        rejected(lambda a: a.update(session_id="D"), "audit session ID")
        rejected(lambda a: a["buckets"][0].update(bucket_ns=a["buckets"][1]["bucket_ns"]), "duplicate audit")
        rejected(lambda a: a["buckets"][0].update(bucket_ns=9999 * 10**9), "exact bucket join")
        rejected(lambda a: a["buckets"][0].update(label="wrong"), "label or technique")
        rejected(lambda a: a["buckets"][0].update(technique="wrong"), "label or technique")
        rejected(lambda a: a.update(matched_unlink_attempts=0), "unlink count mismatch")
        rejected(lambda a: a.pop("npz_sha256"), "64-hex npz_sha256")
        rejected(lambda a: a.update(npz_sha256="bad"), "64-hex npz_sha256")
        rejected(lambda a: a.update(npz_sha256="g" * 64), "64-hex npz_sha256")
        rejected(lambda a: a.update(npz_sha256="0" * 64), "source hash mismatch")
        # No clean normals: all normal timestamps lie within 59 seconds of an attack.
        with np.load(paths[4], allow_pickle=False) as data:
            payload = dict(data)
        changed_labels = np.where(times == 0, "attack", labels)
        payload["labels"] = changed_labels
        payload["techniques"] = np.where(times == 0, targets[0], techniques)
        # Also contaminate every otherwise-clean normal at its own bucket.
        payload["labels"] = np.where(clean, "attack", payload["labels"])
        payload["techniques"] = np.where(clean, targets[0], payload["techniques"])
        np.savez(paths[4], **payload)
        for row in audits[4]["buckets"]:
            i = np.flatnonzero(times * 10**9 == row["bucket_ns"])[0]
            row.update(label=str(payload["labels"][i]), technique=str(payload["techniques"][i]))
        audits[4]["source_stat"][str(paths[4])] = list(_identity(paths[4].stat()))
        audits[4]["npz_sha256"] = evaluator.sha(paths[4])
        audit_paths[4].write_text(json.dumps(audits[4]))
        try:
            run()
        except ValueError as exc:
            assert "no clean-history normal" in str(exc)
        else:
            raise AssertionError("relaxed calibration history rule")
        assert not fits and not scored


if __name__ == "__main__":
    test()
    print("temporal evaluator exact join/history purge/arm parity/future mutation checks passed (estimator stand-ins)")
