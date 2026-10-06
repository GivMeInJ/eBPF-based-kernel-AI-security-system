"""Runnable normal-only isolation/score-direction check using an estimator stand-in."""
import hashlib
import importlib.util
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
    ensemble.RandomForestClassifier = object
    ensemble.IsolationForest = object
    sklearn.ensemble = ensemble
    sys.modules.update({"sklearn": sklearn, "sklearn.ensemble": ensemble})

import sklearn
import evaluate_event_time as shared
import evaluate_normal_only as evaluator


def test():
    techniques = [tech for group in evaluator.GROUPS.values() for tech in group]
    fits, scored, cutoffs = [], [], []
    real_cutoff = shared.normal_cutoff

    class Forest:
        def __init__(self, **params):
            assert params == {"n_estimators": 300, "random_state": 42, "max_samples": "auto",
                              "max_features": 1.0, "bootstrap": False, "contamination": "auto", "n_jobs": 1}

        def fit(self, X):
            n_sessions = list(evaluator.REGIMES.values())[len(fits)]
            assert X.shape == (2 * n_sessions, 26)
            assert set(X[:, 0]) == set(range(n_sessions)) and np.all(X[:, 1] == 0)
            fits.append(X.copy())
            return self

        def score_samples(self, X):
            assert X.shape[1] == 26
            if set(X[:, 0]) == {4}:
                assert len(X) == 2 and np.all(X[:, 1] == 0)
            else:
                assert set(X[:, 0]) == {5} and len(X) == 389
                assert set(X[:, 1]) == set(range(7))
            scored.append(X.copy())
            return -X[:, 2]  # Lower raw score must produce a larger anomaly score.

    def checked_cutoff(scores, target_fpr):
        assert target_fpr == 0.005 and np.array_equal(scores, [0.1, 0.2])
        cutoffs.append(scores.copy())
        return real_cutoff(scores, target_fpr)

    with TemporaryDirectory() as directory:
        paths = [Path(directory) / f"{session}.npz" for session in "ABCDEF"]

        def write(index, attack_value=0.9, nuisance=0, session=None, normal=True,
                  unknown=False):
            n_normal, n_attack = (250, 139) if index == 5 else (2, 6)
            rows = [(0, "normal", "work", 0.1 + 0.1 * (i % 2)) for i in range(n_normal)] if normal else []
            rows += [(i % 6 + 1, "attack", "unexpected" if unknown else techniques[i % 6], attack_value)
                     for i in range(n_attack)]
            X = np.zeros((len(rows), 31))
            X[:, 0] = index
            X[:, 1] = [row[0] for row in rows]
            X[:, 2] = [row[3] for row in rows]
            for excluded in evaluator.STABLE_EXCLUDED:
                X[:, evaluator.FEATURES.index(excluded)] = nuisance
            np.savez(paths[index], X=X, names=np.array(evaluator.FEATURES),
                     labels=np.array([row[1] for row in rows]),
                     techniques=np.array([row[2] for row in rows]),
                     sessions=np.array([session or "ABCDEF"[index]] * len(rows)))

        for i in range(6):
            write(i)

        def run(selected=paths):
            fits.clear()
            scored.clear()
            cutoffs.clear()
            with patch.object(sklearn.ensemble, "IsolationForest", Forest), patch.object(shared, "normal_cutoff", checked_cutoff):
                return evaluator.evaluate(selected)

        result = run(paths[::-1])
        assert len(fits) == len(cutoffs) == 2 and len(scored) == 4
        original_fits = [X.copy() for X in fits]
        assert result["split_ids"] == {"training": list("ABCD"), "calibration": ["E"], "test": ["F"]}
        assert result["calibration_normal_rows_used"]["label_counts"] == {"normal": 2, "attack": 0}
        assert result["calibration_attack_rows_excluded"]["total"] == 6
        assert result["versions"] == {"numpy": np.__version__, "sklearn": sklearn.__version__}
        for name, digest in result["source_sha256"].items():
            assert digest == hashlib.sha256((Path(evaluator.__file__).parent / name).read_bytes()).hexdigest()
        for regime, row in result["regimes"].items():
            n = evaluator.REGIMES[regime]
            assert row["training_session_ids"] == list("ABCD")[:n]
            assert row["training_normal_rows_used"]["label_counts"] == {"normal": 2 * n, "attack": 0}
            assert row["training_attack_rows_excluded"]["total"] == 6 * n
            assert row["threshold"] == real_cutoff(np.array([0.1, 0.2]), 0.005)
            assert row["held_out_test"]["total"] == row["test_rows"]["total"] == 389
            assert {k: row["held_out_test"][k] for k in ("tp", "fn", "fp", "tn")} == {"tp": 139, "fn": 0, "fp": 0, "tn": 250}
            assert sum(g["tp"] for g in row["groups"].values()) == 139
            for group, metrics in row["groups"].items():
                assert set(metrics["per_technique"]) == set(evaluator.GROUPS[group])
                assert metrics["tn"] == 250 and metrics["fp"] == metrics["fn"] == 0

        # Training/calibration attacks and excluded columns cannot affect the fitted models or cutoffs.
        for i in range(6):
            write(i, attack_value=0.01 if i < 5 else 0.9, nuisance=999)
        changed = run()
        assert changed["regimes"] == result["regimes"]
        assert all(np.array_equal(old, new) for old, new in zip(original_fits, fits))

        # Mutate held-out attacks only: predictions change, fitting and calibration cannot.
        write(5, attack_value=0.01)
        changed = run()
        assert all(np.array_equal(old, new) for old, new in zip(original_fits, fits))
        for regime, row in changed["regimes"].items():
            assert row["threshold"] == result["regimes"][regime]["threshold"]
            assert row["held_out_test"]["tp"] == 0 and row["held_out_test"]["fn"] == 139

        def rejected(message, selected=paths):
            try:
                run(selected)
            except ValueError as exc:
                assert message in str(exc), str(exc)
            else:
                raise AssertionError(f"accepted fault: {message}")
            assert not fits and not scored

        rejected("exactly six", paths[:5])
        write(5, session="E")
        rejected("overlapping session partitions")
        write(5)
        write(4, unknown=True)
        rejected("unexpected attack techniques")
        write(4, normal=False)
        rejected("calibration session has no normal")
        write(4)
        write(0, normal=False)
        write(1, normal=False)
        rejected("training has no normal")


if __name__ == "__main__":
    test()
    print("normal-only split/isolation/389-row coverage/score-direction/mask/fault checks passed (estimator stand-in)")
