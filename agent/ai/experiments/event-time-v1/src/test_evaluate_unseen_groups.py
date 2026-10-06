"""Runnable isolation/fault check; dependency stand-in never claims to test real RF quality."""
import importlib.util
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import ModuleType
from unittest.mock import patch

import numpy as np

if importlib.util.find_spec("sklearn") is None:
    sklearn = ModuleType("sklearn")
    ensemble = ModuleType("sklearn.ensemble")
    ensemble.RandomForestClassifier = object  # fit_rf is replaced below, never executed.
    sklearn.ensemble = ensemble
    sys.modules.update({"sklearn": sklearn, "sklearn.ensemble": ensemble})

import evaluate_event_time as shared
import evaluate_unseen_groups as evaluator


def test():
    names = evaluator.FEATURES
    techniques = [tech for group in evaluator.GROUPS.values() for tech in group]
    with TemporaryDirectory() as directory:
        paths = [Path(directory) / f"{session}.npz" for session in "ABCDEF"]

        def write(index, attack_value=0.9, nuisance=0, unknown=False, drop=(), session=None,
                  normal=True):
            rows = [(0, "normal", "idle", 0.1), (0, "normal", "work", 0.2)] if normal else []
            rows += [(code, "attack", "unexpected" if unknown and code == 1 else tech, attack_value)
                     for code, tech in enumerate(techniques, 1) if tech not in drop]
            X = np.zeros((len(rows), 31))
            X[:, 0] = index  # Session marker; never part of the real data protocol.
            X[:, 1] = [row[0] for row in rows]  # Technique marker for leakage assertions.
            X[:, 2] = [row[3] for row in rows]
            for excluded in evaluator.STABLE_EXCLUDED:
                X[:, names.index(excluded)] = nuisance
            np.savez(paths[index], X=X, names=np.array(names),
                     labels=np.array([row[1] for row in rows]),
                     techniques=np.array([row[2] for row in rows]),
                     sessions=np.array([session or "ABCDEF"[index]] * len(rows)))

        for i in range(6):
            write(i)

        fits, scored, cutoffs = [], [], []
        real_cutoff = shared.normal_cutoff

        def fake_fit(X, labels):
            group = list(evaluator.GROUPS)[len(fits) // 2]
            n_sessions = list(evaluator.REGIMES.values())[len(fits) % 2]
            target_codes = {techniques.index(t) + 1 for t in evaluator.GROUPS[group]}
            assert X.shape[1] == 26 and set(X[:, 0]) == set(range(n_sessions))
            assert set(labels) == {0, 1} and not (set(X[:, 1]) & target_codes)
            fits.append((X.copy(), labels.copy()))

            class Model:
                classes_ = np.array([0, 1])

                def predict_proba(self, batch):
                    assert batch.shape[1] == 26
                    if set(batch[:, 0]) == {4}:
                        assert set(batch[:, 1]) == {0} and len(batch) == 2
                    else:
                        assert set(batch[:, 0]) == {5}
                        assert set(batch[:, 1]) == {0} | target_codes
                        assert len(batch) == 2 + len(target_codes)
                    scored.append(batch.copy())
                    return np.column_stack((1 - batch[:, 2], batch[:, 2]))

            return Model()

        def checked_cutoff(scores, target_fpr):
            assert target_fpr == 0.005 and np.array_equal(scores, [0.1, 0.2])
            cutoffs.append(scores.copy())
            return real_cutoff(scores, target_fpr)

        def run(selected=paths):
            fits.clear()
            scored.clear()
            cutoffs.clear()
            with patch.object(shared, "fit_rf", fake_fit), patch.object(shared, "normal_cutoff", checked_cutoff):
                return evaluator.evaluate(selected)

        result = run(paths[::-1])
        assert len(fits) == len(cutoffs) == 8 and len(scored) == 16
        original_fits = [(X.copy(), y.copy()) for X, y in fits]
        assert result["split_ids"] == {"training": list("ABCD"), "calibration": ["E"], "test": ["F"]}
        assert result["calibration_normal_rows_used"]["label_counts"] == {"normal": 2, "attack": 0}
        assert result["calibration_attack_rows_excluded"]["total"] == 6
        for group, group_result in result["groups"].items():
            n = len(evaluator.GROUPS[group])
            for regime, row in group_result["regimes"].items():
                n_sessions = evaluator.REGIMES[regime]
                assert row["training_session_ids"] == list("ABCD")[:n_sessions]
                assert row["training_removed"]["total"] == n_sessions * n
                assert row["training_retained"]["label_counts"] == {"normal": 2 * n_sessions, "attack": n_sessions * (6 - n)}
                assert set(row["training_removed"]["technique_counts"]) == set(evaluator.GROUPS[group])
                assert not (set(row["training_retained"]["technique_counts"]) & set(evaluator.GROUPS[group]))
                assert row["tp"] == n and row["fn"] == row["fp"] == 0 and row["tn"] == 2
                assert row["dr"] == 1 and row["fpr"] == row["calibration_normal_fpr"] == 0
                assert row["threshold"] == real_cutoff(np.array([0.1, 0.2]), 0.005)
                assert row["test_other_attack_rows_excluded"] == 6 - n

        # Calibration attacks and the five excluded columns cannot affect fit, cutoff or scores.
        for i in range(6):
            write(i, attack_value=0.01 if i == 4 else 0.9, nuisance=999)
        assert run() == result
        assert all(np.array_equal(X, old_X) and np.array_equal(y, old_y)
                   for (X, y), (old_X, old_y) in zip(fits, original_fits))

        # Changing held-out targets changes their test scores, never training or thresholds.
        write(5, attack_value=0.01)
        changed = run()
        for group in evaluator.GROUPS:
            for regime in evaluator.REGIMES:
                row = changed["groups"][group]["regimes"][regime]
                assert row["threshold"] == result["groups"][group]["regimes"][regime]["threshold"]
                assert row["tp"] == 0
                assert row["fn"] == len(evaluator.GROUPS[group])
        assert all(np.array_equal(X, old_X) and np.array_equal(y, old_y)
                   for (X, y), (old_X, old_y) in zip(fits, original_fits))

        def rejected(message, selected=paths):
            try:
                run(selected)
            except ValueError as exc:
                assert message in str(exc), str(exc)
            else:
                raise AssertionError(f"accepted fault: {message}")
            assert not fits  # All validation must precede fitting.

        rejected("exactly six", paths[:5])
        write(5, session="E")
        rejected("overlapping session partitions")
        write(5, unknown=True)
        rejected("unexpected attack techniques")
        write(5, drop=evaluator.GROUPS["exfiltration"])
        rejected("test needs normal and target attack")
        write(5)
        write(4, normal=False)
        rejected("calibration session has no normal")
        write(4)
        for i in range(4):
            write(i, normal=False)
        rejected("retained training needs normal and other attack")
        for i in range(4):
            write(i, drop=techniques)
        rejected("retained training needs normal and other attack")


if __name__ == "__main__":
    test()
    print("unseen-group protocol/isolation/mask/fault checks passed (RF dependency stand-in)")
