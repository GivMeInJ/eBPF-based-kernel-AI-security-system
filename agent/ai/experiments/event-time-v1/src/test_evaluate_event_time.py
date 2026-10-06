"""Synthetic check of nested session isolation and zero-positive holdouts."""

import json
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import joblib
import numpy as np

import evaluate_event_time as evaluator
from feature_schema import STABLE_EXCLUDED, apply_feature_mask


def write(path, session, names, excluded_value=999, nuisance=0, include_attack=False):
    rows = [(0.1, "normal", "idle"), (0.2, "normal", "work")]
    if session != "C" or include_attack:
        rows.append((0.9, "attack", "keep"))
    rows.append((excluded_value, "attack", "drop"))
    X = np.array([[ord(session), value] for value, _, _ in rows])
    if len(names) > 2:
        X = np.column_stack((X, np.full((len(rows), len(names) - 2), nuisance)))
    np.savez(path, X=X,
             labels=np.array([label for _, label, _ in rows]),
             techniques=np.array([technique for _, _, technique in rows]),
             sessions=np.array([session] * len(rows)), names=np.array(names))


def test():
    normal_scores = np.array([0.1, 0.2, 0.3, 0.4])
    assert np.mean(normal_scores >= evaluator.normal_cutoff(normal_scores, 0.25)) == 0.25
    tied_scores = np.array([0.1, 0.2, 0.2, 0.2])
    assert np.mean(tied_scores >= evaluator.normal_cutoff(tied_scores, 0.25)) <= 0.25
    with TemporaryDirectory() as directory:
        root = Path(directory)
        names = ["session_marker", "signal"]
        paths = [root / f"{session}.npz" for session in "ABC"]
        for path, session in zip(paths, "ABC"):
            write(path, session, names)

        X, y, _, _, _ = evaluator.read_data(paths, {"drop"})
        old_dir = root / "model"
        old_dir.mkdir()
        (old_dir / "meta.json").write_text(json.dumps({"feature_names": names}))
        joblib.dump(evaluator.fit_rf(X, y), old_dir / "bucket_model.pkl")

        original_fit = evaluator.fit_rf

        def checked_fit(train_X, train_y):
            model = original_fit(train_X, train_y)
            train_sessions = set(train_X[:, 0])

            class CheckedModel:
                classes_ = model.classes_

                def predict_proba(self, test_X):
                    assert train_sessions.isdisjoint(test_X[:, 0])
                    return model.predict_proba(test_X)

            return CheckedModel()

        with patch.object(evaluator, "fit_rf", checked_fit):
            result = evaluator.evaluate(paths, 0.25, {"drop"}, old_dir)
        assert result["excluded_features"] == []
        assert "not verified live metrics" in result["deployed_replay_note"]
        assert len(result["sessions"]) == 3
        for row in result["sessions"]:
            assert row["new_rf"]["total"] == row["deployed_rf"]["total"]
            assert row["deployed_rf"]["threshold"] == 0.67
            assert "drop" not in row["new_rf"]["per_technique"]
        zero = result["sessions"][2]
        assert zero["session"] == "C" and zero["new_rf"]["total"] == 2
        assert zero["new_rf"]["dr"] is None and zero["new_rf"]["tp"] == zero["new_rf"]["fn"] == 0

        write(paths[2], "C", names, excluded_value=-999)
        assert evaluator.evaluate(paths, 0.25, {"drop"}, old_dir) == result
        write(paths[2], "C", names[::-1])
        try:
            evaluator.evaluate(paths, 0.25, {"drop"}, old_dir)
        except ValueError as exc:
            assert "feature name/order mismatch" in str(exc)
        else:
            raise AssertionError("feature mismatch was accepted")
        write(paths[2], "C", names)
        (old_dir / "meta.json").write_text(json.dumps({"feature_names": names[::-1]}))
        try:
            evaluator.evaluate(paths, 0.25, {"drop"}, old_dir)
        except ValueError as exc:
            assert "deployed model feature name/order mismatch" in str(exc)
        else:
            raise AssertionError("deployed model feature mismatch was accepted")


def raises(error, message, function, *args, **kwargs):
    try:
        function(*args, **kwargs)
    except error as exc:
        assert message in str(exc), str(exc)
    else:
        raise AssertionError(f"expected {error.__name__}: {message}")


def test_mask_and_export():
    names = ["session_marker", "signal", *STABLE_EXCLUDED]
    X = np.arange(3 * len(names)).reshape(3, len(names))
    assert np.array_equal(apply_feature_mask(X, names), X)
    assert np.array_equal(apply_feature_mask(X, names, STABLE_EXCLUDED), X[:, :2])
    raises(ValueError, "shape", apply_feature_mask, X[:, :2], names)
    raises(ValueError, "unique", apply_feature_mask, X[:, :2], ["a", "a"])
    raises(ValueError, "unknown excluded", apply_feature_mask, X, names, ["unknown"])
    raises(ValueError, "every column", apply_feature_mask, X, names, names)
    with TemporaryDirectory() as directory:
        root = Path(directory)
        paths = [root / f"{session}.npz" for session in "ABCD"]
        for path, session in zip(paths, "ABCD"):
            write(path, session, names, nuisance=1)
        reference = evaluator.evaluate(paths[:3], 0.25, {"drop"})
        assert reference["excluded_features"] == list(STABLE_EXCLUDED)
        for path, session in zip(paths, "ABCD"):
            write(path, session, names, nuisance=-1e6)
        assert evaluator.evaluate(paths[:3], 0.25, {"drop"}) == reference
        write(paths[2], "C", names, nuisance=-1e6, include_attack=True)

        ordered = evaluator.read_data(paths, {"drop"})
        reversed_data = evaluator.read_data(paths[::-1], {"drop"})
        assert all(np.array_equal(a, b) for a, b in zip(ordered[:4], reversed_data[:4]))
        assert ordered[4] == reversed_data[4]
        train_X, train_y = ordered[:2]
        old_dir = root / "old"
        old_dir.mkdir()
        joblib.dump(evaluator.fit_rf(train_X, train_y), old_dir / "bucket_model.pkl")
        (old_dir / "meta.json").write_text(json.dumps({"feature_names": names}))
        deployed_scores = evaluator.attack_scores
        original_fit = evaluator.fit_rf
        fit_inputs, scoring_inputs = [], []

        def recorded_fit(X, labels):
            fit_inputs.append((X.copy(), labels.copy()))
            return original_fit(X, labels)

        def recorded_scores(model, X):
            scoring_inputs.append(X.copy())
            return deployed_scores(model, X)

        candidate_dir = root / "candidate"
        with patch.object(evaluator, "fit_rf", recorded_fit), \
                patch.object(evaluator, "attack_scores", recorded_scores):
            result = evaluator.evaluate(paths[::-1], 0.25, {"drop"}, old_dir,
                                        export_candidate=candidate_dir)
        assert len(fit_inputs) == 1
        assert fit_inputs[0][0].shape == (6, 2)
        assert set(fit_inputs[0][0][:, 0]) == {ord("A"), ord("B")}
        assert fit_inputs[0][0][:, 0].tolist() == [ord("A")] * 3 + [ord("B")] * 3
        assert [set(X[:, 0]) for X in scoring_inputs] == [{ord("C")}, {ord("D")}, {ord("D")}]
        assert [X.shape[1] for X in scoring_inputs] == [2, 2, len(names)]
        meta = json.loads((candidate_dir / "meta.json").read_text())
        assert meta == result["candidate"]
        assert meta["split_ids"] == {"training": ["A", "B"], "calibration": ["C"], "test": ["D"]}
        assert meta["feature_names"] == names and meta["excluded_features"] == list(STABLE_EXCLUDED)
        assert meta["feature_schema"] == "event_time_stable_v1" and meta["bucket_sec"] == 1.0
        assert set(meta["versions"]) == {"numpy", "sklearn", "joblib"}
        assert meta["sample_counts"] == {
            "training": {"total": 6, "normal": 4, "attack": 2},
            "calibration": {"total": 3, "normal": 2, "attack": 1},
            "test": {"total": 3, "normal": 2, "attack": 1}}
        assert meta["calibration"]["normal_buckets_used"] == 2
        assert meta["calibration"]["normal_fpr"] <= 0.25
        model = joblib.load(candidate_dir / "bucket_model.pkl")
        assert model.n_features_in_ == 2 and model.n_estimators == 300
        assert model.class_weight == "balanced" and model.random_state == 42
        test_X = scoring_inputs[1]
        evidence = evaluator.counts(np.array([0, 0, 1]),
                                    evaluator.attack_scores(model, test_X) >= meta["threshold"],
                                    np.array(["idle", "work", "keep"]))
        assert meta["held_out_test"] == {"threshold": meta["threshold"], **evidence}
        assert result["sessions"][0]["new_rf"] == meta["held_out_test"]
        for filename in ("meta.json", "bucket_model.pkl"):
            assert stat.S_IMODE((candidate_dir / filename).stat().st_mode) == 0o600
        saved = (candidate_dir / "bucket_model.pkl").read_bytes()
        raises(FileExistsError, "already exists", evaluator.evaluate, paths, 0.25, {"drop"},
               export_candidate=candidate_dir)
        assert (candidate_dir / "bucket_model.pkl").read_bytes() == saved
        raises(ValueError, "at least 4", evaluator.evaluate, paths[:3], 0.25, {"drop"},
               export_candidate=root / "too_few")
        raises(ValueError, "overlapping", evaluator.evaluate, paths + [paths[0]], 0.25, {"drop"},
               export_candidate=root / "overlap")
        for path, changed_label in ((paths[2], False), (paths[3], True)):
            with np.load(path, allow_pickle=False) as data:
                part = {key: data[key] for key in data.files}
            if changed_label:
                part["X"][:, 1] = 9999
                part["labels"][:3] = ["attack", "attack", "normal"]
            else:
                part["X"][part["labels"] == "attack", 1] = 9999
            np.savez(path, **part)
        with patch.object(evaluator, "fit_rf", recorded_fit):
            changed = evaluator.evaluate(paths, 0.25, {"drop"}, export_candidate=root / "changed")
        assert len(fit_inputs) == 2
        assert np.array_equal(fit_inputs[0][0], fit_inputs[1][0])
        assert np.array_equal(fit_inputs[0][1], fit_inputs[1][1])
        changed_model = joblib.load(root / "changed" / "bucket_model.pkl")
        assert changed["candidate"]["threshold"] == meta["threshold"]
        assert np.array_equal(model.predict_proba(test_X), changed_model.predict_proba(test_X))
        with np.load(paths[0], allow_pickle=False) as data:
            part = {key: data[key] for key in data.files}
        part["sessions"] = np.array(["A", "other", "A", "A"])
        mixed = root / "mixed.npz"
        np.savez(mixed, **part)
        raises(ValueError, "one session", evaluator.evaluate, [mixed, *paths[1:]], 0.25, {"drop"},
               export_candidate=root / "mixed_candidate")
        assert not any((root / name).exists() for name in ("too_few", "overlap", "mixed_candidate"))


if __name__ == "__main__":
    test()
    test_mask_and_export()
    print("ok")
