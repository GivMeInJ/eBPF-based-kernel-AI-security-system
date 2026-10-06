"""One runnable causal-time, idle-gap, scope and history-contamination check."""
from copy import deepcopy
import numpy as np
from temporal_unlinks import SECOND, TEMPORAL_NAMES, temporal_features, history_clean


def test():
    rows = [{"bucket_ns": t * SECOND, "unlink_attempts": n,
             "unique_directory_scopes": int(n > 0), "unknown_scope_attempts": 0}
            for t, n in ((0, 2), (4, 3), (59, 5), (60, 7), (119, 11), (120, 0))]
    a = {"buckets": rows, "npz_buckets": 6, "dropped_outside_npz": 0,
         "matched_unlink_attempts": 28, "recorded_file_unlink": 28}
    x = temporal_features(a)
    assert x.shape == (6, len(TEMPORAL_NAMES)) == (6, 8)
    assert np.isclose(x[1, 2], np.log1p(5)) and np.isclose(x[1, 3], 2 / 5)
    assert np.isclose(x[2, 6], np.log1p(10))
    assert np.isclose(x[3, 6], np.log1p(15))  # t=0 expires, t=4/59/60 remain.
    assert np.isclose(x[4, 6], np.log1p(18))  # t=60 lies exactly on the lower edge.
    assert np.isclose(x[5, 6], np.log1p(11))  # t=60 is now outside the horizon.
    changed = deepcopy(a)
    changed["buckets"][-2]["unlink_attempts"] += 100
    changed["matched_unlink_attempts"] += 100
    changed["recorded_file_unlink"] += 100
    assert np.array_equal(temporal_features(changed)[:4], x[:4])
    reversed_a = {**a, "buckets": rows[::-1]}
    assert np.array_equal(temporal_features(reversed_a)[::-1], x)
    labels = np.array([0, 0, 1, 0, 0, 0])
    assert history_clean([r["bucket_ns"] for r in rows], labels, labels == 1).tolist() == [False, False, False, False, True, True]
    assert history_clean([r["bucket_ns"] for r in rows], labels, np.zeros(6, dtype=bool)).tolist() == [False, False, True, True, True, True]
    for fault in ({**a, "dropped_outside_npz": 1}, {**a, "npz_buckets": 7}):
        try:
            temporal_features(fault)
        except ValueError:
            pass
        else:
            raise AssertionError("incomplete audit accepted")
    overflow = deepcopy(a)
    for row in overflow["buckets"]:
        row["unlink_attempts"] = 2 ** 62
    overflow["recorded_file_unlink"] = overflow["matched_unlink_attempts"] = 6 * 2 ** 62
    try:
        temporal_features(overflow)
    except ValueError as exc:
        assert "int64" in str(exc)
    else:
        raise AssertionError("cumulative integer overflow accepted")
    print("temporal causality, expiry, gap, order and attack-history purge checks passed")


if __name__ == "__main__":
    test()
