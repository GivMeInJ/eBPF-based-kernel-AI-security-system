"""Causal cgroup/session unlink summaries; no task identity or intent inference."""
import numpy as np

SECOND = 1_000_000_000
WINDOWS = (5, 30, 60)
HISTORY_SECONDS = max(WINDOWS)
TEMPORAL_NAMES = ["unlink_count_log", "unlink_directory_scopes_log"] + [
    name for seconds in WINDOWS for name in
    (f"unlink_count_{seconds}s_log", f"unlink_active_{seconds}s_fraction")]


def _times(bucket_ns):
    values = np.asarray(bucket_ns)
    if (values.ndim != 1 or not len(values) or values.dtype.kind not in "iu" or
            np.any(values < 0) or np.any(values % SECOND) or
            np.any(values > np.iinfo(np.int64).max - HISTORY_SECONDS * SECOND) or
            len(np.unique(values)) != len(values)):
        raise ValueError("invalid/duplicate temporal bucket timestamps")
    values = values.astype(np.int64)
    order = np.argsort(values, kind="stable")
    return values, order


def temporal_features(audit):
    """Return rows in audit order; all trailing windows include only past/current bins."""
    rows = audit["buckets"]
    if audit["dropped_outside_npz"] != 0:
        raise ValueError("outside-NPZ unlink attempts would leave history incomplete")
    times, order = _times([r["bucket_ns"] for r in rows])
    if audit["npz_buckets"] != len(rows):
        raise ValueError("audit bucket count mismatch")
    for r in rows:
        for key in ("unlink_attempts", "unique_directory_scopes", "unknown_scope_attempts"):
            if type(r[key]) is not int or r[key] < 0:
                raise ValueError("invalid unlink count")
        if r["unique_directory_scopes"] + r["unknown_scope_attempts"] > r["unlink_attempts"]:
            raise ValueError("directory scope/count mismatch")
    total = sum(r["unlink_attempts"] for r in rows)
    if total > np.iinfo(np.int64).max:
        raise ValueError("unlink history exceeds int64 capacity")
    if total != audit["matched_unlink_attempts"]:
        raise ValueError("audit unlink sum mismatch")
    if audit["matched_unlink_attempts"] != audit["recorded_file_unlink"]:
        raise ValueError("incomplete audited unlink history")
    counts = np.asarray([r["unlink_attempts"] for r in rows], dtype=np.int64)[order]
    scopes = np.asarray([r["unique_directory_scopes"] for r in rows], dtype=np.int64)[order]
    t = times[order]
    sums = np.r_[0, np.cumsum(counts)]
    active = np.r_[0, np.cumsum(counts > 0)]
    columns = [np.log1p(counts), np.log1p(scopes)]
    end = np.arange(1, len(t) + 1)
    for seconds in WINDOWS:
        begin = np.searchsorted(t, t - (seconds - 1) * SECOND, side="left")
        columns += [np.log1p(sums[end] - sums[begin]),
                    (active[end] - active[begin]) / seconds]
    sorted_rows = np.column_stack(columns).astype(np.float32)
    result = np.empty_like(sorted_rows)
    result[order] = sorted_rows
    return result


def history_clean(bucket_ns, labels, forbidden_attack_mask):
    """Warm-up and causal-history eligibility, exclusively for fit/calibration filtering."""
    times, order = _times(bucket_ns)
    labels, forbidden = np.asarray(labels), np.asarray(forbidden_attack_mask)
    if labels.shape != times.shape or forbidden.shape != times.shape or forbidden.dtype.kind != "b":
        raise ValueError("invalid history labels/mask")
    attacks = labels == (1 if labels.dtype.kind in "biuf" else "attack")
    if np.any(forbidden & ~attacks):
        raise ValueError("forbidden history mask must select attack rows only")
    t = times[order]
    begin = np.searchsorted(t, t - (HISTORY_SECONDS - 1) * SECOND, side="left")
    prefix = np.r_[0, np.cumsum(forbidden[order])]
    clean = (prefix[1:] - prefix[begin] == 0) & (t >= t[0] + (HISTORY_SECONDS - 1) * SECOND)
    result = np.empty_like(clean)
    result[order] = clean
    return result
