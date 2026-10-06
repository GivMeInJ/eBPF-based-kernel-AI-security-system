"""Shared column selection; legacy models keep every feature by default."""

import numpy as np


STABLE_EXCLUDED = (
    "frac_missing", "frac_not_world_readable", "frac_other_owner", "frac_setuid",
    "n_net_dst_log",
)


def apply_feature_mask(X, names, excluded=()):
    X, names = np.asarray(X), np.asarray(names)
    if names.ndim != 1 or X.ndim != 2 or X.shape[1] != len(names):
        raise ValueError("invalid feature shape or names")
    if not len(names) or len(set(names.tolist())) != len(names):
        raise ValueError("feature names must be nonempty and unique")
    if any(not isinstance(name, str) or not name for name in names.tolist()):
        raise ValueError("feature names must be nonempty strings")
    if set(excluded) - set(names.tolist()):
        raise ValueError("unknown excluded feature")
    keep = ~np.isin(names, tuple(excluded))
    if not np.any(keep):
        raise ValueError("feature exclusions remove every column")
    return X[:, keep]
