# Bucket model / data9 — work in progress

This is a snapshot of the existing **simulated-workload** experiment, shared so the team can inspect the data and decide what to improve. It is separate from the normal-only IsolationForest pipeline in [`../../README.md`](../../README.md). The labels describe the test harness's normal/attack units; they do not establish whether a real human user is an attacker.

| File | Contents |
| --- | --- |
| `agg_1s.npz` | 3,866 rows × 31 numeric features from sessions **s1–s11** (1,275 normal, 2,591 attack); `X`, `labels`, `techniques`, `sessions`, `names` |
| `sessions/session_*.tsv` | 12 session timelines: monotonic start/end times, label, workload unit; **s12 has no rows in the NPZ** |
| `bucket_model.pkl`, `meta.json`, `importance.json` | Existing 300-tree RandomForest and its metadata |
| `loso_agg.json`, `bucket_tactic.json`, `eval.log`, `collector_health.tsv` | Previously reported holdout results, technique summaries, evaluation run log, and per-session loss counters |
| `extract.py`, `aggregate.py`, `eval_loso.py`, `eval_bucket_tactic.py`, `train_bucket.py` | Source snapshots used for this experiment |
| `syscall_map_x86_64.json` | The syscall mapping produced on the collection host |

The NPZ has only numeric features and categorical labels; raw event traces, file paths, account data, and the ADFA-LD archive are not included. The model is a Python pickle: load it only in a trusted environment. To inspect the matrix without loading the model:

```python
import numpy as np
with np.load("agg_1s.npz", allow_pickle=False) as data:
    print({name: data[name].shape for name in data.files})
```

The collection was a controlled eBPF experiment on the Linux host, with normal and simulated attack units mixed within each session. The server's `/whs/run_eval.sh` discarded `session_12` because its collector reported **42,326 writer-queue drops**; sessions s1–s11 reported zero queue and ring-buffer loss. `collector_health.tsv` records these counters from the server's `session_*.log` files, and `eval.log` records the exclusion. The pipeline merged s1–s11's extracted records, then ran the following commands from `/whs` (the raw `all.slim.jsonl` is deliberately excluded here):

```bash
python3 aggregate.py /whs/data9/all.slim.jsonl /whs/data9/agg_1s.npz --bucket-sec 1
python3 eval_bucket_tactic.py /whs/data9/agg_1s.npz --out /whs/data9/bucket_tactic.json
python3 eval_loso.py /whs/data9/agg_1s.npz --out /whs/data9/loso_agg.json
python3 train_bucket.py /whs/data9/agg_1s.npz --out /whs/model_bucket_data9 --budget 0.005
```

The last three commands can be rerun using the checked-in NPZ and a different output path. They use separate random forests and threshold procedures: `eval_loso.py` uses 400 trees with a fixed 0.5 threshold; `eval_bucket_tactic.py` and `train_bucket.py` use 300 trees with a quantile threshold. This explains why `loso_agg.json` reports **99.31% detection / 0.78% false positives**, while `meta.json` and `bucket_tactic.json` report **99.23% / 0.55%**.

**Evaluation caveats:** `extract.py` sets the record's `start` to the process start time, and `aggregate.py` groups on `start // bucket_size`. These saved "1-second buckets" therefore group by **process birth time**, while the live detector groups by **event time**. `aggregate.py` also writes the same network count to `n_net_log` and `n_net_dst_log`; those two columns are identical in all 3,866 rows, so the destination-count feature is absent. Both published metrics are historical diagnostics, not validated live performance. The threshold in `meta.json` (0.550133) was selected from the same cross-validation normal scores used to report its false-positive rate; it needs an independent holdout. The live detector has used 0.67, so the saved metadata is not a complete deployment configuration.

There is no verified result here for attacks separated by `sleep`, repeated attacks, or normal administrator work that resembles reconnaissance. A next evaluation should rebuild event-time features, keep whole sessions and techniques separate between training/calibration/testing, and report missed attacks and false alerts on those held-out sessions.
