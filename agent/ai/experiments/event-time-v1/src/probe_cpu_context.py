"""Bounded matched negative control: CPU measures load, not job authorization."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

from sample_cgroup_cpu import cpu_delta, read_cpu


PLAN = [(split, family, pair, label) for split, family in
        (("train", "sha256"), ("calibration", "pbkdf2"), ("test", "arithmetic"))
        for pair in range(2) for label in ((0, 1) if pair == 0 else (1, 0))]


def worker(group, family, seconds):
    (group / "cgroup.procs").write_text(str(os.getpid()))
    if (group / "cpu.max").read_text().strip() != "50000 100000":
        raise RuntimeError("CPU quota mismatch")
    print(json.dumps(read_cpu(group)), flush=True)
    deadline = time.monotonic() + seconds
    data = b"controlled local compute only" * 256
    value = 1
    while time.monotonic() < deadline:
        if family == "sha256":
            hashlib.sha256(data).digest()
        elif family == "pbkdf2":
            hashlib.pbkdf2_hmac("sha256", data, b"public-dummy-salt", 1000)
        elif family == "arithmetic":
            for _ in range(10000):
                value = (value * 1664525 + 1013904223) & 0xffffffff
        else:
            raise ValueError("unknown family")


def evaluate(rows):
    if [(r["split"], r["family"], r["pair"], r["synthetic_policy_label"]) for r in rows] != PLAN:
        raise ValueError("incomplete or changed fixed plan")
    if any(not math.isfinite(r["cpu_cores_mean"]) or not .2 <= r["cpu_cores_mean"] <= .65
           or not r.get("worker_ready") or r.get("quota_readback") != "50000 100000"
           or not 5 <= (r["interval_end_ns"]-r["interval_start_ns"])/1e9 <= 65 for r in rows):
        raise ValueError("invalid CPU score, readiness, quota or duration")
    calibration = [r["cpu_cores_mean"] for r in rows if r["split"] == "calibration" and r["synthetic_policy_label"] == 0]
    threshold = math.nextafter(max(calibration), math.inf)
    test = [r for r in rows if r["split"] == "test"]
    tp = sum(r["cpu_cores_mean"] >= threshold and r["synthetic_policy_label"] == 1 for r in test)
    fp = sum(r["cpu_cores_mean"] >= threshold and r["synthetic_policy_label"] == 0 for r in test)
    return {"status": "complete", "threshold": threshold, "threshold_source": "maximum authorized calibration CPU, nextafter +inf; no test tuning",
            "test": {"TP": tp, "FN": 2-tp, "FP": fp, "TN": 2-fp, "synthetic_policy_recall": tp/2, "FPR": fp/2},
            "policy_oracle": "Manifest authorization is ground truth, never an input feature; no oracle detector reported.",
            "limits": "12 episodes, only 2 authorized calibration and 2 authorized test episodes. Exploratory matched negative control, not real attack detection or an FPR guarantee. Labels describe an external synthetic approval policy; the worker receives neither label nor approval status. Train episodes are descriptive, no model is fitted. No general impossibility claim, model export or live policy change."}


def terminate_run(signum, frame):
    raise SystemExit("terminated; cleaning up owned worker and cgroup")


def run(output, seconds):
    if not math.isfinite(seconds) or not 5 <= seconds <= 60:
        raise ValueError("episode seconds must be 5..60")
    output.mkdir(exist_ok=False)
    group = Path("/sys/fs/cgroup") / ("whs_cpu_probe_" + str(os.getpid()))
    protocol = {"study": "matched CPU authorization negative control", "episode_seconds": seconds,
                "cpu_max": "50000 100000", "role": "isolated_compute", "ground_truth": "synthetic policy authorization, not malicious intent",
                "split_rule": "entire sessions/pairs and compute families disjoint; fixed before collection",
                "plan": [{"split": s, "family": f, "pair": p, "synthetic_policy_label": label} for s, f, p, label in PLAN],
                "features": ["cpu_cores_mean"], "authorization_not_feature": True,
                "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (output / "protocol.json").write_text(json.dumps(protocol, indent=2) + "\n")
    group.mkdir()
    process = None
    rows = []
    old_handler = signal.signal(signal.SIGTERM, terminate_run)
    try:
        (group / "cpu.max").write_text("50000 100000")
        quota = (group / "cpu.max").read_text().strip()
        if quota != "50000 100000":
            raise RuntimeError("CPU quota mismatch")
        with (output / "intervals.jsonl").open("x", buffering=1) as intervals, (output / "episodes.jsonl").open("x", buffering=1) as episodes:
            for index, (split, family, pair, label) in enumerate(PLAN):
                if (group / "cgroup.procs").read_text().strip():
                    raise RuntimeError("unexpected process in isolated cgroup")
                process = subprocess.Popen([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", str(group), "--family", family, "--seconds", str(seconds)], stdout=subprocess.PIPE, text=True)
                with selectors.DefaultSelector() as ready:
                    ready.register(process.stdout, selectors.EVENT_READ)
                    if not ready.select(timeout=5):
                        raise TimeoutError("worker readiness timeout")
                    first = json.loads(process.stdout.readline(1024))
                first["identity"] = tuple(first["identity"])
                if first["identity"] != read_cpu(group)["identity"] or str(process.pid) not in (group / "cgroup.procs").read_text().split():
                    raise RuntimeError("worker did not join isolated cgroup")
                before = first
                deadline = time.monotonic() + seconds + 5
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("worker completion timeout")
                    time.sleep(1)
                    after = read_cpu(group)
                    intervals.write(json.dumps({"episode": index, "role": "isolated_compute", **cpu_delta(before, after)}) + "\n")
                    before = after
                if process.wait() != 0:
                    raise RuntimeError("compute worker failed")
                process.stdout.close()
                after = read_cpu(group)
                row = {"episode": index, "split": split, "family": family, "pair": pair,
                       "synthetic_policy_label": label, "role": "isolated_compute", "worker_ready": True,
                       "quota_readback": quota, **cpu_delta(first, after)}
                if not seconds*.8 <= (row["interval_end_ns"]-row["interval_start_ns"])/1e9 <= seconds+3:
                    raise RuntimeError("insufficient or delayed episode coverage")
                rows.append(row)
                episodes.write(json.dumps(row) + "\n")
                print(f"completed episode {index+1}/{len(PLAN)} split={split} family={family}", flush=True)
                process = None
                time.sleep(1)
        result = evaluate(rows)
        result["protocol_sha256"] = hashlib.sha256((output / "protocol.json").read_bytes()).hexdigest()
        result["episodes_sha256"] = hashlib.sha256((output / "episodes.jsonl").read_bytes()).hexdigest()
        (output / "evaluation.json").write_text(json.dumps(result, indent=2) + "\n")
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        group.rmdir()
        signal.signal(signal.SIGTERM, old_handler)


def self_check():
    rows = [{"split": s, "family": f, "pair": p, "synthetic_policy_label": label, "cpu_cores_mean": .5,
             "worker_ready": True, "quota_readback": "50000 100000", "interval_start_ns": 0, "interval_end_ns": 10_000_000_000} for s, f, p, label in PLAN]
    result = evaluate(rows)
    assert result["test"] == {"TP": 0, "FN": 2, "FP": 0, "TN": 2, "synthetic_policy_recall": 0, "FPR": 0}
    for bad in (rows[:-1], [{**r, "cpu_cores_mean": float("nan")} for r in rows],
                [{**r, "cpu_cores_mean": 0} for r in rows], [{**r, "worker_ready": False} for r in rows]):
        try:
            evaluate(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid/incomplete input accepted")
    print("Identical-score threshold accounting; incomplete/invalid/idle/unready data rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--seconds", type=float, default=10)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--family", choices=("sha256", "pbkdf2", "arithmetic"))
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if args.self_check:
        self_check()
    elif args.worker:
        worker(args.worker, args.family, args.seconds)
    elif args.output:
        run(args.output, args.seconds)
    else:
        parser.error("--output required")
