"""Closed-capture evidence checks for the fixed benign behavior matrix."""
import argparse
from collections import Counter
import errno
import hashlib
import json
from pathlib import Path

import behavior_memory as B
from finalize_event_time_session import check_closed, check_collection, snapshot, EVENT_NAMES
from probe_behavior_lineage import MATRIX

EXPECTED = ((0, 1), (1, 0), (1, 1), (1, 0), (0, 1), (1, 1), (1, 1), (2, 2))


def require_sensor_root(memory, header, expected):
    _, cg, start, pid, tgid = header[:5]
    state = memory.tasks.get((cg, pid))
    if not state or state[0] != start or state[1] or pid != tgid:
        raise ValueError("sensor task identity unresolved")
    root = memory.root((memory.epoch, cg, pid, start), state)
    if root is None or root[1:] != expected:
        raise ValueError("sensor belongs to unrelated/unverified job root")


def summarize(jobs):
    if len(jobs) != len(MATRIX):
        raise ValueError("incomplete matrix")
    for row, spec, expected in zip(jobs, MATRIX, EXPECTED):
        if (row["mode"], row["label"], row["expected_advisories"]) != spec:
            raise ValueError("changed matrix")
        if (row["credential_hooks"], row["connect_attempts"]) != expected:
            raise ValueError("missing precursor or connect coverage")
        if row["advisories"] != spec[2] or not row["root_exit_verified"]:
            raise ValueError("advisory or root exit mismatch")
    return {"normal_jobs": 6, "normal_jobs_with_advisory": sum(r["advisories"] > 0 for r in jobs[:6]),
            "synthetic_risk_jobs": 2, "synthetic_risk_advisories": sum(r["advisories"] for r in jobs[6:]),
            "not_attack_dr_or_operational_fpr": True}


def verify(directory):
    paths = [directory / name for name in ("capture.bin", "collector.log", "matrix_manifest.json", "matrix_protocol.json", "probe.json")]
    paths += [directory / (mode + ".phases.jsonl") for mode, _, _ in MATRIX]
    sources = snapshot(paths)
    check_closed(sources)
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    manifest = json.loads(paths[2].read_text())
    protocol = json.loads(paths[3].read_text())
    if protocol["plan"] != [list(x) for x in MATRIX] or len(manifest) != len(MATRIX):
        raise ValueError("protocol/manifest mismatch")
    if protocol["probe_sha256"] != hashlib.sha256(Path(__file__).with_name("probe_behavior_lineage.py").read_bytes()).hexdigest():
        raise ValueError("fixture source mismatch")
    if any(not (type(r["start_ns"]) is int and type(r["end_ns"]) is int and 0 <= r["start_ns"] < r["end_ns"]) for r in manifest):
        raise ValueError("invalid job time bounds")
    if any(a["end_ns"] > b["start_ns"] for a, b in zip(manifest, manifest[1:])):
        raise ValueError("overlapping jobs")
    jobs = [{**r, "credential_hooks": 0, "connect_attempts": 0, "advisories": 0,
             "root_exit_verified": False, "typed_forks": 0} for r in manifest]
    for row, path, expected in zip(jobs, paths[5:], EXPECTED):
        phases = [json.loads(line) for line in path.read_text().splitlines()]
        results = [p for p in phases if p["phase"] == "local_connect_result"]
        if (len(results) != expected[1] or any(p["application_result"] != errno.ECONNREFUSED for p in results)
                or sum(p["phase"] == "fixture_complete" for p in phases) != 1
                or any(not row["start_ns"] <= p["timestamp_ns"] < row["end_ns"] for p in phases)):
            raise ValueError("missing application refusal/completion evidence")
        row["application_refused_connects"] = len(results)
    memory = B.BehaviorMemory(retention_sec=protocol["retention_sec"], stream_epoch="behavior-matrix")
    kinds, incomplete, advisories, root_exec, root_exit, health = Counter(), [], [], {}, {}, []
    cgroups = set()
    with paths[0].open("rb") as stream:
        while (event := B.read_frame(stream)) is not None:
            header = B.HEADER.unpack_from(event)
            ts, cg, start, pid, tgid = header[:5]
            result, flags, kind = header[11], header[13], header[15]
            kinds[kind] += 1
            before = memory.counts.copy()
            advisory = memory.observe(event)
            if kind == B.HEALTH:
                health.append(ts)
                continue
            cgroups.add(cg)
            matches = [i for i, row in enumerate(jobs) if row["start_ns"] <= ts < row["end_ns"]]
            if len(matches) != 1:
                raise ValueError("event outside/ambiguous job interval")
            i = matches[0]
            row = jobs[i]
            row["credential_hooks"] += memory.counts["credential_open_hooks"]-before["credential_open_hooks"]
            row["connect_attempts"] += memory.counts["non_loopback_connect_attempts"]-before["non_loopback_connect_attempts"]
            row["typed_forks"] += memory.counts["verified_fork_edges"]-before["verified_fork_edges"]
            if pid == row["leader_pid"] and kind in (B.EXEC, B.EXIT):
                if not start or pid != tgid:
                    raise ValueError("invalid root identity")
                target = root_exec if kind == B.EXEC else root_exit
                if i in target:
                    raise ValueError("duplicate root exec/exit")
                target[i] = (cg, pid, start)
            # Attribution is needed for negative controls too: time coincidence
            # and an unrelated typed fork cannot establish sensor coverage.
            if (kind == B.CONNECT or memory.counts["credential_open_hooks"] > before["credential_open_hooks"]
                    or memory.counts["verified_fork_edges"] > before["verified_fork_edges"]):
                require_sensor_root(memory, header, root_exec.get(i))
            if kind == B.CONNECT:
                if result not in (-errno.ECONNREFUSED, -errno.EINPROGRESS) or not flags & B.DEST_VALID:
                    raise ValueError("unexpected syscall connect result or destination unknown")
                if not flags & 64:
                    incomplete.append({"type": kind, "flags": flags})
            if advisory:
                root = advisory["root_identity"]
                if advisory["scope"] != "verified_task_lineage" or (root["cgroup_id"], root["pid"], root["task_start_ns"]) != root_exec.get(i):
                    raise ValueError("advisory not matched verified root")
                row["advisories"] += 1
                advisories.append(advisory)
    for i, row in enumerate(jobs):
        row["root_exit_verified"] = i in root_exec and root_exec.get(i) == root_exit.get(i)
        if row["typed_forks"] < 1:
            raise ValueError("missing typed fork coverage")
    if len(cgroups) != 1 or len(set(root_exec.values())) != len(jobs):
        raise ValueError("unresolved/distinct root scope")
    if not health or min(health) > jobs[0]["start_ns"] or max(health) < jobs[-1]["end_ns"]:
        raise ValueError("missing bracketing HEALTH")
    bad = ("unsafe_ordering", "health_loss_or_counter_reset", "uncertain_process", "unsupported_thread",
           "missing_fork_identity", "unresolved_generation", "unresolved_fork", "unresolved_fork_generation",
           "unresolved_root_generation", "fork_family_invalidated", "capacity_tasks_dropped", "cgroup_identity_changed", "pid_reuse")
    if any(memory.counts[x] for x in bad):
        raise ValueError("coverage invalidation: " + str({x: memory.counts[x] for x in bad if memory.counts[x]}))
    quality = check_collection(paths[1].read_text(), {"network_counts": {k: v for k, v in kinds.items() if 8 <= k <= 13}, "incomplete_socket_metadata": incomplete})
    if any(kinds[i+1] != quality["received"][name] for i, name in enumerate(EVENT_NAMES)):
        raise ValueError("raw/collector event count mismatch")
    summary = summarize(jobs)
    if memory.evidence:
        raise ValueError("root-exit precursor cleanup failed")
    check_closed(sources)
    if snapshot(paths) != sources:
        raise ValueError("source changed during verification")
    return {"status": "passed", "continuous_replay_no_label_reset": True, "sensor_attribution_verified": True, "jobs": jobs, "summary": summary,
            "advisories": advisories, "coverage": memory.summary(), "collector_quality": quality,
            "input_sha256": hashes, "limits": "All jobs are benign dummy fixtures. Approved matched sequence intentionally produces an advisory. Kernel EINPROGRESS is not refusal; application refusal is separately fixture-recorded, not kernel proof. No intent inference, transfer, trained model efficacy or operational FPR claim. Clock interval matching checked only for this run, not a CPU/BPF clock integration."}


def self_check():
    memory = B.BehaviorMemory(stream_epoch="check")
    memory.task(9, 10, 100)
    memory.task(9, 20, 200)
    memory.task(9, 30, 300)[2] = ("check", 9, 20, 200)
    header = (0, 9, 300, 30, 30)
    require_sensor_root(memory, header, (9, 20, 200))
    try:
        require_sensor_root(memory, header, (9, 10, 100))
    except ValueError:
        pass
    else:
        raise AssertionError("unrelated typed family satisfied sensor coverage")
    jobs = [{"mode": mode, "label": label, "expected_advisories": count, "advisories": count,
             "credential_hooks": expected[0], "connect_attempts": expected[1], "root_exit_verified": True}
            for (mode, label, count), expected in zip(MATRIX, EXPECTED)]
    assert summarize(jobs)["normal_jobs_with_advisory"] == 1
    for bad in (jobs[:-1], [{**r, "root_exit_verified": False} for r in jobs],
                [{**r, "credential_hooks": 0} for r in jobs]):
        try:
            summarize(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("missing matrix coverage accepted")
    print("Matched normal advisory preserved; missing root/sensor/matrix evidence rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=Path)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if args.self_check:
        self_check()
    else:
        print(json.dumps(verify(args.directory), indent=2))
