"""Constructed frames only: no monitored syscalls, attacks or network traffic."""

import io
import ipaddress
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

import behavior_memory as B


def frame(kind, sec, *, pid=10, tgid=None, start=10**15, cgroup=9,
          flags=0, result=0, path="/etc/shadow", mode=1,
          parent=10, child=11, child_tgid=0, child_start=0, reserved=0,
          address="192.0.2.1", loss=0, ppid=0, size=None):
    size = B.SIZES[kind] if size is None else size
    event = bytearray(size)
    B.HEADER.pack_into(event, 0, int(sec * 1e9), cgroup, start, pid,
                       pid if tgid is None else tgid, pid, pid, ppid, 0, 0, 0,
                       result, size, flags, 1, kind, b"fixture")
    if kind == B.FILE_OPEN:
        struct.pack_into("<II", event, 112, mode, 1)
        encoded = path.encode()
        event[120:120 + len(encoded)] = encoded
    elif kind == B.CONNECT:
        ip = ipaddress.ip_address(address)
        struct.pack_into("<q", event, 120, result)
        struct.pack_into("<H", event, 152, 2 if ip.version == 4 else 10)
        event[184:184 + len(ip.packed)] = ip.packed
    elif kind == B.FORK:
        struct.pack_into("<IIIIQ", event, 88, parent, child, reserved, child_tgid, child_start)
    elif kind == B.HEALTH:
        struct.pack_into("<5Q", event, 88, loss, 0, 0, 0, 0)
    return B.FRAME.pack(b"EBPF", 1, 1, 0, size) + event


def run(*frames, **options):
    memory = B.BehaviorMemory(stream_epoch="fixture", **options)
    reviews = list(B.replay(io.BytesIO(b"".join(frames)), memory))
    assert len(memory.tasks) <= memory.max_tasks
    assert len(memory.evidence) <= memory.max_tasks
    return reviews, memory


def check():
    credential = lambda sec, **kw: frame(B.FILE_OPEN, sec, **kw)
    attempt = lambda sec, **kw: frame(B.CONNECT, sec, flags=B.DEST_VALID, result=-111, **kw)
    fork = lambda sec, child, birth, **kw: frame(
        B.FORK, sec, flags=B.FORK_CHILD_ID_VALID, child=child,
        child_tgid=child, child_start=birth, size=376, **kw)

    # The opaque task birth token deliberately exceeds event timestamps.
    reviews, memory = run(credential(1), attempt(601), credential(602), attempt(1202))
    assert [r["episode"] for r in reviews] == [1, 2]
    assert reviews[0]["identity"]["task_start_ns"] == 10**15
    assert not memory.evidence
    assert memory.counts["non_loopback_connect_attempts"] == 2
    output = json.dumps(reviews + [memory.summary()])
    assert "/etc/shadow" not in output and "192.0.2.1" not in output
    assert "BEHAVIOR_REVIEW" in output and "ALERT" not in output

    benign, _ = run(credential(1, path="/etc/hosts"), credential(601, path="/etc/passwd"), attempt(602))
    assert benign == []
    # Labels are neither read nor part of the observable contract.
    labelled = {label: run(credential(1), attempt(601))[0] for label in ("admin", "attack")}
    assert labelled["admin"] == labelled["attack"]

    for change in ({"pid": 20}, {"cgroup": 10}, {"start": 10**15 + 1}):
        other, m = run(credential(1), attempt(601, **change))
        assert other == []
        if "start" in change:
            assert m.counts["pid_reuse"] == 1 and not m.evidence
    # ppid alone and even a well-shaped fork do not transfer a precursor.
    other, m = run(credential(1), attempt(601, pid=11, ppid=10))
    assert other == [] and m.counts["connect_without_direct_precursor"] == 1
    other, m = run(credential(1), frame(B.FORK, 2), attempt(601, pid=11, ppid=10))
    assert other == [] and m.counts["descendant_correlation_unsupported"] == 1
    # A descendant can produce its own direct same-task pair.
    own, _ = run(frame(B.FORK, 1), credential(2, pid=11), attempt(602, pid=11))
    assert len(own) == 1
    other, m = run(credential(1), frame(B.FORK, 2, parent=99), attempt(601))
    assert other == [] and m.counts["unresolved_fork"] == 1

    # Two separate leaf readers and connectors, each tied to the same alive
    # shell generation. No first-seen PID or birth/event clock comparison.
    a, b, c, d = (10**15 + i for i in range(1, 5))
    sibling = [fork(1, 11, a), credential(2, pid=11, start=a),
               frame(B.EXIT, 3, pid=11, start=a), fork(601, 12, b),
               attempt(602, pid=12, start=b)]
    reviews, m = run(*sibling)
    assert len(reviews) == 1 and reviews[0]["scope"] == "verified_task_lineage"
    assert reviews[0]["precursor_identity"]["pid"] == 11
    assert reviews[0]["identity"]["pid"] == 12 and reviews[0]["identity"]["tgid"] == 12
    assert reviews[0]["root_identity"]["pid"] == 10
    assert reviews[0]["attempt_ns"] - reviews[0]["precursor_ns"] == 600 * 10**9
    assert m.counts["verified_fork_edges"] == 2 and m.counts["leaf_exits"] == 1
    assert not m.evidence
    reviews, m = run(*sibling, attempt(603, pid=12, start=b),
                     fork(604, 13, c), credential(605, pid=13, start=c),
                     frame(B.EXIT, 606, pid=13, start=c), fork(1204, 14, d),
                     attempt(1205, pid=14, start=d))
    assert [r["episode"] for r in reviews] == [1, 2]
    assert all(r["scope"] == "verified_task_lineage" for r in reviews)
    assert m.counts["verified_task_lineage_advisories"] == 2
    assert run(*sibling, retention_sec=600)[0] == []

    # A bound child's own pair is still distinguished as direct same-task.
    assert run(fork(1, 11, a), credential(2, pid=11, start=a),
               attempt(602, pid=11, start=a))[0][0]["scope"] == "direct_same_task_only"
    # A root precursor may be followed by its explicitly bound child.
    assert run(credential(1), fork(2, 11, a), attempt(601, pid=11, start=a))[0][0]["scope"] == "verified_task_lineage"
    assert run(fork(1, 11, a), credential(2, pid=11, start=a, path="/etc/hosts"),
               fork(601, 12, b), attempt(602, pid=12, start=b))[0] == []

    prefix = sibling[:4]  # live root, leaf reader exited, connector bound
    for change in ({"pid": 99}, {"start": b + 100}, {"cgroup": 99}):
        reviews, m = run(*prefix, attempt(602, pid=change.get("pid", 12),
                         start=change.get("start", b), cgroup=change.get("cgroup", 9)))
        assert reviews == []
    # Even a subsequent return to the old cgroup does not recover its family.
    assert run(*prefix, attempt(602, pid=12, start=b, cgroup=99),
               attempt(603, pid=12, start=b))[0] == []
    # Missing identity flag/edge, a different creator and a changed root birth
    # cannot use the old family evidence. ppid alone never establishes an edge.
    assert run(*sibling[:3], attempt(602, pid=12, start=b, ppid=10))[0] == []
    assert run(*sibling[:3], frame(B.FORK, 601, child=12), attempt(602, pid=12, start=b))[0] == []
    assert run(*sibling[:3], fork(601, 12, b, pid=20, parent=20),
               attempt(602, pid=12, start=b))[0] == []
    assert run(*sibling[:3], fork(601, 12, b, start=10**15 + 100),
               attempt(602, pid=12, start=b))[0] == []
    assert run(*sibling[:3], frame(B.EXIT, 600), fork(601, 12, b),
               attempt(602, pid=12, start=b))[0] == []
    assert run(*prefix, frame(B.HEALTH, 601.5, loss=1), attempt(602, pid=12, start=b))[0] == []
    uncertain_child = frame(B.CONNECT, 602, pid=12, start=b,
                            flags=B.DEST_VALID | B.PROCESS_UNCERTAIN)
    assert run(*prefix, uncertain_child, attempt(603, pid=12, start=b))[0] == []
    assert run(*prefix, frame(4, 600, pid=12, start=b), attempt(602, pid=12, start=b))[0] == []

    # The typed export exposes thread clones immediately; block that parent
    # generation rather than waiting for a worker to happen to emit activity.
    thread_fork = frame(B.FORK, 601, flags=B.FORK_CHILD_ID_VALID,
                        child=12, child_tgid=10, child_start=b)
    assert run(*sibling[:3], thread_fork, credential(602), attempt(603))[0] == []
    assert run(*prefix, frame(4, 601.5, pid=13, tgid=12, start=d),
               credential(601.6, pid=12, start=b), attempt(602, pid=12, start=b))[0] == []
    # A reset cannot unblock a generation already known to have worker threads.
    assert run(thread_fork, frame(B.HEALTH, 602, loss=1), credential(603), attempt(604))[0] == []
    assert run(thread_fork, credential(602, cgroup=99), attempt(603, cgroup=99))[0] == []
    for overrides in ({"child_start": 0}, {"reserved": 1}, {"parent": 99}):
        options = dict(child=12, child_tgid=12, child_start=b)
        options.update(overrides)
        invalid_fork = frame(B.FORK, 601, flags=B.FORK_CHILD_ID_VALID, **options)
        assert run(*sibling[:3], invalid_fork, attempt(602, pid=12, start=b))[0] == []
    assert run(*prefix, fork(601.5, 12, b), attempt(602, pid=12, start=b))[0] == []
    assert run(*sibling, max_tasks=1)[0] == []
    assert len(run(*sibling, max_tasks=2)[0]) == 1
    # Nested observed creators are supported while both observed parents live;
    # an intermediate parent's exit conservatively invalidates the family too.
    nested = [fork(1, 11, a), fork(2, 21, c, pid=11, parent=11, start=a),
              credential(3, pid=21, start=c), frame(B.EXIT, 4, pid=21, start=c)]
    assert len(run(*nested, fork(601, 12, b), attempt(603, pid=12, start=b))[0]) == 1
    assert run(*nested, frame(B.EXIT, 600, pid=11, start=a),
               fork(601, 12, b), attempt(603, pid=12, start=b))[0] == []
    # An observed root exit after a cgroup move also drops its old family.
    assert run(*sibling[:3], frame(B.EXIT, 600, cgroup=99),
               fork(601, 12, b), attempt(602, pid=12, start=b))[0] == []

    # Compact 360-byte process and 104-byte syscall frames, as well as legacy
    # full 376-byte records, obey type minima with unchanged header offsets.
    compact_fork = frame(B.FORK, 1, flags=B.FORK_CHILD_ID_VALID,
                         child=11, child_tgid=11, child_start=a, size=360)
    assert len(run(compact_fork, credential(2, pid=11, start=a),
                   frame(4, 3, pid=11, start=a, size=104),
                   frame(5, 4, pid=11, start=a, size=104),
                   attempt(602, pid=11, start=a))[0]) == 1
    assert len(run(frame(B.EXEC, 1, size=376), credential(2),
                   frame(4, 3, size=376), attempt(602))[0]) == 1
    assert B.HEADER.size == 88 and B.FRAME.size == 12
    for kind, size in ((B.FORK, 360), (B.EXEC, 360), (B.EXIT, 360), (4, 104), (5, 104)):
        assert B.SIZES[kind] == size

    for path in ("/etc/gshadow", "/root/.ssh/id_ed25519", "/home/alice/.ssh/id_rsa",
                 "/etc/ssh/ssh_host_ed25519_key"):
        assert len(run(credential(1, path=path), attempt(601))[0]) == 1
    for options in ({"flags": 1}, {"flags": 2}, {"flags": 4}, {"result": -13}, {"mode": 2}):
        assert run(credential(1, **options), attempt(601))[0] == []
    unterminated = bytearray(credential(1))
    unterminated[B.FRAME.size + 120:] = b"x" * 256
    assert run(bytes(unterminated), attempt(601))[0] == []
    for destination in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "ff02::1",
                        "::ffff:0.0.0.0", "::ffff:224.0.0.1"):
        assert run(credential(1), attempt(601, address=destination))[0] == []
    assert len(run(credential(1), attempt(601, address="2001:db8::1"))[0]) == 1
    assert len(run(credential(1), attempt(601, address="::ffff:192.0.2.1"))[0]) == 1
    uncertain = frame(B.CONNECT, 601, flags=B.DEST_VALID | B.PROCESS_UNCERTAIN)
    other, m = run(credential(1), uncertain, attempt(602))
    assert other == [] and m.counts["uncertain_process"] == 1
    assert run(credential(1), frame(B.CONNECT, 601))[0] == []

    worker = frame(4, 2, pid=11, tgid=10, start=10**15 + 1)
    other, m = run(credential(1), worker, credential(3), attempt(601))
    assert other == [] and m.counts["unsupported_thread"] == 1
    # Different worker observations must not forget an earlier exclusion.
    other, _ = run(worker, frame(4, 3, pid=21, tgid=20), credential(4), attempt(601))
    assert other == []
    fresh, _ = run(worker, credential(3, start=10**15 + 2), attempt(601, start=10**15 + 2))
    assert fresh == []  # worker-before-leader leaves the leader generation unresolved
    fresh, _ = run(credential(1), worker, credential(3, start=10**15 + 2),
                   attempt(601, start=10**15 + 2))
    assert len(fresh) == 1  # a changed, previously known leader generation starts clean
    assert run(credential(1), frame(B.EXIT, 2), attempt(601))[0] == []
    for unknown in (frame(4, 2, start=0), frame(B.EXEC, 2, start=0)):
        other, m = run(credential(1), unknown, attempt(601))
        assert other == [] and m.counts["unresolved_generation"] == 1
    other, m = run(credential(2), attempt(1), attempt(3))
    assert other == [] and m.counts["unsafe_ordering"] == 1
    other, m = run(credential(1), attempt(1))
    assert other == [] and m.counts["unsafe_ordering"] == 1
    other, m = run(credential(1), frame(B.HEALTH, 2, loss=1), attempt(601))
    assert other == [] and m.counts["health_loss_or_counter_reset"] == 1
    # Unchanged cumulative counters do not perpetually reset fresh evidence.
    fresh, _ = run(frame(B.HEALTH, 1, loss=1), credential(2),
                   frame(B.HEALTH, 3, loss=1), attempt(601))
    assert len(fresh) == 1 and fresh[0]["coverage_confirmed"] is False
    other, m = run(credential(1), attempt(3601))
    assert other == [] and m.counts["retention_precursors_dropped"] == 1
    assert len(run(credential(1), attempt(600), retention_sec=601)[0]) == 1
    other, m = run(credential(1), attempt(601), retention_sec=600)
    assert other == [] and m.counts["retention_precursors_dropped"] == 1
    other, m = run(credential(1), credential(2, pid=20), attempt(601), max_tasks=1)
    assert other == [] and m.counts["capacity_precursors_dropped"] == 2
    for retention in (0, -1, float("nan"), float("inf"), 1e308):
        try:
            B.BehaviorMemory(retention_sec=retention)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid retention accepted")
    limited = B.BehaviorMemory(max_tasks=1)
    try:
        list(B.replay(io.BytesIO(worker + frame(4, 3, pid=21, tgid=20)), limited))
    except ValueError as error:
        assert str(error) == "TASK_CAPACITY_EXHAUSTED" and not limited.tasks
    else:
        raise AssertionError("known thread exclusions evicted")

    # Bad framing/schema clears pending evidence and fails, including EOF tails.
    bad_schema = bytearray(attempt(601))
    struct.pack_into("<H", bad_schema, B.FRAME.size + 68, 2)
    bad_size = bytearray(attempt(601))
    struct.pack_into("<I", bad_size, B.FRAME.size + 60, 376)
    invalid = [attempt(601)[:-1], b"E", bytes(bad_schema), bytes(bad_size),
               B.FRAME.pack(b"EBPF", 1, 1, 0, 2**32 - 1),
               B.FRAME.pack(b"EBPF", 1, 0, 0, 200), b"X" * B.FRAME.size]
    # Complete wire frames that are too short for their declared event type.
    for kind, short in ((B.FORK, 359), (4, 103), (B.FILE_OPEN, 375), (B.CONNECT, 199)):
        invalid.append(frame(kind, 601, size=short))
    for tail in invalid:
        m = B.BehaviorMemory(stream_epoch="fixture")
        try:
            list(B.replay(io.BytesIO(credential(1) + tail), m))
        except ValueError:
            assert not m.evidence and not m.tasks and m.counts["invalid_input"] == 1
        else:
            raise AssertionError("malformed input accepted")

    # CLI emits minimal JSONL and a summary; errors have nonzero status.
    with tempfile.TemporaryDirectory() as temp:
        capture = Path(temp) / "fixture.bin"
        capture.write_bytes(credential(1) + attempt(601))
        command = [sys.executable, str(Path(B.__file__)), str(capture), "--stream-epoch", "fixture"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        lines = [json.loads(line) for line in result.stdout.splitlines()]
        assert lines[0]["type"] == "BEHAVIOR_REVIEW"
        assert lines[-1]["complete_replay"] and lines[-1]["counters"]["advisories"] == 1
        capture.write_bytes(credential(1) + b"E")
        result = subprocess.run(command, capture_output=True, text=True)
        assert result.returncode == 2
        assert json.loads(result.stdout)["complete_replay"] is False
        assert json.loads(result.stderr)["reason_code"] == "TRUNCATED_EOF"
        assert "/etc/shadow" not in result.stdout + result.stderr
    print("behavior_memory: constructed binary regressions passed")


if __name__ == "__main__":
    check()
