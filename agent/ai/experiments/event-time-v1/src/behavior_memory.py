"""Offline, advisory-only schema-v1 replay; never a deployed ALERT policy.

An eligible file_open LSM hook is NOT proof of a completed read. A connect
event is an ATTEMPT (including failed calls), not proof of transfer/exfiltration
or malicious human intent. No secret contents, paths or addresses are emitted.

Same-task leader observations and explicitly exported leader-to-leader fork
identities are supported. Old forks without child identity flag 1<<11 remain
unsupported. A child is matched by cgroup, PID, TGID and opaque start token;
ppid and comparisons between birth tokens and event timestamps are never used.
Family evidence survives a leaf child's exit while its observed root remains
alive. Any observed parent exit, missing edge metadata, loss or uncertainty
invalidates that family. These are verified creator edges, not human identity.
Absence of observed worker threads does not prove a process is single-threaded.
Connect timestamps are syscall-entry times emitted on exit: any backwards
timestamp clears memory, deliberately sacrificing coverage rather than guessing.
Retention uses event timestamps ONLY; task_start_ns is an opaque identity token.
"""

import argparse
from collections import Counter, OrderedDict
import ipaddress
import json
import math
import re
import struct
import sys
import uuid


FRAME = struct.Struct("<4sBBHI")
HEADER = struct.Struct("<QQQIIIIIIIIiIIHH16s")
SIZES = {**dict.fromkeys(range(1, 4), 360), 4: 104, 5: 104, 6: 376, 7: 376,
         **dict.fromkeys(range(8, 14), 200), 14: 128}
FORK, EXEC, EXIT, FILE_OPEN, CONNECT, HEALTH = 1, 2, 3, 6, 8, 14
PATH_BAD, DEST_VALID, PROCESS_UNCERTAIN, USERSPACE = 7, 16, 512, 1024
FORK_CHILD_ID_VALID = 1 << 11
CREDENTIAL = re.compile(
    r"^(/etc/(shadow|gshadow)|/etc/ssh/ssh_host_[^/]+_key|"
    r"/(root|home/[^/]+)/\.ssh/id_(rsa|dsa|ecdsa|ed25519))$")


def read_frame(source):
    def exact(n, eof=False):
        data = bytearray()
        while len(data) < n:
            chunk = source.read(n - len(data))
            if not chunk:
                if eof and not data:
                    return None
                raise ValueError("TRUNCATED_EOF")
            data.extend(chunk)
        return bytes(data)

    wire = exact(FRAME.size, eof=True)
    if wire is None:
        return None
    magic, version, little, reserved, size = FRAME.unpack(wire)
    if (magic, version, little, reserved) != (b"EBPF", 1, 1, 0):
        raise ValueError("INVALID_WIRE_HEADER")
    if not 104 <= size <= 376:
        raise ValueError("INVALID_FRAME_LENGTH")
    return exact(size)


class BehaviorMemory:
    def __init__(self, retention_sec=3600, max_tasks=4096, stream_epoch=None):
        if not math.isfinite(retention_sec * 1e9) or retention_sec <= 0:
            raise ValueError("INVALID_RETENTION")
        if isinstance(max_tasks, bool) or not isinstance(max_tasks, int) or max_tasks < 1:
            raise ValueError("INVALID_TASK_LIMIT")
        self.ttl = int(retention_sec * 1e9)
        if self.ttl < 1:
            raise ValueError("INVALID_RETENTION")
        self.max_tasks = max_tasks
        self.epoch = stream_epoch or str(uuid.uuid4())
        # Every supported task is a leader, so pid == tgid is part of this key.
        self.tasks = OrderedDict()  # (cgroup,pid) -> [start,blocked,root,has_children]
        self.evidence = OrderedDict()  # root/direct identity -> (timestamp,source identity)
        self.counts = Counter()
        self.last_ts = None
        self.health = None

    def clear(self, reason, keep_blocks=True):
        self.counts[reason] += 1
        self.counts["reset_precursors_dropped"] += len(self.evidence)
        self.evidence.clear()
        # A loss/reset must not erase already observed thread exclusions.
        self.tasks = OrderedDict((s, [v[0], True, None, False])
                                 for s, v in self.tasks.items() if keep_blocks and v[1])

    def expire(self, ts):
        while self.evidence and ts - next(iter(self.evidence.values()))[0] >= self.ttl:
            self.evidence.popitem(last=False)
            self.counts["retention_precursors_dropped"] += 1

    def drop_family(self, root, reason):
        self.counts[reason + "_precursors_dropped"] += int(self.evidence.pop(root, None) is not None)
        # ponytail: bounded scan on removal only; index families if this measures slow.
        for slot, state in list(self.tasks.items()):
            if state[2] == root or (self.epoch, *slot, state[0]) == root:
                self.tasks.pop(slot)

    def task(self, cgroup, pid, start):
        slot = (cgroup, pid)
        state = self.tasks.get(slot)
        if state is None and any(s[1] == pid and s[0] != cgroup for s in self.tasks):
            self.clear("cgroup_identity_changed")
        if state is not None and state[0] not in (0, start):
            old_key = (self.epoch, cgroup, pid, state[0])
            self.counts["pid_reuse"] += 1
            self.drop_family(state[2] or old_key, "reuse")
            state = None
        if state is None:
            if slot not in self.tasks and len(self.tasks) >= self.max_tasks:
                # ponytail: bounded LRU; never evict a known thread exclusion.
                victim = next((s for s, v in self.tasks.items() if not v[1]), None)
                if victim is None:
                    self.clear("capacity_exhausted", keep_blocks=False)
                    raise ValueError("TASK_CAPACITY_EXHAUSTED")
                old = self.tasks[victim]
                self.counts["capacity_tasks_dropped"] += 1
                key = (self.epoch, *victim, old[0])
                self.drop_family(old[2] or key, "capacity")
            blocked = any(s[1] == pid and v[1] and v[0] in (0, start)
                          for s, v in self.tasks.items())
            state = [start, blocked, None, False]
            self.tasks[slot] = state
        if state[0] == 0:
            state[0] = start  # retain unknown-thread exclusion; do not unblock
        self.tasks.move_to_end(slot)
        return state

    def root(self, key, state):
        root = state[2]
        if root is None:
            return key
        parent = self.tasks.get((root[1], root[2]))
        if parent is None or parent[0] != root[3] or parent[1]:
            self.clear("unresolved_root_generation")
            return None
        return root

    def block_thread(self, cgroup, tgid):
        known = self.tasks.get((cgroup, tgid))
        leader_start = known[0] if known is not None else 0
        self.clear("unsupported_thread")
        self.task(cgroup, tgid, leader_start)[1] = True

    def fork(self, event, key, state, flags):
        parent, child, reserved, child_tgid, child_start = struct.unpack_from("<IIIIQ", event, 88)
        if parent != key[2] or not child or child == parent:
            self.clear("unresolved_fork")
            return
        if not flags & FORK_CHILD_ID_VALID:
            self.counts["descendant_correlation_unsupported"] += 1
            self.clear("missing_fork_identity")
            return
        if reserved or not child_tgid or not child_start:
            self.clear("unresolved_fork_generation")
            return
        if child != child_tgid:
            self.block_thread(key[1], key[2])
            return
        if state[1]:
            self.counts["blocked_thread_generation"] += 1
            return
        root = self.root(key, state)
        if root is None:
            return
        old_child = self.tasks.get((key[1], child))
        if old_child is not None and (old_child[0] == child_start or old_child[0] == 0):
            # A task cannot be freshly born twice, or be resolved from an unknown thread.
            self.clear("unresolved_fork_generation")
            return
        child_state = self.task(key[1], child, child_start)
        # Reuse/eviction may have removed the old family while admitting the child.
        if self.tasks.get((key[1], key[2])) is not state:
            self.clear("fork_family_invalidated")
            return
        if state[2] is not None and self.root(key, state) is None:
            return
        state[2], state[3] = root, True
        child_state[2] = root
        self.counts["verified_fork_edges"] += 1

    def observe(self, event):
        if len(event) < HEADER.size:
            self.clear("invalid_input")
            raise ValueError("INVALID_EVENT_LENGTH")
        (ts, cgroup, start, pid, tgid, _npid, _ntgid, _ppid, _uid, _gid,
         _cpu, result, size, flags, schema, kind, _comm) = HEADER.unpack_from(event)
        if schema != 1 or not SIZES.get(kind, 377) <= len(event) <= 376 or size != len(event):
            self.clear("invalid_input")
            raise ValueError("INVALID_EVENT_SCHEMA_OR_LENGTH")
        self.counts["frames"] += 1
        if self.last_ts is not None and ts < self.last_ts:
            self.clear("unsafe_ordering")
            self.last_ts = ts
            return None
        self.last_ts = ts
        self.expire(ts)

        if kind == HEALTH:
            values = struct.unpack_from("<5Q", event, 88)
            loss = values[:3] + values[4:]
            previous = self.health
            if (previous is None and any(loss)) or (previous is not None and loss != previous):
                self.clear("health_loss_or_counter_reset")
            self.health = loss
            self.counts["health_frames"] += 1
            self.counts["network_filtered_max"] = max(self.counts["network_filtered_max"], values[3])
            return None
        if flags & (PROCESS_UNCERTAIN | USERSPACE):
            self.clear("uncertain_process")
            return None
        if not pid or not tgid or not start:
            self.clear("unresolved_generation")
            return None
        if pid != tgid:
            self.block_thread(cgroup, tgid)
            return None
        if kind == EXIT and (cgroup, pid) not in self.tasks:
            self.counts["untracked_exit"] += 1

        state = self.task(cgroup, pid, start)
        key = (self.epoch, cgroup, pid, start)
        if kind == EXIT:
            if state[2] is not None and not state[3] and state[2] != key:
                self.tasks.pop((cgroup, pid))  # retain leaf evidence at the alive root
                self.counts["leaf_exits"] += 1
            else:
                self.drop_family(state[2] or key, "exit")
            return None
        if kind == FORK:
            self.fork(event, key, state, flags)
            return None
        if state[1]:
            self.counts["blocked_thread_generation"] += 1
            return None
        root = self.root(key, state)
        if root is None:
            return None
        if kind == FILE_OPEN:
            if flags & PATH_BAD or b"\0" not in event[120:376]:
                self.counts["uncertain_path"] += 1
                return None
            operation, = struct.unpack_from("<I", event, 116)
            mode, = struct.unpack_from("<I", event, 112)
            if operation != 1 or result != 0 or not mode & 1:
                self.counts["ineligible_open_hook"] += 1
                return None
            path = event[120:376].split(b"\0", 1)[0].decode("utf-8", "replace")
            if CREDENTIAL.fullmatch(path):
                self.evidence.pop(root, None)
                self.evidence[root] = (ts, key)
                self.counts["credential_open_hooks"] += 1
            return None
        if kind != CONNECT:
            return None
        if not flags & DEST_VALID:
            self.counts["uncertain_destination"] += 1
            return None
        family, = struct.unpack_from("<H", event, 152)
        if family not in (2, 10):
            self.counts["unsupported_family"] += 1
            return None
        address = ipaddress.ip_address(event[184:188] if family == 2 else event[184:200])
        mapped = getattr(address, "ipv4_mapped", None)
        if address.is_loopback or (mapped is not None and mapped.is_loopback):
            self.counts["loopback_attempts"] += 1
            return None
        destination = mapped if mapped is not None else address
        if destination.is_unspecified or destination.is_multicast:
            self.counts["unsupported_destination"] += 1
            return None
        self.counts["non_loopback_connect_attempts"] += 1
        precursor = self.evidence.get(root)
        if precursor is None:
            self.counts["connect_without_direct_precursor"] += 1
            return None
        precursor_ts, source_key = precursor
        if ts <= precursor_ts:
            self.clear("unsafe_ordering")
            return None
        self.evidence.pop(root)
        self.counts["advisories"] += 1
        scope = "direct_same_task_only" if source_key == key else "verified_task_lineage"
        self.counts[scope + "_advisories"] += 1
        identity = lambda k: {"stream_epoch": k[0], "cgroup_id": k[1],
                              "pid": k[2], "tgid": k[2], "task_start_ns": k[3]}
        return {"type": "BEHAVIOR_REVIEW", "advisory_only": True,
                "scope": scope, "coverage_confirmed": False,
                "reason_codes": ["CREDENTIAL_FILE_OPEN_HOOK", "NON_LOOPBACK_CONNECT_ATTEMPT"],
                "identity": identity(key), "precursor_identity": identity(source_key),
                "root_identity": identity(root),
                "precursor_ns": precursor_ts, "attempt_ns": ts,
                "episode": self.counts["advisories"]}

    def summary(self, complete=True):
        return {"type": "coverage_summary", "advisory_only": True,
                "scope": "direct_same_task_or_verified_task_lineage", "complete_replay": complete,
                "retention_sec": self.ttl / 1e9, "max_tasks": self.max_tasks,
                "pending_precursors": len(self.evidence), "tracked_tasks": len(self.tasks),
                "counters": dict(sorted(self.counts.items())),
                "limitations": ["HOOK_NOT_READ_PROOF", "ATTEMPT_NOT_TRANSFER_PROOF",
                                "NO_INTENT_INFERENCE", "UNFLAGGED_DESCENDANTS_UNSUPPORTED",
                                "CROSS_CGROUP_LINEAGE_UNSUPPORTED",
                                "ABSENCE_OF_THREADS_NOT_PROVEN", "COVERAGE_UNCONFIRMED"]}


def replay(source, memory):
    while True:
        try:
            event = read_frame(source)
        except (ValueError, OSError):
            memory.clear("invalid_input")
            raise
        if event is None:
            return
        advisory = memory.observe(event)
        if advisory is not None:
            yield advisory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", help="offline raw .bin capture, or - for stdin")
    parser.add_argument("--retention-sec", type=float, default=3600)
    parser.add_argument("--max-tasks", type=int, default=4096)
    parser.add_argument("--stream-epoch", default=None)
    args = parser.parse_args()
    try:
        memory = BehaviorMemory(args.retention_sec, args.max_tasks, args.stream_epoch)
    except ValueError as error:
        parser.error(str(error))
    complete = True
    try:
        with (sys.stdin.buffer if args.binary == "-" else open(args.binary, "rb")) as source:
            for advisory in replay(source, memory):
                print(json.dumps(advisory))
    except (ValueError, OSError) as error:
        complete = False
        memory.clear("replay_failed")
        print(json.dumps({"type": "replay_error", "reason_code":
                          str(error) if isinstance(error, ValueError) else "INPUT_IO_ERROR"}),
              file=sys.stderr)
    print(json.dumps(memory.summary(complete)))
    return 0 if complete else 2


if __name__ == "__main__":
    sys.exit(main())
