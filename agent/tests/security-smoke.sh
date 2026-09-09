#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
set -euo pipefail

agent="${1:-.output/host-events}"
test_dir="$(mktemp -d /tmp/ebpf-agent-security.XXXXXX)"
agent_pid=""

cleanup() {
  [[ -z "${agent_pid}" ]] || kill -INT "${agent_pid}" 2>/dev/null || true
  rm -rf -- "${test_dir}"
}
trap cleanup EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run this smoke test as root" >&2
  exit 1
fi

# CLI-controlled allocations and unsigned IDs must stay inside hard limits.
if "${agent}" --queue-capacity 7 >/dev/null 2>&1 ||
   "${agent}" --ringbuf-bytes 134217728 >/dev/null 2>&1 ||
   "${agent}" --rate-map-entries 65537 >/dev/null 2>&1 ||
   "${agent}" --target-cgroup -1 >/dev/null 2>&1; then
  echo "agent accepted an unsafe resource/identifier value" >&2
  exit 1
fi

# A privileged output must not follow a symlink or truncate its target.
printf 'safe-marker\n' > "${test_dir}/victim"
ln -s "${test_dir}/victim" "${test_dir}/symlink-output"
if "${agent}" --self-test --no-file --no-cgroup-hooks \
  --network-events none --output "${test_dir}/symlink-output" \
  >/dev/null 2>"${test_dir}/symlink-error"; then
  echo "agent accepted a symbolic-link output" >&2
  exit 1
fi
grep -q '^safe-marker$' "${test_dir}/victim"

# An attacker-created FIFO must not block startup or receive audit records.
mkfifo "${test_dir}/untrusted-fifo"
if timeout 2 "${agent}" --self-test --no-file --no-cgroup-hooks \
  --network-events none --output "${test_dir}/untrusted-fifo" \
  >/dev/null 2>"${test_dir}/fifo-error"; then
  echo "agent accepted a special output without an explicit opt-in" >&2
  exit 1
fi

# Existing audit data must be preserved and regular output must be mode 0600.
printf 'preserve-me\n' > "${test_dir}/events.ndjson"
chmod 0644 "${test_dir}/events.ndjson"
"${agent}" --self-test --no-file --no-cgroup-hooks \
  --network-events none --output "${test_dir}/events.ndjson" \
  >/dev/null 2>"${test_dir}/append-error"
[[ "$(stat -c '%a' "${test_dir}/events.ndjson")" == "600" ]]
[[ "$(head -n 1 "${test_dir}/events.ndjson")" == "preserve-me" ]]
grep -q '"event_type":"HEALTH"' "${test_dir}/events.ndjson"
python3 - "${test_dir}/events.ndjson" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    events = [json.loads(line) for line in stream if line.startswith("{")]
health = [event for event in events if event["event_type"] == "HEALTH"]
assert health
assert health[-1]["uid"] == 65534
assert health[-1]["gid"] == 65534
PY

# Explicit privilege retention and a custom drop identity must be honored.
"${agent}" --self-test --no-file --no-cgroup-hooks --network-events none \
  --retain-privileges --output "${test_dir}/retain.ndjson" \
  >/dev/null 2>"${test_dir}/retain-error"
"${agent}" --self-test --no-file --no-cgroup-hooks --network-events none \
  --run-as 65533:65533 --output "${test_dir}/run-as.ndjson" \
  >/dev/null 2>"${test_dir}/run-as-error"
python3 - "${test_dir}/retain.ndjson" "${test_dir}/run-as.ndjson" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    retained = [json.loads(line) for line in stream]
with open(sys.argv[2], encoding="utf-8") as stream:
    dropped = [json.loads(line) for line in stream]
assert retained[-1]["event_type"] == "HEALTH" and retained[-1]["uid"] == 0
assert dropped[-1]["event_type"] == "HEALTH"
assert dropped[-1]["uid"] == 65533 and dropped[-1]["gid"] == 65533
PY

# Oversized and type-truncated binary frames must fail before allocation/decode.
python3 - "${test_dir}/oversized.bin" "${test_dir}/short.bin" <<'PY'
import struct
import sys

frame = struct.Struct("<4sBBHI")
with open(sys.argv[1], "wb") as stream:
    stream.write(frame.pack(b"EBPF", 1, 1, 0, 1 << 30))

payload = struct.pack(
    "<QQQ8IiIIHH16s",
    0, 0, 0,
    1, 1, 1, 1, 0, 0, 0, 0,
    0, 88, 0, 1, 6, b"crafted",
)
with open(sys.argv[2], "wb") as stream:
    stream.write(frame.pack(b"EBPF", 1, 1, 0, len(payload)))
    stream.write(payload)
PY
if python3 tools/decode-events.py "${test_dir}/oversized.bin" \
  >/dev/null 2>"${test_dir}/oversized-error"; then
  echo "decoder accepted an oversized frame" >&2
  exit 1
fi
grep -q 'invalid frame payload size' "${test_dir}/oversized-error"
if python3 tools/decode-events.py "${test_dir}/short.bin" \
  >/dev/null 2>"${test_dir}/short-error"; then
  echo "decoder accepted a truncated FILE_OPEN frame" >&2
  exit 1
fi
grep -q 'invalid payload size for FILE_OPEN' "${test_dir}/short-error"

# Linux comm/path bytes must always produce UTF-8 JSON, even for invalid bytes.
timeout --signal=INT 3 "${agent}" --no-file --no-cgroup-hooks \
  --network-events udp --network-rate 1 --network-burst 1 \
  --output "${test_dir}/utf8.ndjson" \
  >/dev/null 2>"${test_dir}/utf8-error" &
agent_pid=$!
sleep 0.5
python3 - <<'PY'
import ctypes
import socket

ctypes.CDLL(None).prctl(15, ctypes.c_char_p(b"\xffevil"), 0, 0, 0)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b"x", ("127.0.0.1", 9))
sock.close()
PY
python3 -c 'import ctypes,socket; ctypes.CDLL(None).prctl(15,ctypes.c_char_p(b"rate-a"),0,0,0); s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"a",("127.0.0.1",9)); s.close()'
python3 -c 'import ctypes,socket; ctypes.CDLL(None).prctl(15,ctypes.c_char_p(b"rate-b"),0,0,0); s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"b",("127.0.0.1",9)); s.close()'
set +e
wait "${agent_pid}"
agent_status=$?
set -e
agent_pid=""
if [[ "${agent_status}" -ne 0 && "${agent_status}" -ne 124 ]]; then
  cat "${test_dir}/utf8-error" >&2
  exit 1
fi
python3 - "${test_dir}/utf8.ndjson" <<'PY'
import json
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()
assert b"\xff" not in data
events = [json.loads(line.decode("utf-8")) for line in data.splitlines()]
udp_comms = {
    event["comm"]
    for event in events
    if event["event_type"] == "NETWORK_UDP_SEND"
}
assert {"rate-a", "rate-b"} <= udp_comms
PY

echo "security smoke test passed"
