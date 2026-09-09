#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
set -euo pipefail

agent="${1:-.output/host-events}"
test_dir="$(mktemp -d /tmp/host-events-backpressure.XXXXXX)"
fifo="${test_dir}/events.fifo"
stats="${test_dir}/stats.log"
captured="${test_dir}/captured.bin"
health="${test_dir}/health.ndjson"
workload_pid=""
reader_pid=""

cleanup() {
  [[ -z "${workload_pid}" ]] || kill "${workload_pid}" 2>/dev/null || true
  [[ -z "${reader_pid}" ]] || kill "${reader_pid}" 2>/dev/null || true
  rm -f "${fifo}" "${stats}" "${captured}" "${health}"
  rmdir "${test_dir}" 2>/dev/null || true
}
trap cleanup EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run this smoke test as root" >&2
  exit 1
fi

mkfifo "${fifo}"
python3 tests/slow-reader.py "${fifo}" "${captured}" &
reader_pid=$!
python3 bench/udp-benchmark.py --count 10000 --delay 1 > /dev/null &
workload_pid=$!

set +e
timeout --signal=INT 5 "${agent}" --no-file \
  --target-pid "${workload_pid}" --network-events udp \
  --format binary --queue-capacity 8 --allow-special-output \
  --output "${fifo}" 2> "${stats}"
agent_status=$?
set -e
wait "${workload_pid}" || true
workload_pid=""
wait "${reader_pid}" || true
reader_pid=""

if [[ "${agent_status}" -ne 0 && "${agent_status}" -ne 124 ]]; then
  cat "${stats}" >&2
  exit 1
fi
grep -Eq 'writer queue dropped=[1-9][0-9]*' "${stats}"
python3 tools/decode-events.py "${captured}" --event-type HEALTH > "${health}"
python3 - "${health}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    events = [json.loads(line) for line in stream]
assert events
assert any(event["writer_queue_dropped"] > 0 for event in events)
PY
cat "${stats}"
echo "backpressure validation passed"
