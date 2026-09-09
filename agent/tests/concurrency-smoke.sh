#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
set -euo pipefail

agent="${1:-.output/host-events}"
output="$(mktemp /tmp/host-events-concurrency.XXXXXX.ndjson)"
stats="$(mktemp /tmp/host-events-concurrency.XXXXXX.log)"
workload_pid=""

cleanup() {
  [[ -z "${workload_pid}" ]] || kill "${workload_pid}" 2>/dev/null || true
  rm -f "${output}" "${stats}"
}
trap cleanup EXIT

python3 tests/concurrent-workload.py &
workload_pid=$!

set +e
timeout --signal=INT 8 "${agent}" --no-file --target-pid "${workload_pid}" \
  --network-events connect,accept --queue-capacity 8192 \
  --ringbuf-bytes 8388608 --output "${output}" 2> "${stats}"
agent_status=$?
set -e
wait "${workload_pid}" || true
workload_pid=""

if [[ "${agent_status}" -ne 0 && "${agent_status}" -ne 124 ]]; then
  cat "${stats}" >&2
  exit 1
fi
python3 tests/validate-concurrency.py "${output}"
grep -Eq 'writer queue dropped=0$' "${stats}"
grep -Eq 'ringbuf_lost +0$' "${stats}"
grep -Eq 'map_update_failed +0$' "${stats}"
cat "${stats}"
