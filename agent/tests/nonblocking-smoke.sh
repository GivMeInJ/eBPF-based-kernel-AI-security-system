#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
set -euo pipefail

agent="${1:-.output/host-events}"
output="$(mktemp /tmp/host-events-nonblocking.XXXXXX.ndjson)"
workload_pid=""

cleanup() {
  [[ -z "${workload_pid}" ]] || kill "${workload_pid}" 2>/dev/null || true
  rm -f "${output}"
}
trap cleanup EXIT

python3 tests/nonblocking-workload.py &
workload_pid=$!

set +e
timeout --signal=INT 5 "${agent}" --no-file --target-pid "${workload_pid}" \
  --network-events connect --output "${output}"
agent_status=$?
set -e
wait "${workload_pid}" || true
workload_pid=""

if [[ "${agent_status}" -ne 0 && "${agent_status}" -ne 124 ]]; then
  exit 1
fi
python3 tests/validate-nonblocking.py "${output}"
