#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
set -euo pipefail

agent="${1:-.output/host-events}"
output="$(mktemp /tmp/host-events-rate.XXXXXX.ndjson)"
workload_pid=""

cleanup() {
  if [[ -n "${workload_pid}" ]]; then
    kill "${workload_pid}" 2>/dev/null || true
  fi
  rm -f "${output}"
}
trap cleanup EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run this smoke test as root" >&2
  exit 1
fi

python3 tests/rate-workload.py &
workload_pid=$!

set +e
timeout --signal=INT 5 "${agent}" --no-file \
  --target-pid "${workload_pid}" --network-events udp \
  --network-rate 5 --network-burst 2 --output "${output}"
reader_status=$?
set -e
wait "${workload_pid}" || true
workload_pid=""

if [[ "${reader_status}" -ne 0 && "${reader_status}" -ne 124 ]]; then
  echo "rate-limited network sensor exited with ${reader_status}" >&2
  exit 1
fi

python3 tests/validate-rate.py "${output}"
