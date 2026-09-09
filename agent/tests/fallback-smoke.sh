#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
set -euo pipefail

agent="${1:-.output/host-events}"
output="$(mktemp /tmp/host-events-fallback.XXXXXX.ndjson)"

cleanup() {
  rm -f "${output}"
}
trap cleanup EXIT

timeout --signal=INT 5 "${agent}" --no-file --no-cgroup-hooks \
  --network-events all --output "${output}" &
reader_pid=$!
sleep 0.7
python3 tests/network-workload.py

set +e
wait "${reader_pid}"
reader_status=$?
set -e
if [[ "${reader_status}" -ne 0 && "${reader_status}" -ne 124 ]]; then
  exit 1
fi
python3 tests/validate-network.py "${output}"
echo "cgroup fallback validation passed"
