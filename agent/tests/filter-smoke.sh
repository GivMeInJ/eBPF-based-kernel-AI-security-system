#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
set -euo pipefail

agent="${1:-.output/host-events}"
output="$(mktemp /tmp/host-events-filter.XXXXXX.ndjson)"

cleanup() {
  rm -f "${output}"
}
trap cleanup EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run this smoke test as root" >&2
  exit 1
fi

timeout --signal=INT 5 "${agent}" --no-file \
  --network-events udp --network-protocol udp --network-port 9 \
  --ringbuf-bytes 1048576 --output "${output}" &
reader_pid=$!
sleep 0.7
python3 tests/network-workload.py

set +e
wait "${reader_pid}"
reader_status=$?
set -e
if [[ "${reader_status}" -ne 0 && "${reader_status}" -ne 124 ]]; then
  echo "filtered network sensor exited with ${reader_status}" >&2
  exit 1
fi

python3 tests/validate-filter.py "${output}"
