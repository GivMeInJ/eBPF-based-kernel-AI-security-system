#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
set -euo pipefail

agent="${1:-.output/host-events}"
output="$(mktemp /tmp/host-events-rate-map.XXXXXX.ndjson)"
stats="$(mktemp /tmp/host-events-rate-map.XXXXXX.log)"

cleanup() {
  rm -f "${output}" "${stats}"
}
trap cleanup EXIT

timeout --signal=INT 5 "${agent}" --no-file --network-events all \
  --network-rate 100000 --network-burst 100000 --rate-map-entries 2 \
  --output "${output}" 2> "${stats}" &
reader_pid=$!
sleep 0.7
python3 tests/network-workload.py

set +e
wait "${reader_pid}"
reader_status=$?
set -e
if [[ "${reader_status}" -ne 0 && "${reader_status}" -ne 124 ]]; then
  cat "${stats}" >&2
  exit 1
fi

python3 tests/validate-network.py "${output}"
grep -Eq 'map_update_failed +0$' "${stats}"
cat "${stats}"
echo "rate-limit Map saturation validation passed"
