#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
set -euo pipefail

agent="${1:-.output/host-events}"
binary_output="$(mktemp /tmp/host-events-binary.XXXXXX.bin)"
decoded_output="$(mktemp /tmp/host-events-decoded.XXXXXX.ndjson)"

cleanup() {
  rm -f "${binary_output}" "${decoded_output}"
}
trap cleanup EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run this smoke test as root" >&2
  exit 1
fi

timeout --signal=INT 5 "${agent}" --no-file --network-events all \
  --format binary --output "${binary_output}" &
reader_pid=$!
sleep 0.7
python3 tests/network-workload.py

set +e
wait "${reader_pid}"
reader_status=$?
set -e
if [[ "${reader_status}" -ne 0 && "${reader_status}" -ne 124 ]]; then
  echo "binary network sensor exited with ${reader_status}" >&2
  exit 1
fi

python3 tools/decode-events.py "${binary_output}" > "${decoded_output}"
python3 tests/validate-network.py "${decoded_output}"
python3 tests/validate-schema.py "${decoded_output}"
echo "binary frame validation passed"
