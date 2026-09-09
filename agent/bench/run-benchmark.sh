#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
set -euo pipefail

agent="${1:-.output/host-events}"
event_count="${2:-50000}"
test_dir="$(mktemp -d /tmp/host-events-benchmark.XXXXXX)"
binary_output="${test_dir}/events.bin"
workload_result="${test_dir}/workload.json"
agent_result="${test_dir}/agent-time.txt"
agent_log="${test_dir}/agent.log"
workload_pid=""

cleanup() {
  [[ -z "${workload_pid}" ]] || kill "${workload_pid}" 2>/dev/null || true
  rm -f "${binary_output}" "${workload_result}" "${agent_result}" "${agent_log}"
  rmdir "${test_dir}" 2>/dev/null || true
}
trap cleanup EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run this benchmark as root" >&2
  exit 1
fi

python3 bench/udp-benchmark.py --count "${event_count}" --delay 1.5 \
  > "${workload_result}" &
workload_pid=$!

set +e
/usr/bin/time -q -f 'elapsed_sec=%e\nuser_sec=%U\nsystem_sec=%S\nmax_rss_kb=%M' \
  -o "${agent_result}" timeout --signal=INT 6 "${agent}" --no-file \
  --target-pid "${workload_pid}" --network-events udp \
  --format binary --queue-capacity 65536 --ringbuf-bytes 8388608 \
  --output "${binary_output}" 2> "${agent_log}"
agent_status=$?
set -e
wait "${workload_pid}" || true
workload_pid=""

if [[ "${agent_status}" -ne 0 && "${agent_status}" -ne 124 ]]; then
  cat "${agent_log}" >&2
  exit 1
fi

emitted="$(python3 tools/decode-events.py "${binary_output}" \
  --count --event-type NETWORK_UDP_SEND)"
sent="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sent"])' \
  "${workload_result}")"

cat "${workload_result}"
cat "${agent_result}"
grep -E 'writer queue dropped|ringbuf_lost' "${agent_log}"
echo "emitted=${emitted}"
echo "capture_ratio=$(python3 -c 'import sys; print(f"{int(sys.argv[1])/int(sys.argv[2]):.6f}")' "${emitted}" "${sent}")"
