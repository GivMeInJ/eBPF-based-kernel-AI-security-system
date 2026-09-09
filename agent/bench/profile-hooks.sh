#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
set -euo pipefail

agent="${1:-.output/host-events}"
event_count="${2:-100000}"
test_dir="$(mktemp -d /tmp/ebpf-agent-profile.XXXXXX)"
workload_output="${test_dir}/workload.json"
agent_log="${test_dir}/agent.log"
bpftool_bin="${BPFTOOL:-$(find /usr/lib/linux-tools-* -maxdepth 1 \
  -type f -name bpftool | sort -V | tail -n 1)}"
workload_pid=""
agent_pid=""
original_bpf_stats="$(sysctl -n kernel.bpf_stats_enabled)"

cleanup() {
  [[ -z "${workload_pid}" ]] || kill "${workload_pid}" 2>/dev/null || true
  [[ -z "${agent_pid}" ]] || kill -INT "${agent_pid}" 2>/dev/null || true
  sysctl -q -w "kernel.bpf_stats_enabled=${original_bpf_stats}" >/dev/null || true
  rm -f "${workload_output}" "${agent_log}"
  rmdir "${test_dir}" 2>/dev/null || true
}
trap cleanup EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run this profiler as root" >&2
  exit 1
fi
test -x "${bpftool_bin}"
sysctl -q -w kernel.bpf_stats_enabled=1 >/dev/null

python3 bench/udp-benchmark.py --count "${event_count}" --delay 1.5 \
  > "${workload_output}" &
workload_pid=$!
timeout --signal=INT 7 "${agent}" --no-file --target-pid "${workload_pid}" \
  --network-events udp --format binary --queue-capacity 65536 \
  --allow-special-output --output /dev/null >/dev/null 2>"${agent_log}" &
agent_pid=$!

wait "${workload_pid}" || true
workload_pid=""
"${bpftool_bin}" -j prog show name trace_sendto_enter | jq '
  (if type == "array" then .[0] else . end) as $p
  | {
      program: $p.name,
      run_count: $p.run_cnt,
      run_time_ns: $p.run_time_ns,
      average_ns_per_call:
        (if ($p.run_cnt // 0) > 0 then $p.run_time_ns / $p.run_cnt else 0 end)
    }'
wait "${agent_pid}" || true
agent_pid=""
cat "${workload_output}"
grep -E 'writer queue dropped|ringbuf_lost' "${agent_log}"
