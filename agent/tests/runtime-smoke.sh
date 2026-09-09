#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
set -euo pipefail

agent="${1:-.output/host-events}"
process_output="$(mktemp /tmp/host-events-process.XXXXXX.ndjson)"
syscall_output="$(mktemp /tmp/host-events-syscall.XXXXXX.ndjson)"
workload_pid=""

cleanup() {
  if [[ -n "${workload_pid}" ]]; then
    kill "${workload_pid}" 2>/dev/null || true
  fi
  rm -f "${process_output}" "${syscall_output}"
}
trap cleanup EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run this smoke test as root" >&2
  exit 1
fi

timeout --signal=INT 3 "${agent}" --no-file --output "${process_output}" &
reader_pid=$!
sleep 0.5
/bin/sh -c '/usr/bin/true'
python3 -c '
import socket

sock = socket.socket()
sock.connect_ex(("127.0.0.1", 9))
sock.close()
'
set +e
wait "${reader_pid}"
reader_status=$?
set -e
if [[ "${reader_status}" -ne 0 && "${reader_status}" -ne 124 ]]; then
  echo "process sensor exited with ${reader_status}" >&2
  exit 1
fi
grep -q '"event_type":"PROCESS_EXEC"' "${process_output}"
grep -q '"event_type":"NETWORK_CONNECT"' "${process_output}"

python3 -c '
import os
import time

deadline = time.monotonic() + 4
while time.monotonic() < deadline:
    os.stat("/etc/hosts")
    time.sleep(0.005)
' &
workload_pid=$!

set +e
timeout --signal=INT 3 "${agent}" --no-file --syscalls \
  --target-pid "${workload_pid}" --output "${syscall_output}"
reader_status=$?
set -e
wait "${workload_pid}" || true
workload_pid=""

if [[ "${reader_status}" -ne 0 && "${reader_status}" -ne 124 ]]; then
  echo "syscall sensor exited with ${reader_status}" >&2
  exit 1
fi
grep -q '"event_type":"SYSCALL_ENTER"' "${syscall_output}"
grep -q '"event_type":"SYSCALL_EXIT"' "${syscall_output}"
python3 tests/validate-schema.py "${process_output}" "${syscall_output}"

echo "runtime smoke test passed"
