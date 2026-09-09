#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd "${script_dir}/.." && pwd)"
tool="${project_root}/.compat-tools/bpfcompat-linux-amd64"
loader="${project_root}/.output/host-events-static"
workdir="${EBPF_AGENT_VM_WORKDIR:-${XDG_CACHE_HOME:-${HOME:-/var/tmp}/.cache}/ebpf-agent/bpfcompat-work}"

if [[ ! -x "${tool}" ]]; then
  echo "missing ${tool}; install the checksum-verified v0.3.6 binary first" >&2
  exit 1
fi
if [[ ! -x "${loader}" ]]; then
  echo "missing static loader; run make static first" >&2
  exit 1
fi
install -d -m 700 "${workdir}"

exec "${tool}" test-command \
  --cmd '$BPFCOMPAT_BIN --self-test --no-file --network-events all --format binary --output /tmp/ebpf-agent-self-test.bin' \
  --bin "${loader}" \
  --matrix "${script_dir}/kernel-matrix.yaml" \
  --out "${script_dir}/local-report.json" \
  --markdown "${script_dir}/local-report.md" \
  --timeout 8m \
  --concurrency 3 \
  --workdir "${workdir}"
