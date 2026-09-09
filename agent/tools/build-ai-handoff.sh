#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd "${script_dir}/.." && pwd)"
bundle_id="ai-handoff-schema-v1-20260909"
output_root="${1:-${project_root}/dist}"
staging_root="$(mktemp -d /var/tmp/ebpf-agent-handoff.XXXXXX)"
verify_root="$(mktemp -d /var/tmp/ebpf-agent-handoff-verify.XXXXXX)"
bundle="${staging_root}/${bundle_id}"

cleanup() {
  rm -rf -- "${staging_root}" "${verify_root}"
}
trap cleanup EXIT

for command in python3 sha256sum tar zip unzip; do
  command -v "${command}" >/dev/null
done
test -x "${project_root}/.output/host-events-static"
test ! -e "${output_root}/${bundle_id}"
test ! -e "${output_root}/${bundle_id}.tar.gz"
test ! -e "${output_root}/${bundle_id}.zip"
test ! -e "${output_root}/${bundle_id}.ARCHIVE_SHA256SUMS"

install -d -m 0755 \
  "${bundle}/bin" "${bundle}/docs" "${bundle}/include" \
  "${bundle}/samples" "${bundle}/tools"
install -m 0755 "${project_root}/.output/host-events-static" \
  "${bundle}/bin/host-events-static"
install -m 0755 "${project_root}/tools/decode-events.py" \
  "${bundle}/tools/decode-events.py"
install -m 0755 "${project_root}/tools/generate-handoff-samples.py" \
  "${bundle}/tools/generate-handoff-samples.py"
install -m 0755 "${project_root}/tools/validate-handoff-bundle.py" \
  "${bundle}/tools/validate-handoff-bundle.py"
install -m 0644 "${project_root}/docs/ai-handoff-v1.md" \
  "${bundle}/AI_HANDOFF_GUIDE.md"
install -m 0644 "${project_root}/docs/event-schema-v1.md" \
  "${bundle}/docs/event-schema-v1.md"
install -m 0644 "${project_root}/docs/event-schema-v1.schema.json" \
  "${bundle}/docs/event-schema-v1.schema.json"
install -m 0644 "${project_root}/VALIDATION_REPORT.md" \
  "${bundle}/docs/VALIDATION_REPORT.md"
install -m 0644 "${project_root}/include/agent_events.h" \
  "${bundle}/include/agent_events.h"

python3 "${project_root}/tools/generate-handoff-samples.py" \
  "${bundle}/samples"
python3 "${bundle}/tools/decode-events.py" \
  "${bundle}/samples/events-v1.bin" \
  > "${bundle}/samples/events-v1.ndjson"
chmod 0644 "${bundle}/samples/"*

collector_sha="$(sha256sum "${bundle}/bin/host-events-static" | cut -d' ' -f1)"
sample_count="$(python3 "${bundle}/tools/decode-events.py" \
  "${bundle}/samples/events-v1.bin" --count)"
created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "${bundle}/BUNDLE_MANIFEST.json" "${collector_sha}" \
  "${sample_count}" "${created_at}" <<'PY'
import json
import sys

manifest = {
    "handoff_id": "ebpf-agent-ai-handoff-schema-v1-20260909",
    "bundle_version": "2026.09.09-schema-v1",
    "created_at_utc": sys.argv[4],
    "event_schema_version": 1,
    "wire_version": 1,
    "target": {
        "os": "Linux",
        "architecture": "x86_64",
        "endianness": "little",
        "minimum_tested_kernel": "5.15.0-190-generic",
    },
    "collector": {
        "path": "bin/host-events-static",
        "sha256": sys.argv[2],
        "default_drop_identity": "65534:65534",
        "output_policy": "append, no symlink/hardlink, regular file mode 0600",
    },
    "sample_event_count": int(sys.argv[3]),
    "sample_kind": "deterministic_sanitized_fixture",
    "tested_kernels": [
        "5.15.0-190-generic",
        "6.1.0-52-cloud-amd64",
        "6.6.145-bpf-lsm",
        "6.8.0-138-generic",
        "6.18.33.1-microsoft-standard-WSL2",
    ],
    "validation": {
        "build": "PASS",
        "functional_smoke": "PASS",
        "security_smoke": "PASS",
        "asan_ubsan": "PASS",
        "bpf_lsm_file_open_unlink": "PASS",
        "kernel_compatibility_matrix": "PASS",
    },
    "labels_embedded_in_events": False,
}
with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as stream:
    json.dump(manifest, stream, ensure_ascii=False, indent=2)
    stream.write("\n")
PY
chmod 0644 "${bundle}/BUNDLE_MANIFEST.json"

(
  cd "${bundle}"
  find . -type f ! -name SHA256SUMS -printf '%P\n' \
    | LC_ALL=C sort \
    | while IFS= read -r path; do sha256sum "${path}"; done \
    > SHA256SUMS
)
python3 "${bundle}/tools/validate-handoff-bundle.py" "${bundle}"

tar --sort=name --owner=0 --group=0 --numeric-owner \
  -czf "${staging_root}/${bundle_id}.tar.gz" \
  -C "${staging_root}" "${bundle_id}"
(
  cd "${staging_root}"
  zip -q -X -r "${bundle_id}.zip" "${bundle_id}"
  sha256sum "${bundle_id}.tar.gz" "${bundle_id}.zip" \
    > "${bundle_id}.ARCHIVE_SHA256SUMS"
  sha256sum -c "${bundle_id}.ARCHIVE_SHA256SUMS" >/dev/null
)

install -d -m 0755 "${verify_root}/tar" "${verify_root}/zip"
tar -xzf "${staging_root}/${bundle_id}.tar.gz" -C "${verify_root}/tar"
unzip -q "${staging_root}/${bundle_id}.zip" -d "${verify_root}/zip"
python3 "${verify_root}/tar/${bundle_id}/tools/validate-handoff-bundle.py" \
  "${verify_root}/tar/${bundle_id}"
python3 "${verify_root}/zip/${bundle_id}/tools/validate-handoff-bundle.py" \
  "${verify_root}/zip/${bundle_id}"
test -x "${verify_root}/tar/${bundle_id}/bin/host-events-static"
test -x "${verify_root}/zip/${bundle_id}/bin/host-events-static"

mkdir -p "${output_root}"
cp -R "${bundle}" "${output_root}/${bundle_id}"
cp "${staging_root}/${bundle_id}.tar.gz" \
  "${output_root}/${bundle_id}.tar.gz"
cp "${staging_root}/${bundle_id}.zip" \
  "${output_root}/${bundle_id}.zip"
cp "${staging_root}/${bundle_id}.ARCHIVE_SHA256SUMS" \
  "${output_root}/${bundle_id}.ARCHIVE_SHA256SUMS"

printf '%s\n' \
  "bundle=${output_root}/${bundle_id}" \
  "tar=${output_root}/${bundle_id}.tar.gz" \
  "zip=${output_root}/${bundle_id}.zip" \
  "archive_checksums=${output_root}/${bundle_id}.ARCHIVE_SHA256SUMS"
