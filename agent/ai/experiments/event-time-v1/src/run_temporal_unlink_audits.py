"""Audit accepted existing captures in sequence, preserving a log and exclusive output."""
import argparse
import hashlib
import json
from pathlib import Path

from audit_unlink_buckets import audit
from finalize_event_time_session import check_closed, check_collection, snapshot
from temporal_unlinks import temporal_features


def audit_prefix(prefix):
    capture, npz, proof_path, log_path, network_path = [Path(prefix + suffix) for suffix in
        (".bin.zst", ".event_time.npz", ".bin.zst.sha256.json", ".collector.log", ".network.audit.json")]
    sources = snapshot([capture, npz, proof_path, log_path, network_path])
    check_closed(sources)
    proof = json.loads(proof_path.read_text())
    digest = hashlib.sha256(capture.read_bytes()).hexdigest()
    if digest != proof["archive_sha256"]:
        raise ValueError("archive checksum mismatch")
    network = json.loads(network_path.read_text())
    network["network_counts"] = {int(k): v for k, v in network["network_counts"].items()}
    quality = check_collection(log_path.read_text(), network)
    result = audit(capture, npz, quality["received"]["FILE_UNLINK"])
    temporal_features(result)
    result["archive_sha256"] = digest
    result["npz_sha256"] = hashlib.sha256(npz.read_bytes()).hexdigest()
    result["collector_quality"] = quality
    if snapshot(list(sources)) != sources:
        raise ValueError("input identity changed across checksum/audit/quality validation")
    check_closed(sources)
    result["input_source_stat"] = {str(path): list(identity) for path, identity in sources.items()}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    parser.add_argument("prefix", nargs=6, help="six accepted session prefixes (without suffix)")
    args = parser.parse_args()
    destination = Path(args.output)
    destination.mkdir(mode=0o700, exist_ok=False)
    for number, prefix in enumerate(args.prefix, 1):
        result = audit_prefix(prefix)
        with (destination / f"session_{number}.unlink.audit.json").open("x") as stream:
            json.dump(result, stream, indent=2, allow_nan=False)
        print(f"session {number}/6: {result['npz_buckets']} buckets, {result['recorded_file_unlink']} matched unlink attempts", flush=True)
    (destination / "audits.complete").write_text("six closed, checksum-verified captures audited\n")


if __name__ == "__main__":
    main()
