"""Small checksum-to-audit source-change regression check; parser is tested separately."""
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import run_temporal_unlink_audits as runner


def test():
    with TemporaryDirectory() as directory:
        prefix = str(Path(directory) / "session")
        capture = Path(prefix + ".bin.zst")
        capture.write_bytes(b"original")
        Path(prefix + ".event_time.npz").write_bytes(b"npz")
        Path(prefix + ".collector.log").write_text("collector")
        Path(prefix + ".network.audit.json").write_text('{"network_counts": {}}')
        Path(prefix + ".bin.zst.sha256.json").write_text(json.dumps({"archive_sha256": hashlib.sha256(b"original").hexdigest()}))
        def substitute(*args):
            return {"recorded_file_unlink": 0, "npz_buckets": 1}
        with patch.object(runner, "check_closed"), patch.object(runner, "check_collection", return_value={"received": {"FILE_UNLINK": 0}}), patch.object(runner, "temporal_features"), patch.object(runner, "audit", substitute):
            result = runner.audit_prefix(prefix)
            assert result["archive_sha256"] == hashlib.sha256(b"original").hexdigest()
            assert len(result["input_source_stat"]) == 5
            def mutated(*args):
                capture.write_bytes(b"changed after checksum")
                return substitute()
            with patch.object(runner, "audit", mutated):
                try:
                    runner.audit_prefix(prefix)
                except ValueError as exc:
                    assert "identity changed" in str(exc)
                else:
                    raise AssertionError("changed capture published with stale checksum")
    print("checksum/audit input-identity race check passed (parser/quality stand-ins)")


if __name__ == "__main__":
    test()
