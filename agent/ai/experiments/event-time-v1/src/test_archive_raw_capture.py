"""One small self-check; real zstd roundtrip when the CLI is installed."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from unittest.mock import patch

from archive_raw_capture import archive_raw_capture


def fails(error, action):
    try:
        action()
    except error:
        return
    raise AssertionError(f"expected {error}")


def test():
    with TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        source = root / "capture.bin"
        data = b"temporal replay\x00\xff" * 10000
        source.write_bytes(data)
        destination = root / "capture.bin.zst"
        manifest = root / "capture.bin.zst.sha256.json"
        partial = root / "capture.bin.zst.partial"
        archive = lambda: archive_raw_capture(source, allowed_root=root)

        # Refuse all existing artifacts, including dangling symlinks.
        for blocker in (destination, partial, manifest):
            blocker.symlink_to(root / "missing")
            fails(FileExistsError, archive)
            assert source.read_bytes() == data and blocker.is_symlink()
            blocker.unlink()
        link = root / "link.bin"
        link.symlink_to(source)
        fails(ValueError, lambda: archive_raw_capture(link, allowed_root=root))
        allowed = root / "allowed"
        allowed.mkdir(mode=0o700)
        fails(ValueError, lambda: archive_raw_capture(source, allowed_root=allowed))
        root.chmod(0o755)
        fails(ValueError, archive)
        root.chmod(0o700)

        if not shutil.which("zstd"):
            print("ok: artifact/symlink/permission refusal; SKIP real zstd checks (not installed)")
            return

        before = source.stat()
        assert archive() == destination and not source.exists()
        decoded = subprocess.run(["zstd", "-q", "-d", "-c", "--", str(destination)],
                                 capture_output=True, check=True).stdout
        record = json.loads(manifest.read_text())
        assert decoded == data
        assert record["source_sha256"] == hashlib.sha256(data).hexdigest()
        assert record["archive_sha256"] == hashlib.sha256(destination.read_bytes()).hexdigest()
        assert record["source_stat"]["ino"] == before.st_ino
        assert record["source_stat"]["mtime_ns"] == before.st_mtime_ns
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in (destination, manifest))
        assert not partial.exists()
        destination.unlink()
        manifest.unlink()
        source.write_bytes(data)

        run = subprocess.run

        # A valid, checksummed frame with different bytes must still fail SHA256.
        def corrupt(command, **kwargs):
            return run(command, stdout=kwargs["stdout"], input=b"wrong capture", check=True)

        with patch("archive_raw_capture.subprocess.run", side_effect=corrupt):
            fails(RuntimeError, archive)
        assert source.read_bytes() == data
        assert not any(path.exists() for path in (destination, manifest, partial))

        # Even restored mtime cannot hide a same-size edit (ctime also checked).
        def mutate(command, **kwargs):
            result = run(command, **kwargs)
            before = source.stat()
            source.write_bytes(b"x" * len(data))
            os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
            return result

        with patch("archive_raw_capture.subprocess.run", side_effect=mutate):
            fails(RuntimeError, archive)
        assert source.exists() and not destination.exists() and not partial.exists()
    print("ok: roundtrip, provenance/modes, refusals, corruption and source-change preservation")


if __name__ == "__main__":
    test()
