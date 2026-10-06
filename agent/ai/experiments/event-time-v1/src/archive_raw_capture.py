"""Archive a finished capture; stop and wait for its collector before calling.

The CLI accepts only /whs captures. Tests may pass an explicit allowed_root.
An interrupted publication leaves the raw file and any published artifacts;
existing artifacts are always refused on retry.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _sha256(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _refuse_existing(path):
    try:
        path.lstat()  # Also refuses dangling symlinks.
    except FileNotFoundError:
        return
    raise FileExistsError(f"refusing existing artifact: {path}")


def archive_raw_capture(source, *, allowed_root=Path("/whs")):
    """Return the .bin.zst path; publish a .bin.zst.sha256.json manifest too."""
    source = Path(source)
    info = source.lstat()
    if source.suffix != ".bin" or not stat.S_ISREG(info.st_mode):
        raise ValueError("input must be a regular, non-symlink .bin file")
    source = source.resolve(strict=True)
    if not source.is_relative_to(Path(allowed_root).resolve(strict=True)):
        raise ValueError("input resolves outside allowed_root")
    if stat.S_IMODE(source.parent.stat().st_mode) != 0o700:
        raise ValueError("input directory must have mode 0700")

    destination = source.with_name(source.name + ".zst")
    manifest = destination.with_name(destination.name + ".sha256.json")
    partial = destination.with_name(destination.name + ".partial")
    for path in (destination, partial, manifest):
        _refuse_existing(path)
    identity = _identity(info)

    def unchanged():
        current = source.lstat()
        if (not stat.S_ISREG(current.st_mode)
                or _identity(current) != identity
                or _identity(os.fstat(raw.fileno())) != identity):
            raise RuntimeError("source changed; retaining raw capture")

    partial.mkdir(mode=0o700)  # Exclusive per-capture reservation.
    staged = []
    cleaned = False
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        with os.fdopen(os.open(source, flags), "rb") as raw:
            unchanged()
            original_sha256 = _sha256(raw)
            unchanged()
            raw.seek(0)
            with tempfile.NamedTemporaryFile(dir=partial, delete=False) as compressed:
                archive_stage = Path(compressed.name)  # tempfile creates mode 0600.
                staged.append(archive_stage)
                subprocess.run(["zstd", "-q", "--check", "-c"],
                               stdin=raw, stdout=compressed, check=True)
                compressed.flush()
                os.fsync(compressed.fileno())
            unchanged()

            # Decode to a pipe: native checksum + SHA256, no second raw disk copy.
            command = ["zstd", "-q", "-d", "--check", "-c", "--", str(archive_stage)]
            with subprocess.Popen(command, stdout=subprocess.PIPE) as decoder:
                decoded_sha256 = _sha256(decoder.stdout)
                if decoder.wait():
                    raise subprocess.CalledProcessError(decoder.returncode, command)
            if decoded_sha256 != original_sha256:
                raise RuntimeError("decompressed SHA256 mismatch; retaining raw capture")
            unchanged()
            with archive_stage.open("rb") as compressed:
                archive_sha256 = _sha256(compressed)
            provenance = {
                "source": str(source), "archive": str(destination),
                "source_sha256": original_sha256,
                "source_stat": dict(zip(
                    ("dev", "ino", "size", "mtime_ns", "ctime_ns"), identity)),
                "archive_sha256": archive_sha256,
                "archive_size": archive_stage.stat().st_size,
            }
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                                             dir=partial, delete=False) as record:
                manifest_stage = Path(record.name)
                staged.append(manifest_stage)
                json.dump(provenance, record, sort_keys=True)
                record.write("\n")
                record.flush()
                os.fsync(record.fileno())

            # POSIX rename overwrites; link+unlink publishes atomically without clobber.
            destination.hardlink_to(archive_stage)
            manifest.hardlink_to(manifest_stage)
            for path in staged:
                path.unlink()
            staged.clear()
            partial.rmdir()
            cleaned = True
            directory_fd = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)  # Both verified artifacts are durable first.
            finally:
                os.close(directory_fd)
            unchanged()
            source.unlink()  # Last mutation; every preceding failure retains raw.
        return destination
    finally:
        if not cleaned:
            for path in staged:
                path.unlink(missing_ok=True)
            partial.rmdir()


def main():
    parser = argparse.ArgumentParser(
        description="Archive finished /whs .bin captures; stop and wait for the collector first.")
    parser.add_argument("captures", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        for source in args.captures:
            print(archive_raw_capture(source))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"archive failed: {exc}\n")


if __name__ == "__main__":
    main()
