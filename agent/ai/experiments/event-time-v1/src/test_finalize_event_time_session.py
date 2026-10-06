"""Small fault check: optional socket metadata is accepted only with exact event accounting."""
import copy
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
from unittest.mock import patch

from audit_network_capture import FRAME, audit
from finalize_event_time_session import EVENT_NAMES, check_collection
import finalize_event_time_session as finalizer


def collector(socket_failures):
    counts = {"NETWORK_CONNECT": 940, "NETWORK_BIND": 2}
    return ("writer queue dropped=0\nwriter priority dropped=0\nevent statistics:\n" +
            "".join(f"  {name} received={counts.get(name, 0)} lost=0\n" for name in EVENT_NAMES) +
            "network sensor statistics:\n  map_update_failed 0\n" +
            f"  socket_read_failed {socket_failures}\n" +
            "  ringbuf_lost 0\n  user_read_failed 0\n  filtered 0\n  rate_limited 0\n")


def rejected(log, report):
    try:
        check_collection(log, report)
    except ValueError:
        return
    raise AssertionError("fault accepted")


def test():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        timeline = root / "session.tsv"
        timeline.write_text("1\t200\tnormal\tw_ssh_config\n")
        raw = root / "session.bin"
        for missing in (True, False):
            with raw.open("wb") as stream:
                for number in range(942):
                    payload = bytearray(200)
                    struct.pack_into("<Q", payload, 0, 100)
                    struct.pack_into("<I", payload, 64, 16 if missing and number == 0 else 64)
                    struct.pack_into("<H", payload, 70, 8 if number < 940 else 9)
                    struct.pack_into("<H", payload, 152, 2)
                    stream.write(FRAME.pack(b"EBPF", 1, 1, 0, len(payload)) + payload)
            report = audit(raw, timeline)
            assert report["network_counts"] == {8: 940, 9: 2}
            assert len(report["incomplete_socket_metadata"]) == int(missing)
            valid = check_collection(collector(int(missing)), report)
            assert valid["socket_metadata_complete"] == (not missing)
            if missing:
                assert report["incomplete_socket_metadata"][0] == {
                    "type": 8, "timestamp_ns": 100, "flags": 16, "result": 0,
                    "family": 2, "unit": "w_ssh_config"}
                assert "remain unknown" in valid["note"]
                rejected(collector(0), report)
                rejected(collector(2), report)
                rejected(collector("bad"), report)
                rejected(collector(-1), report)
                rejected(collector(1) + "  socket_read_failed 1\n", report)
                for counter in ("map_update_failed", "user_read_failed", "ringbuf_lost",
                                "rate_limited", "filtered"):
                    rejected(collector(1).replace(f"  {counter} 0", f"  {counter} 1"), report)
                for name in ("queue", "priority"):
                    rejected(collector(1).replace(f"writer {name} dropped=0",
                                                  f"writer {name} dropped=1"), report)
                rejected(collector(1).replace("SYSCALL_ENTER received=0 lost=0",
                                              "SYSCALL_ENTER received=0 lost=1"), report)
                wrong = copy.deepcopy(report)
                wrong["network_counts"][8] -= 1
                rejected(collector(1), wrong)
                wrong = copy.deepcopy(report)
                wrong["network_counts"][10] = 1
                rejected(collector(1).replace("NETWORK_LISTEN received=0",
                                              "NETWORK_LISTEN received=1"), wrong)


def test_publication():
    # Isolate the actual final publication; collector/audit faults are checked above.
    original_resolve, original_link = Path.resolve, Path.hardlink_to
    for collision in (False, True):
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            prefix = root / "session"
            raw = root / "session.bin"
            raw.write_bytes(b"retained raw capture")
            (root / "session.tsv").write_text("".join(
                f"{i * 100 + 1}\t{i * 100 + 2}\t{'attack' if i == 92 else 'normal'}\tunit_{i}\n"
                for i in range(93)))
            (root / "session.collector.log").write_text(collector(0))
            final, partial = root / "session.event_time.npz", root / "session.event_time.partial"

            def resolve(path, *args, **kwargs):
                if path == Path("/whs"):
                    return root
                if path == Path("/whs/session"):
                    return prefix
                return original_resolve(path, *args, **kwargs)

            def build(_diagnostic, _timeline, output, **_kwargs):
                output.write_bytes(b"validated NPZ")
                output.chmod(0o600)
                return dict(normal=1, attack=1, missing_units=[], duplicate_buckets=0,
                            skipped_duplicate=0, skipped_unknown=0, truncated_final_lines=0)

            def link(target, source):
                if collision:
                    target.write_bytes(b"external final")  # After the existence check.
                return original_link(target, source)

            with patch.object(Path, "resolve", resolve), patch.object(Path, "hardlink_to", link), \
                    patch.object(finalizer, "check_closed"), patch.object(finalizer, "build", build), \
                    patch.object(finalizer, "check_health", return_value={}), \
                    patch.object(finalizer.subprocess, "run"), \
                    patch.object(finalizer, "audit", return_value={
                        "network_counts": {8: 940, 9: 2}, "incomplete_socket_metadata": []}):
                if collision:
                    try:
                        finalizer.finalize("/whs/session", 0, 9300, "publication_test")
                    except FileExistsError:
                        pass
                    else:
                        raise AssertionError("late final-file collision accepted")
                else:
                    finalizer.finalize("/whs/session", 0, 9300, "publication_test")
            assert raw.read_bytes() == b"retained raw capture"
            assert final.read_bytes() == (b"external final" if collision else b"validated NPZ")
            assert partial.exists() == collision


if __name__ == "__main__":
    test()
    test_publication()
    print("collector/socket audit faults and exclusive publication checks passed")
