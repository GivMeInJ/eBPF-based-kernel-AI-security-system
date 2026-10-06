"""진단 옵션과 디코딩 최적화를 같은 캡처의 기존 출력과 비교한다."""

import json
import os
import runpy
import select
import signal
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DETECTOR = os.environ.get("DETECTOR", str(ROOT / "detect2.py"))
# Legacy chunk_2.bin has an 8-byte truncated tail; override CAPTURE with a complete capture.
CAPTURE = Path(os.environ.get("CAPTURE", "/whs/data/attack_chunks/chunk_2.bin"))
MODEL = Path(os.environ.get("MODEL", "/whs/model_bucket_data9"))
MAP = Path(os.environ.get("MAP", "/whs/syscall_map_x86_64.json"))
ORIGINAL = os.environ.get("DETECTOR_ORIGINAL")

# --header-only runs locally without the server capture/model dependencies.
module = runpy.run_path(DETECTOR)
EX = module["EX"]
header = bytes(range(88))
assert module["EVENT_HEADER"].size == 88
assert module["EVENT_HEADER"].unpack(header) == (
    int.from_bytes(header[:8], "little"),
    int.from_bytes(header[EX.OFF_TGID:EX.OFF_TGID + 4], "little"),
    int.from_bytes(header[EX.OFF_PPID:EX.OFF_PPID + 4], "little"),
    int.from_bytes(header[EX.OFF_UID:EX.OFF_UID + 4], "little"),
    int.from_bytes(header[60:64], "little"),
    int.from_bytes(header[68:70], "little"),
    int.from_bytes(header[EX.OFF_TYPE:EX.OFF_TYPE + 2], "little"),
    header[EX.OFF_COMM:EX.OFF_COMM + 16],
)
if "--header-only" in sys.argv:
    print("OK: header metadata matches original byte decoding")
    sys.exit(0)

def run(*extra, detector=DETECTOR, stdin_capture=False):
    command = [
        sys.executable, detector,
        "--model", str(MODEL), "--map", str(MAP),
        "--input", "-" if stdin_capture else str(CAPTURE),
        "--quiet", "--explain", "--threshold", "0", *extra,
    ]
    if stdin_capture:
        with CAPTURE.open("rb") as source:
            return subprocess.check_output(command, stdin=source,
                stderr=subprocess.DEVNULL).decode().splitlines()
    return subprocess.check_output(command, stderr=subprocess.DEVNULL).decode().splitlines()


def idle_output(detector, interrupt=False):
    with CAPTURE.open("rb") as source:
        while True:
            frame = source.read(EX.FRAME.size)
            assert len(frame) == EX.FRAME.size, "no activity frame for idle check"
            payload = source.read(EX.FRAME.unpack(frame)[-1])
            if EX.U16.unpack_from(payload, EX.OFF_TYPE)[0] != EX.HEALTH_EVENT:
                break
    proc = subprocess.Popen([
        sys.executable, detector, "--model", str(MODEL), "--map", str(MAP),
        "--threshold", "0", "--grace-sec", "0.05",
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        proc.stdin.write(frame + payload + (b"E" if interrupt else b""))
        proc.stdin.flush()
        assert select.select([proc.stdout], [], [], 30)[0], "idle bucket did not finalize"
        line = proc.stdout.readline().decode().strip()
        assert line and proc.poll() is None, "expected finalization before EOF"
        if interrupt:
            proc.send_signal(signal.SIGINT)
        else:
            proc.stdin.close()
        assert proc.wait(timeout=10) == 0
        assert proc.stdout.read() == b"", "idle bucket emitted twice at EOF"
        return [line]
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def reject_malformed(tmp):
    wire = lambda size: EX.FRAME.pack(b"EBPF", 1, 1, 0, size)
    def payload(etype, size, version=1, declared_size=None):
        data = bytearray(size)
        EX.U32.pack_into(data, 60, size if declared_size is None else declared_size)
        EX.U16.pack_into(data, 68, version)
        EX.U16.pack_into(data, EX.OFF_TYPE, etype)
        return data
    cases = {
        "truncated_header": (b"EBPF", "EOF"),
        "truncated_payload": (wire(376) + payload(4, 88, declared_size=376), "EOF"),
        "short_header_size": (wire(87), "프레임 크기"),
        "oversize": (wire(377), "프레임 크기"),
    }
    for etype, minimum in ((2, 360), (4, 104), (6, 376), (8, 200), (14, 128)):
        data = payload(etype, minimum - 1)
        cases[f"short_type_{etype}"] = (wire(len(data)) + data, "이벤트 크기/유형")
    for version in (0, 2):
        cases[f"schema_{version}"] = (wire(128) + payload(14, 128, version=version), "이벤트 스키마")
    for declared_size in (127, 129):
        cases[f"declared_size_{declared_size}"] = (
            wire(128) + payload(14, 128, declared_size=declared_size), "이벤트 선언 크기")
    cases["valid_health"] = (wire(128) + payload(14, 128), None)
    for name, (data, message) in cases.items():
        capture = Path(tmp) / (name + ".bin")
        capture.write_bytes(data)
        for use_stdin in (False, True):
            with capture.open("rb") as source:
                result = subprocess.run([
                    sys.executable, DETECTOR, "--model", str(MODEL), "--map", str(MAP),
                    "--input", "-" if use_stdin else str(capture),
                ], stdin=source if use_stdin else subprocess.DEVNULL,
                    capture_output=True, timeout=30)
            assert (result.returncode == 0 if message is None else
                    result.returncode != 0 and message in result.stderr.decode()), (
                name, use_stdin, result.returncode, result.stderr)
    print("OK: truncated frame headers/payloads and invalid sizes rejected in file/stdin modes")


with tempfile.TemporaryDirectory() as tmp:
    reject_malformed(tmp)
    diagnostic = Path(tmp) / "diagnostic.jsonl"
    summary = Path(tmp) / "summary.jsonl"
    plain = run()
    enabled = run("--diagnostic-log", str(diagnostic))
    summarized = run("--diagnostic-log", str(summary), "--diagnostic-summary-only")
    assert run("--threshold", "2") == []
    without_clock = lambda lines: [
        {k: v for k, v in json.loads(line).items() if k != "ts"}
        for line in lines
    ]
    assert plain and without_clock(plain) == without_clock(enabled)
    assert without_clock(plain) == without_clock(summarized)
    records = [json.loads(line) for line in diagnostic.read_text().splitlines()]
    buckets = [r for r in records if r["type"] == "bucket"]
    assert buckets and any(r["type"] == "health" for r in records)
    assert all(len(r["features"]) == 31 for r in buckets)
    assert all(r["bucket_ns"] <= r["first_event_ns"] <= r["last_event_ns"]
               < r["bucket_ns"] + 1_000_000_000 for r in buckets)
    assert all({"tgid", "ppid", "uid", "comm"} <= p.keys()
               for r in buckets for p in r["processes"])
    assert os.stat(diagnostic).st_mode & 0o777 == 0o600
    summary_records = [json.loads(line) for line in summary.read_text().splitlines()]
    summary_buckets = [r for r in summary_records if r["type"] == "bucket"]
    assert len(summary_buckets) == len(buckets)
    assert all(len(r["features"]) == 31 and "processes" not in r
               and {"n_procs", "n_syscalls", "n_files", "n_exec", "n_net", "comms"} <= r.keys()
               for r in summary_buckets)
    assert [r["features"] for r in summary_buckets] == [r["features"] for r in buckets]
    assert [(r["first_event_ns"], r["last_event_ns"]) for r in summary_buckets] == [
        (r["first_event_ns"], r["last_event_ns"]) for r in buckets]
    assert [r for r in summary_records if r["type"] == "health"] == [
        r for r in records if r["type"] == "health"]
    assert os.stat(summary).st_mode & 0o777 == 0o600
    assert without_clock(idle_output(DETECTOR)) == without_clock(
        idle_output(DETECTOR, interrupt=True))
    if ORIGINAL:
        original_diagnostic = Path(tmp) / "original.jsonl"
        original = run("--diagnostic-log", str(original_diagnostic), detector=ORIGINAL)
        assert without_clock(plain) == without_clock(original)
        assert without_clock(diagnostic.read_text().splitlines()) == without_clock(
            original_diagnostic.read_text().splitlines())
        assert without_clock(run(stdin_capture=True)) == without_clock(
            run(detector=ORIGINAL, stdin_capture=True))
        assert without_clock(idle_output(DETECTOR)) == without_clock(idle_output(ORIGINAL))
        print("OK: original/candidate scores, features, process metadata, HEALTH, stdin EOF and idle match")
    print(f"OK: 경보 {len(plain)}건 동일, 진단 버킷 {len(buckets)}건, HEALTH 포함")
