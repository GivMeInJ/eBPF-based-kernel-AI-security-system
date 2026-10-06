"""Owned-host regression: dummy credential opens, a real sleep, and local refused connects.

No secret contents or remote destinations are used. A BEHAVIOR_REVIEW is an
advisory about observable events, not proof of malicious intent or transfer.
"""
import argparse
import errno
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid

CGROUP_WRAPPER = 'echo $$ > "$1/cgroup.procs" || exit 1; shift; exec "$@"'


def cleanup_job(job, cgroup):
    """An exited leader can leave children; never signal an unowned member."""
    owned = False
    members = [int(pid) for pid in (cgroup / "cgroup.procs").read_text().split()]
    for pid in members:
        try:
            pgid = os.getpgid(pid)
        except ProcessLookupError:
            continue
        if pgid != job.pid:
            raise RuntimeError("unowned cgroup member; refusing process cleanup")
        owned = True
    if job.poll() is None:
        try:
            if os.getpgid(job.pid) != job.pid:
                raise RuntimeError("worker process group changed; refusing cleanup")
            owned = True
        except ProcessLookupError:
            pass
    if owned:
        try:
            os.killpg(job.pid, signal.SIGTERM)
            time.sleep(0.2)
            os.killpg(job.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    job.wait()


def worker(credential, config, address, port, gap):
    def opened(path):
        subprocess.run(["cat", path], stdout=subprocess.DEVNULL, check=True)

    def attempt():
        code = ("import errno,socket,sys; s=socket.socket(); s.settimeout(2); "
                "r=s.connect_ex((sys.argv[1],int(sys.argv[2]))); "
                "s.close(); sys.exit(0 if r==errno.ECONNREFUSED else 1)")
        subprocess.run([sys.executable, "-c", code, address, port], check=True)

    opened(config)
    attempt()
    print(json.dumps({"phase": "admin_config_then_local_attempt", "timestamp_ns": time.monotonic_ns()}), flush=True)
    for episode, delay in ((1, float(gap)), (2, 10)):
        opened(credential)
        print(json.dumps({"phase": "dummy_precursor", "episode": episode,
                          "timestamp_ns": time.monotonic_ns(), "sleep_sec": delay}), flush=True)
        time.sleep(delay)
        attempt()
        print(json.dumps({"phase": "local_attempt", "episode": episode,
                          "timestamp_ns": time.monotonic_ns()}), flush=True)
    opened(credential)  # Precursor without follow-up must not produce a third advisory.
    print(json.dumps({"phase": "precursor_only", "timestamp_ns": time.monotonic_ns()}), flush=True)


def run(agent, out, gap):
    if os.geteuid() != 0 or not 2 <= gap <= 1800:
        raise ValueError("requires root and a gap between 2 and 1800 seconds")
    out = Path(out).resolve()
    if Path("/whs").resolve() not in out.parents:
        raise ValueError("output must be below /whs")
    addresses = json.loads(subprocess.check_output(["ip", "-j", "-4", "addr", "show"]))
    address = next(item["local"] for link in addresses for item in link["addr_info"]
                   if item.get("scope") == "global" and
                   not ipaddress.ip_address(item["local"]).is_loopback)
    token = uuid.uuid4().hex[:12]
    fixture = Path("/home") / ("ebpf-memory-probe-" + token)
    cgroup = Path("/sys/fs/cgroup") / ("behaviorprobe-" + token)
    out.mkdir(mode=0o700, exist_ok=False)
    fixture.mkdir(mode=0o700, exist_ok=False)
    (fixture / ".ssh").mkdir(mode=0o700)
    credential = fixture / ".ssh" / "id_ed25519"
    credential.write_text("dummy regression fixture; not a private key\n")
    credential.chmod(0o600)
    config = out / "admin.conf"
    config.write_text("dummy admin configuration\n")
    config.chmod(0o600)
    cgroup.mkdir(exist_ok=False)
    collector = job = None
    try:
        # A bound, non-listening socket reserves an owned local port. Every
        # connect must be refused; there is no listener or data transfer.
        with socket.socket() as reservation, (out / "collector.log").open("x") as log:
            reservation.bind((address, 0))
            port = str(reservation.getsockname()[1])
            collector = subprocess.Popen(
                [agent, "--fork-identities", "--network-events", "connect", "--target-cgroup",
                 str(cgroup.stat().st_ino), "--queue-capacity", "65536", "--ringbuf-bytes",
                 "67108864", "--format", "binary", "--output", str(out / "capture.bin")],
                stdout=log, stderr=subprocess.STDOUT)
            time.sleep(3)
            if collector.poll() is not None:
                raise RuntimeError("collector startup failed; retained collector.log")
            with (out / "phases.jsonl").open("x") as phases:
                job = subprocess.Popen(
                    ["bash", "-c", CGROUP_WRAPPER,
                     "probe", str(cgroup), sys.executable, str(Path(__file__).resolve()),
                     "--worker", str(credential), str(config), address, port, str(gap)],
                    stdout=phases, stderr=log, start_new_session=True)
                status = job.wait(timeout=gap + 120)
                if status:
                    raise RuntimeError(f"worker failed: {status}")
            time.sleep(3)
            if collector.poll() is not None:
                raise RuntimeError("collector ended before probe completion")
            collector.send_signal(signal.SIGINT)
            if collector.wait(timeout=30):
                raise RuntimeError("collector failed on shutdown")
        result = {"dummy_credentials_only": True, "destination": "owned_local_host",
                  "connect_result_required": errno.ECONNREFUSED, "real_sleep_sec": gap,
                  "fresh_episode_sleep_sec": 10, "expected_advisories": 2,
                  "intent": "regression fixture", "not_an_attack_accuracy_measurement": True}
    finally:
        try:
            if job is not None:
                cleanup_job(job, cgroup)
        finally:
            if collector is not None and collector.poll() is None:
                collector.send_signal(signal.SIGINT)
                try:
                    collector.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    collector.kill()
                    collector.wait()
            if not (cgroup / "cgroup.procs").read_text().strip():
                credential.unlink()
                (fixture / ".ssh").rmdir()
                fixture.rmdir()
                cgroup.rmdir()
            else:
                raise RuntimeError("cgroup cleanup incomplete; artifacts retained")
    (out / "probe.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"completed": str(out), **result}))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        worker(*sys.argv[2:])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--agent", required=True)
        parser.add_argument("--out", required=True)
        parser.add_argument("--gap-sec", type=float, default=600)
        args = parser.parse_args()
        run(args.agent, args.out, args.gap_sec)
