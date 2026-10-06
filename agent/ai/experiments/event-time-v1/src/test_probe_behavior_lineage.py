"""Check the fixture sequence without opening files, connecting or sleeping."""
import contextlib
import io
import json
from pathlib import Path
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from probe_behavior_lineage import CGROUP_WRAPPER, cleanup_job, worker


if __name__ == "__main__":
    with patch("probe_behavior_lineage.subprocess.run") as run, \
            patch("probe_behavior_lineage.time.sleep") as sleep, \
            contextlib.redirect_stdout(io.StringIO()) as output:
        worker("dummy-key", "admin-config", "192.0.2.1", "54321", "600")
    assert [call.args[0] for call in sleep.call_args_list] == [600, 10]
    commands = [call.args[0] for call in run.call_args_list]
    assert [cmd[1] for cmd in commands if cmd[0] == "cat"] == [
        "admin-config", "dummy-key", "dummy-key", "dummy-key"]
    attempts = [cmd for cmd in commands if "-c" in cmd]
    assert len(attempts) == 3 and all("ECONNREFUSED" in cmd[2] for cmd in attempts)
    records = [json.loads(line) for line in output.getvalue().splitlines()]
    assert [r["episode"] for r in records if r["phase"] == "local_attempt"] == [1, 2]
    assert records[-1]["phase"] == "precursor_only"
    with TemporaryDirectory() as directory:
        root = Path(directory)
        sentinel = root / "must-not-run"
        failed = subprocess.run(["bash", "-c", CGROUP_WRAPPER, "probe", str(root / "missing"),
                                 sys.executable, "-c", "from pathlib import Path; import sys; "
                                 "Path(sys.argv[1]).touch()", str(sentinel)], capture_output=True)
        assert failed.returncode != 0 and not sentinel.exists()
        (root / "cgroup.procs").write_text("456\n")
        job = SimpleNamespace(pid=123, poll=lambda: 0, wait=lambda: None)
        with patch("probe_behavior_lineage.os.getpgid", return_value=123), \
                patch("probe_behavior_lineage.os.killpg") as kill, \
                patch("probe_behavior_lineage.time.sleep"):
            cleanup_job(job, root)
        assert [c.args for c in kill.call_args_list] == [(123, signal.SIGTERM), (123, signal.SIGKILL)]
        with patch("probe_behavior_lineage.os.getpgid", return_value=999), \
                patch("probe_behavior_lineage.os.killpg") as kill:
            try:
                cleanup_job(job, root)
            except RuntimeError:
                pass
            else:
                raise AssertionError("unowned group accepted")
            kill.assert_not_called()
    print("fixture sequence passed without files, network or waits")
