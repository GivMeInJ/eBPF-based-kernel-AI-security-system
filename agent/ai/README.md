# AI training pipeline

The collector's binary syscall stream becomes a normal-only IsolationForest
model. Collect normal workload data on the Linux machine that will run
detection later.

Install the dependencies and build the map once:

```bash
pip3 install -r ai/requirements.txt
sudo apt-get install -y auditd
python3 ai/syscall_map.py /path/to/OSCAIR_Syscall_Map.txt --output syscall_map_x86_64.json
```

Collect only a dedicated cgroup. The model uses syscall entry IDs only.

```bash
CGID=$(stat -c %i /sys/fs/cgroup/trainset)
sudo .output/host-events --syscalls-enter-only --no-file --network-events none \
  --target-cgroup "$CGID" --queue-capacity 65536 --ringbuf-bytes 67108864 \
  --format binary --output normal.bin
```

Convert only captures whose final collector statistics report zero queue and
ring-buffer drops. The converter also rejects a lossy capture.

```bash
python3 ai/bin2traces.py normal.bin traces --map syscall_map_x86_64.json
python3 ai/train.py traces --map syscall_map_x86_64.json --output model
```

Keep `model.pkl`, `syscall_map_x86_64.json`, and `meta.json` together when
deploying. Raw production captures are ignored by Git because they may disclose
workload information. Commit the generated model bundle when it is appropriate
to share it with the team.
