"""
eBPF 바이너리 캡처 -> 프로세스 윈도우별 '풍부한' 레코드(JSONL).

기존 bin2traces.py 는 syscall 번호 목록만 뽑아서, "어떤 파일을 열었는지",
"어디로 접속했는지", "어떤 순서였는지"가 전부 사라졌다. 실측 결과
cat /etc/shadow 와 cat /etc/passwd 가 완전히 동일한 피처 벡터가 되어
모델이 원리적으로 구분 불가능했다(점수 소수점 4자리까지 동일).

이 스크립트는 한 프로세스 윈도우에 대해 아래를 모두 보존한다:
  - syscall 시퀀스 (순서 유지 -> n-gram 가능)
  - FILE_OPEN 경로/플래그/접근모드
  - NETWORK_CONNECT 목적지 포트/주소
  - PROCESS_EXEC 실행 파일 경로
  - 프로세스 메타 (uid, ppid, comm)

사용:
  python3 extract.py capture.bin out.jsonl --map syscall_map_x86_64.json \
      [--window 500] [--min-len 5] [--label normal] [--technique baseline]
"""
import argparse, json, os, struct, sys
from collections import defaultdict

FRAME = struct.Struct("<4sBBHI")
U16, U32, U64 = struct.Struct("<H"), struct.Struct("<I"), struct.Struct("<Q")

# agent_event_header (88 bytes)
OFF_TASK_START, OFF_PPID, OFF_UID, OFF_TGID = 16, 40, 44, 28
OFF_TYPE, OFF_COMM = 70, 72
# payload 시작 = 88
OFF_SYSCALL_ID = 88                 # agent_syscall_payload.syscall_id
OFF_FILE_FLAGS, OFF_FILE_MODE = 88 + 20, 88 + 24   # open_flags, f_mode
OFF_FILE_PATH = 88 + 32             # path[256]
OFF_EXEC_FILENAME = 88 + 16         # agent_process_payload.filename[256]
OFF_NET_FAMILY = 88 + 64
OFF_NET_DST_PORT = 88 + 70
OFF_NET_DST_ADDR = 88 + 96
HEALTH = struct.Struct("<QQQQQ")

SYSCALL_ENTER, PROCESS_EXEC, FILE_OPEN, NETWORK_CONNECT, HEALTH_EVENT = 4, 2, 6, 8, 14
CHUNK = 1 << 22


def cstr(buf, off, n):
    return bytes(buf[off:off + n]).split(b"\0", 1)[0].decode("utf-8", "replace")


def ipv4(buf, off):
    b = bytes(buf[off:off + 4])
    return ".".join(str(x) for x in b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("out")
    ap.add_argument("--map", required=True)
    ap.add_argument("--window", type=int, default=500)
    ap.add_argument("--min-len", type=int, default=5)
    ap.add_argument("--label", default="normal")
    ap.add_argument("--technique", default="",
                    help="공격 기법 이름(leave-one-technique-out 평가용)")
    ap.add_argument("--ignore-loss", action="store_true")
    ap.add_argument("--max-records", type=int, default=0,
                    help="이 캡처에서 뽑을 최대 레코드 수(0=제한없음). "
                         "기법마다 syscall 볼륨이 수백배 차이나므로(예: find / 계열은 "
                         "1회에 180만) 상한을 두지 않으면 한 기법이 학습셋을 "
                         "독점한다. 초과 시 reservoir sampling 으로 균등 표본 추출.")
    ap.add_argument("--max-per-unit", type=int, default=300,
                    help="유닛(정상 함수명 / 공격 기법명)마다 뽑을 최대 레코드 수. "
                         "전체 상한(--max-records)만 두면 syscall 볼륨이 큰 유닛이 "
                         "표본을 독점한다(실측: 한 세션에서 find+getcap 이 공격 표본의 "
                         "91%%를 차지). 유닛별로 따로 reservoir 를 돌려 균형을 맞춘다. "
                         "0 이면 끄고 --max-records 로 되돌아간다. 기본값이 0 이 아닌 "
                         "이유: 균형 잡힌 표본이 맞는 기본값이고, 전체 상한만 거는 쪽이 "
                         "특수한 경우이기 때문.")
    ap.add_argument("--slim", action="store_true",
                    help="syscall 배열 대신 통계(개수/종류수/상위빈도)만 남기고 "
                         "표본추출 없이 **모든 윈도우**를 내보낸다. 시간 버킷 집계용. "
                         "집계는 전체 윈도우가 있어야 '3초 안에 프로세스 120개' 같은 "
                         "밀도를 잴 수 있는데, 유닛별 표본추출본으로는 그게 불가능하다.")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--timeline", default="",
                    help="bench.sh 가 남긴 타임라인 TSV(start_ns, end_ns, class, unit). "
                         "주면 --label/--technique 대신 프로세스 윈도우의 시작 시각으로 "
                         "라벨을 결정한다. 어느 유닛 구간에도 속하지 않는 윈도우(수집기 "
                         "자체 소음, 유닛 사이 유휴)는 버린다. 정상/공격을 한 세션 안에 "
                         "섞어 수집했을 때 라벨을 복원하는 유일한 방법.")
    ap.add_argument("--session", default="",
                    help="세션 식별자. leave-one-session-out 평가에 쓴다.")
    a = ap.parse_args()
    import random
    rng = random.Random(a.seed)

    tl = []
    if a.timeline:
        import bisect
        for line in open(a.timeline):
            f = line.split("\t")
            if len(f) >= 4:
                tl.append((int(f[0]), int(f[1]), f[2].strip(), f[3].strip()))
        tl.sort()
        tl_starts = [x[0] for x in tl]

    def label_of(ts):
        """윈도우 시작 ts 가 속한 유닛 구간을 찾는다. 없으면 None(=버림)."""
        i = bisect.bisect_right(tl_starts, ts) - 1
        if i < 0 or ts > tl[i][1]:
            return None
        cls, unit = tl[i][2], tl[i][3]
        return cls, (unit[2:] if cls == "attack" and unit.startswith("t_") else unit)

    M = json.load(open(a.map))
    nr2fid = {int(k): v for k, v in M["nr_to_feature_id"].items()}

    # 윈도우 상태
    sysq = defaultdict(list)       # key -> [fid,...]
    files = defaultdict(list)
    nets = defaultdict(list)
    execs = defaultdict(list)
    meta = {}                      # key -> dict(comm, uid, ppid)
    written = 0          # 실제로 만들어진 윈도우 수(표본추출 전)
    total_sys = unknown = frames = 0
    health = {}
    out = open(a.out, "w") if (a.slim or not (a.max_records or a.max_per_unit)) else None
    strata, seen_u = {}, {}
    reservoir = []       # --max-records 지정 시에만 사용

    def flush(key, force=False):
        nonlocal written
        seq = sysq.get(key, [])
        if len(seq) < a.min_len:
            if force:
                sysq.pop(key, None); files.pop(key, None)
                nets.pop(key, None); execs.pop(key, None)
            return
        m = meta.get(key, {})
        lab, tech = a.label, a.technique
        if tl:
            r = label_of(key[1])
            if r is None:
                sysq[key] = []; files[key] = []; nets[key] = []; execs[key] = []
                return
            lab, tech = r
        rec = {
            "label": lab, "technique": tech, "session": a.session,
            "tgid": key[0], "start": key[1],
            "comm": m.get("comm", "?"), "uid": m.get("uid", -1), "ppid": m.get("ppid", -1),
            "syscalls": seq,
            "files": files.get(key, []),
            "net": nets.get(key, []),
            "execs": execs.get(key, []),
        }
        if a.slim:
            rec.pop("syscalls", None)
            rec["n_syscalls"] = len(seq)
            rec["n_uniq_syscalls"] = len(set(seq))
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            written += 1
            sysq[key] = []; files[key] = []; nets[key] = []; execs[key] = []
            return
        if a.max_per_unit:
            # 유닛별 reservoir. 각 유닛 안에서는 알고리즘 R 로 균등 추출하고,
            # 유닛 사이에는 상한을 똑같이 줘서 볼륨 큰 유닛의 독점을 막는다.
            u = (lab, tech)
            res = strata.setdefault(u, [])
            seen_u[u] = seen_u.get(u, 0) + 1
            if len(res) < a.max_per_unit:
                res.append(rec)
            else:
                j = rng.randrange(seen_u[u])
                if j < a.max_per_unit:
                    res[j] = rec
        elif a.max_records:
            # reservoir sampling (알고리즘 R): 전체를 메모리에 안 올리고
            # 균등 확률 표본을 얻는다. 앞부분만 자르면 프로세스 시작 구간에
            # 편중되므로 반드시 균등 추출이어야 한다.
            if len(reservoir) < a.max_records:
                reservoir.append(rec)
            else:
                j = rng.randrange(written + 1)
                if j < a.max_records:
                    reservoir[j] = rec
        else:
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
        written += 1
        sysq[key] = []
        files[key] = []
        nets[key] = []
        execs[key] = []

    size = os.path.getsize(a.binary)
    buf = b""
    read = 0
    with open(a.binary, "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            read += len(chunk)
            buf = buf + chunk if buf else chunk
            off, n = 0, len(buf)
            while off + FRAME.size <= n:
                magic, wire, little, _res, psize = FRAME.unpack_from(buf, off)
                if magic != b"EBPF" or wire != 1 or little != 1:
                    sys.exit(f"손상된 프레임 (offset {off})")
                po = off + FRAME.size
                if po + psize > n:
                    break
                frames += 1
                etype = U16.unpack_from(buf, po + OFF_TYPE)[0]

                if etype in (SYSCALL_ENTER, FILE_OPEN, NETWORK_CONNECT, PROCESS_EXEC):
                    key = (U32.unpack_from(buf, po + OFF_TGID)[0],
                           U64.unpack_from(buf, po + OFF_TASK_START)[0])
                    # comm 은 execve 완료 후에야 갱신되므로 매번 덮어쓴다(마지막 값 승리)
                    meta[key] = {
                        "comm": cstr(buf, po + OFF_COMM, 16),
                        "uid": U32.unpack_from(buf, po + OFF_UID)[0],
                        "ppid": U32.unpack_from(buf, po + OFF_PPID)[0],
                    }

                    if etype == SYSCALL_ENTER:
                        nr = U32.unpack_from(buf, po + OFF_SYSCALL_ID)[0]
                        fid = nr2fid.get(nr)
                        if fid is None:
                            unknown += 1
                        else:
                            total_sys += 1
                            sysq[key].append(fid)
                            if len(sysq[key]) >= a.window:
                                flush(key)
                    elif etype == FILE_OPEN:
                        files[key].append({
                            "p": cstr(buf, po + OFF_FILE_PATH, 256),
                            "fl": U32.unpack_from(buf, po + OFF_FILE_FLAGS)[0],
                            "m": U32.unpack_from(buf, po + OFF_FILE_MODE)[0],
                        })
                    elif etype == NETWORK_CONNECT:
                        nets[key].append({
                            "port": U16.unpack_from(buf, po + OFF_NET_DST_PORT)[0],
                            "fam": U16.unpack_from(buf, po + OFF_NET_FAMILY)[0],
                            "addr": ipv4(buf, po + OFF_NET_DST_ADDR),
                        })
                    elif etype == PROCESS_EXEC:
                        execs[key].append(cstr(buf, po + OFF_EXEC_FILENAME, 256))

                elif etype == HEALTH_EVENT:
                    h = HEALTH.unpack_from(buf, po + 88)
                    health = dict(zip(("writer_queue_dropped", "writer_priority_dropped",
                                       "kernel_ringbuf_lost", "network_filtered",
                                       "network_rate_limited"), h))
                off = po + psize
            buf = buf[off:]
            if read % (CHUNK * 64) < CHUNK:
                print(f"  {100*read/size:5.1f}%  프레임 {frames:,}  레코드 {written:,}",
                      file=sys.stderr, flush=True)

    for key in list(sysq.keys()):
        flush(key, force=True)

    if a.slim:
        out.close()
        emitted = written
    elif a.max_per_unit:
        with open(a.out, "w") as fh:
            for u in sorted(strata):
                for rec in strata[u]:
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        emitted = sum(len(v) for v in strata.values())
    elif a.max_records:
        with open(a.out, "w") as fh:
            for rec in reservoir:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        emitted = len(reservoir)
    else:
        out.close()
        emitted = written

    w = sys.stderr.write
    w(f"\n프레임 {frames:,}  syscall {total_sys:,}  윈도우 {written:,}\n")
    if (a.max_records or a.max_per_unit) and written > emitted:
        cap = f"유닛당 {a.max_per_unit}" if a.max_per_unit else f"전체 {a.max_records}"
        w(f"표본추출: {written:,} -> {emitted:,} (상한 {cap}, 유닛 {len(strata) or 1}개)\n")
    if unknown:
        w(f"매핑 없는 syscall {unknown:,}\n")
    lost = {k: v for k, v in health.items()
            if k in ("writer_queue_dropped", "writer_priority_dropped",
                     "kernel_ringbuf_lost") and v}
    if lost and not a.ignore_loss:
        w(f"경고: 이벤트 유실 {lost} -> 학습에 쓰지 말 것 (--ignore-loss 로 무시 가능)\n")
        sys.exit(2)
    if written == 0:
        sys.exit("레코드 0개")


if __name__ == "__main__":
    main()
