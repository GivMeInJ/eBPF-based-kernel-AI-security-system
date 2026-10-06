"""
실시간 탐지기 — 버킷 계층 단독 구성.

구 detect.py 와 무엇이 다른가
-----------------------------
구버전은 누수를 발견하기 전에 만든 것이라 지금 평가 결과와 연결되어 있지 않다.

  구 detect.py                    이 파일
  syscall 빈도 1,155차원      ->  버킷 집계 25차원
  프로세스 윈도우 단위 판정    ->  1초 버킷 단위 (실제 경보 단위)
  고정 임계값 0.5            ->  학습 정상 버킷 분위수
  하드코딩 민감파일 규칙 3개   ->  없음 (구조적 피처가 대신한다)

왜 버킷 단독인가: 정책 비교에서 윈도우 모델과 결합하면 미지 계열 탐지가
81.8% -> 31.2% 로 떨어졌다. 한쪽이 명확히 우월할 때 결합은 손해다.

피처 계산은 aggregate.py 의 bucket_features() 를 그대로 쓴다.
같은 계산을 두 곳에 구현하면 학습 피처와 추론 피처가 조용히 어긋난다.

사용:
  host-events --syscalls-enter-only --format binary --output - | \
      detect2.py --model model_bucket --map syscall_map_x86_64.json
"""
import argparse, json, logging, os, select, struct, sys, time
from collections import defaultdict
from logging.handlers import RotatingFileHandler
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extract as EX
from aggregate import FEATURES, PermLookup, bucket_features
from feature_schema import apply_feature_mask

# agent_event_header: timestamp, tgid, ppid, uid, size, schema, type, comm (88 bytes).
EVENT_HEADER = struct.Struct("<Q20xI8xII12xI4xHH16s")
MAX_EVENT_SIZE = 376
# Schema 1 minima from producer minimum_event_size(), including the 88-byte header.
MIN_EVENT_SIZES = {
    **dict.fromkeys(range(1, 4), 360), **dict.fromkeys(range(4, 6), 104),
    **dict.fromkeys(range(6, 8), 376), **dict.fromkeys(range(8, 14), 200),
    14: 128,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="train_bucket.py 가 만든 디렉터리")
    ap.add_argument("--map", required=True)
    ap.add_argument("--input", default="-", help="바이너리 프레임 소스 (기본 stdin)")
    ap.add_argument("--threshold", type=float, default=None,
                    help="meta.json 의 값을 덮어쓴다(시험용)")
    ap.add_argument("--grace-sec", type=float, default=2.0,
                    help="이 시간만큼 지난 버킷을 확정한다(이벤트 도착 순서 흔들림 흡수)")
    ap.add_argument("--quiet", action="store_true", help="정상 버킷은 출력 생략")
    ap.add_argument("--explain", action="store_true",
                    help="경보에 기여 피처와 대표 경로를 붙인다")
    ap.add_argument("--diagnostic-log", default="",
                    help="모든 관측 버킷의 점수·프로세스 요약·센서 유실을 기록 (64 MiB x 3)")
    ap.add_argument("--diagnostic-summary-only", action="store_true",
                    help="진단 버킷에서 프로세스별 실행 파일·경로 정보를 제외")
    a = ap.parse_args()

    diag = None
    if a.diagnostic_log:
        os.umask(0o077)  # 회전 후 새 파일도 원본과 같이 0600
        try:
            handler = RotatingFileHandler(a.diagnostic_log, maxBytes=64 << 20,
                                          backupCount=2, encoding="utf-8")
        except OSError as e:
            sys.stderr.write(f"진단 기록 비활성화: {e}\n")
        else:
            diag = logging.getLogger("detect2.diagnostic")
            diag.setLevel(logging.INFO)
            diag.propagate = False
            handler.setFormatter(logging.Formatter("%(message)s"))
            diag.addHandler(handler)

    import joblib
    meta = json.load(open(os.path.join(a.model, "meta.json")))
    model = joblib.load(os.path.join(a.model, "bucket_model.pkl"))
    thr = a.threshold if a.threshold is not None else meta["threshold"]
    BN = int(meta["bucket_sec"] * 1e9)
    raw_names = meta["feature_names"]
    excluded = meta.get("excluded_features", [])
    if raw_names != FEATURES:
        ap.error("모델과 수집 피처 이름/순서가 다름")
    if not isinstance(excluded, list) or set(excluded) - set(raw_names):
        ap.error("잘못된 excluded_features")
    names = [name for name in raw_names if name not in excluded]
    if model.n_features_in_ != len(names) or list(model.classes_) != [0, 1]:
        ap.error("모델의 입력 차원/클래스 순서가 다름")
    imp = model.feature_importances_
    M = json.load(open(a.map))
    nr2fid = {int(k): v for k, v in M["nr_to_feature_id"].items()}
    perm = PermLookup()

    # 버킷 -> tgid -> 레코드
    buckets = defaultdict(lambda: defaultdict(
        lambda: {"tgid": 0, "comm": "?", "uid": -1, "files": [], "net": [],
                 "execs": [], "n_syscalls": 0, "_uniq": set(), "_comm": None}))
    n_alert = n_norm = 0
    last_ts = 0
    bucket_bounds = {}

    def finalize(b):
        nonlocal n_alert, n_norm
        procs = buckets.pop(b, None)
        if not procs:
            return
        recs = []
        for tg, r in procs.items():
            r["tgid"] = tg
            r["n_uniq_syscalls"] = len(r.pop("_uniq"))
            recs.append(r)
        raw_x = np.array([bucket_features(recs, perm)], dtype=np.float32)
        x = apply_feature_mask(raw_x, raw_names, excluded)
        score = float(model.predict_proba(x)[0, 1])
        hit = score >= thr
        out = {
            "verdict": "ALERT" if hit else "normal",
            "score": round(score, 4), "threshold": round(thr, 4),
            "bucket_ns": int(b * BN), "ts": time.time(),
            "n_procs": len(recs),
            "n_syscalls": sum(r["n_syscalls"] for r in recs),
            "n_files": sum(len(r["files"]) for r in recs),
            "comms": sorted({r["comm"] for r in recs})[:8],
        }
        if diag:
            # Diagnostics retain the raw schema for dataset builders; the model
            # scores the persisted column selection, identically to training.
            record = {"type": "bucket", **out, "features": raw_x[0].tolist(),
                      "n_exec": sum(len(r["execs"]) for r in recs),
                      "n_net": sum(len(r["net"]) for r in recs)}
            record["first_event_ns"], record["last_event_ns"] = bucket_bounds.pop(b)
            if a.diagnostic_summary_only:
                record["comms"] = sorted({r["comm"] for r in recs})
            else:
                processes = []
                for r in recs:
                    paths = []
                    for f in r["files"]:
                        p = f["p"]
                        if p not in paths:
                            paths.append(p)
                        if len(paths) == 4:
                            break
                    processes.append({
                        "tgid": r["tgid"], "ppid": r["ppid"], "uid": r["uid"],
                        "comm": r["comm"], "n_syscalls": r["n_syscalls"],
                        "n_uniq_syscalls": r["n_uniq_syscalls"],
                        "n_files": len(r["files"]), "n_exec": len(r["execs"]),
                        "n_net": len(r["net"]), "execs": r["execs"][:2],
                        "paths": paths,
                    })
                record["processes"] = processes
            diag.info(json.dumps(record, ensure_ascii=False))
        if hit:
            n_alert += 1
            if a.explain:
                # 이 버킷에서 정상 평균 대비 튄 피처를 중요도 가중으로 제시
                dev = x[0] * imp
                rank = np.argsort(dev)[::-1][:5]
                out["drivers"] = [[names[j], round(float(x[0][j]), 4)] for j in rank]
                paths = [f["p"] for r in recs for f in r["files"]]
                uniq = []
                for p in paths:
                    if p not in uniq:
                        uniq.append(p)
                    if len(uniq) >= 8:
                        break
                out["sample_paths"] = uniq
        else:
            n_norm += 1
            if a.quiet:
                return
        print(json.dumps(out, ensure_ascii=False), flush=True)

    src = sys.stdin.buffer if a.input == "-" else open(a.input, "rb")
    is_pipe = a.input == "-"
    fd = src.fileno() if is_pipe else None
    # 버킷별 '마지막으로 이벤트를 받은 벽시계 시각'. 실시간 스트림에서 트래픽이
    # 멈추면 이벤트 ts 기반 cutoff 가 전진하지 않아 tail 버킷이 영영 확정되지
    # 않는다(오프라인은 EOF 가 flush 하지만 파이프는 EOF 가 없다).
    # 벽시계로 grace 초 이상 조용한 버킷을 확정한다.
    bucket_seen = {}
    buf = b""
    try:
        while True:
            if is_pipe:
                # grace 주기로 깨어나 유휴 버킷을 확정한다.
                r, _, _ = select.select([fd], [], [], a.grace_sec)
                if not r:
                    nowm = time.monotonic()
                    for b in sorted(buckets):
                        if nowm - bucket_seen.get(b, nowm) >= a.grace_sec:
                            finalize(b); bucket_seen.pop(b, None)
                    continue
            chunk = src.read1(1 << 20) if hasattr(src, "read1") else src.read(1 << 20)
            if not chunk:
                if buf:
                    sys.exit(f"잘린 프레임 (EOF, 잔여 {len(buf)} bytes)")
                break
            buf = buf + chunk if buf else chunk
            off, n = 0, len(buf)
            seen_in_chunk = set()
            while off + EX.FRAME.size <= n:
                magic, wire, little, _res, psize = EX.FRAME.unpack_from(buf, off)
                if magic != b"EBPF" or wire != 1 or little != 1 or _res != 0:
                    sys.exit(f"손상된 프레임 (offset {off})")
                if not EVENT_HEADER.size <= psize <= MAX_EVENT_SIZE:
                    sys.exit(f"잘못된 프레임 크기 (size {psize})")
                po = off + EX.FRAME.size
                if po + psize > n:
                    break
                ev = buf[po:po + psize]
                off = po + psize

                ts, tgid, ppid, uid, declared_size, schema, etype, comm_raw = EVENT_HEADER.unpack_from(ev)
                if schema != 1:
                    sys.exit(f"잘못된 이벤트 스키마 (schema {schema})")
                if declared_size != psize:
                    sys.exit(f"잘못된 이벤트 선언 크기 (header {declared_size}, frame {psize})")
                if psize < MIN_EVENT_SIZES.get(etype, MAX_EVENT_SIZE + 1):
                    sys.exit(f"잘못된 이벤트 크기/유형 (type {etype}, size {psize})")
                # HEALTH 는 에이전트가 스스로 만드는 통계 이벤트라
                # 프로세스 활동이 아니다. 넣으면 syscall 0개짜리 가짜
                # 프로세스가 모든 버킷에 끼어 피처를 왜곡한다.
                if etype == EX.HEALTH_EVENT:
                    if diag:
                        diag.info(json.dumps({
                            "type": "health", "timestamp_ns": ts,
                            **dict(zip(("writer_queue_dropped", "writer_priority_dropped",
                                        "kernel_ringbuf_lost", "network_filtered",
                                        "network_rate_limited"),
                                       EX.HEALTH.unpack_from(ev, 88))),
                        }))
                    continue
                b = ts // BN
                last_ts = max(last_ts, ts)
                if diag:
                    bounds = bucket_bounds.setdefault(b, [ts, ts])
                    if ts < bounds[0]: bounds[0] = ts
                    if ts > bounds[1]: bounds[1] = ts
                seen_in_chunk.add(b)
                r = buckets[b][tgid]
                if comm_raw != r["_comm"]:
                    r["_comm"] = comm_raw
                    r["comm"] = comm_raw.split(b"\0", 1)[0].decode("utf-8", "replace") or r["comm"]
                r["uid"] = uid
                r["ppid"] = ppid

                if etype == EX.SYSCALL_ENTER:
                    nr = EX.U32.unpack_from(ev, EX.OFF_SYSCALL_ID)[0]
                    fid = nr2fid.get(nr)
                    if fid is not None:
                        r["n_syscalls"] += 1
                        r["_uniq"].add(fid)
                elif etype == EX.FILE_OPEN:
                    r["files"].append({
                        "p": EX.cstr(ev, EX.OFF_FILE_PATH, 256),
                        "fl": int.from_bytes(ev[EX.OFF_FILE_FLAGS:EX.OFF_FILE_FLAGS + 4], "little"),
                        "m": int.from_bytes(ev[EX.OFF_FILE_MODE:EX.OFF_FILE_MODE + 4], "little"),
                    })
                elif etype == EX.PROCESS_EXEC:
                    r["execs"].append(EX.cstr(ev, EX.OFF_EXEC_FILENAME, 256))
                elif etype == EX.NETWORK_CONNECT:
                    r["net"].append({
                        "port": int.from_bytes(
                            ev[EX.OFF_NET_DST_PORT:EX.OFF_NET_DST_PORT + 2], "little"),
                        "addr": EX.ipv4(ev, EX.OFF_NET_DST_ADDR),
                    })

            buf = buf[off:] if off else buf

            # 확정: (1) 이벤트 ts 로 grace 지난 버킷 (2) 벽시계로 grace 조용한 버킷
            cutoff = (last_ts - int(a.grace_sec * 1e9)) // BN
            nowm = time.monotonic()
            # ponytail: 청크 처리 완료 시각을 공유한다. 유휴 확정 오차는 청크 처리 시간 이하.
            for b in seen_in_chunk:
                bucket_seen[b] = nowm
            for b in sorted(buckets):
                if b < cutoff or nowm - bucket_seen.get(b, nowm) >= a.grace_sec:
                    finalize(b); bucket_seen.pop(b, None)
    except KeyboardInterrupt:
        pass

    for b in sorted(buckets):          # 스트림 끝: 남은 버킷 전부 확정
        finalize(b)
    sys.stderr.write(f"\n종료: ALERT {n_alert}건 / normal {n_norm}건  "
                     f"(임계값 {thr:.4f}, 버킷 {meta['bucket_sec']}초)\n")


if __name__ == "__main__":
    main()
