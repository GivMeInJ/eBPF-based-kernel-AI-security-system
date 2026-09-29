"""
시간 버킷 집계 — 단일 프로세스 창으로는 없는 정보를 만든다.

왜 필요한가
-----------
정찰(recon)은 프로세스 하나만 보면 정상 관리 작업과 구분이 불가능하다.
실측: 정상 `w_proc` 과 공격 `t_proc_enum` 은 글자 그대로 같은 명령이고,
이것이 오탐의 84% 와 정찰 LOTO 0.9~7% 를 동시에 설명한다.

구분 신호는 상위 계층에 있다. `cat /proc/1/status` 한 번은 무해하지만
"3초 안에 서로 다른 프로세스 120개가 /proc 을 훑고, 그중 일부가 권한 없는
파일을 건드렸다" 는 다르다. 그 정보는 프로세스 창 하나에는 없고 버킷에만 있다.

주의 — 순환 논리 금지
--------------------
집계 단위를 '유닛 경계'로 잡으면 라벨을 보고 자르는 셈이라 무의미하다.
반드시 **고정 시간 버킷**으로 자르고, 한 버킷에 두 클래스가 섞인 비율을
같이 보고한다(섞임이 많으면 이 접근 자체가 성립하지 않는다).
정상 쪽에도 대량 작업(grep -r, lsof, find, tar)이 들어 있으므로
"양이 많으면 공격" 이라는 지름길은 데이터가 막아 준다.

사용: python3 aggregate.py all.jsonl out.npz [--bucket-sec 5]
"""
import argparse, json, os
from collections import defaultdict
import numpy as np

FEATURES = [
    "n_windows_log",          # 버킷 안 프로세스 창 수
    "n_procs_log",            # 서로 다른 tgid 수
    "n_comms_log",            # 서로 다른 프로그램 수
    "n_syscalls_log",         # 총 syscall
    "syscall_diversity",      # 서로 다른 syscall 종류 / 총량
    "n_files_log",            # 총 파일 접근
    "n_uniq_files_log",       # 서로 다른 경로 수
    "n_uniq_dirs_log",        # 서로 다른 디렉터리 수
    "files_per_proc",         # 프로세스당 파일 접근 (훑는 강도)
    "frac_missing",           # 존재하지 않는 경로 비율 (탐침 시도)
    "frac_not_world_readable",# 권한 없는 파일 비율
    "frac_other_owner",
    "frac_setuid",
    "frac_hidden",
    "frac_write",
    "proc_pid_breadth_log",   # /proc/<숫자> 중 서로 다른 pid 수  <- 정찰 핵심
    "proc_pid_frac",          # /proc/<숫자> 접근이 전체 파일 접근에서 차지하는 비율
    "sensitive_dir_breadth",  # /etc /root /home 중 서로 다른 디렉터리 수
    "max_path_depth",
    "mean_path_depth",
    "n_net_log",
    "n_net_dst_log",
    "n_exec_log",
    "exec_per_proc",
    "n_uniq_syscalls_log",
    # 디렉터리 분포 — "얼마나 많이 읽었나" 가 아니라 "어디를 읽었나".
    #
    # 실측 동기: 수용 시험에서 처음 보는 공격 kmod_probe(0/6), cred_grep(0/2)을
    # 전부 놓쳤다. 그 버킷들은 정상보다 파일을 11배 읽는데도(n_files_log 8.35 vs
    # 5.92) 점수가 0.13~0.32 였다. 학습셋의 공격이 쓰기(frac_write 0.079)와
    # 민감파일(0.124) 쪽에 치우쳐 있어서, '대량으로 읽기만 하는 공격' 축을
    # 배운 적이 없었기 때문이다.
    # 정상 w_grep 도 /usr/include 를 대량으로 읽으므로 '많이 읽는다' 만으로는
    # 구분이 안 된다. 구분되는 것은 **어디를** 읽느냐다.
    #
    # pwnkit 실패에서 배운 대로, 축을 넣기 전에 몇 개 기법이 그 축에서 0이
    # 아닌지 세었다(중앙값 0.05 이상 기준):
    #   /etc 공격 35종  /usr 36종  /dev 26종  /proc 13종  /tmp 7종  <- 충분
    #   /sys 1종  /root 2종  /home 1종  /var 1종                    <- 희소
    # 희소한 축은 기법 지문이 될 위험이 있어 'other' 로 묶는다.
    "frac_dir_etc", "frac_dir_proc", "frac_dir_usr",
    "frac_dir_dev", "frac_dir_tmp", "frac_dir_other",
]

# 위 실측에 따라 개별 축으로 둘 만큼 널리 쓰이는 디렉터리만 나열한다.
DIR_FRACS = ("/etc/", "/proc/", "/usr/", "/dev/", "/tmp/")

# 누구나 쓸 수 있는 디렉터리. 여기서 온 코드가 특권 프로세스에 로드되면 위험 신호다.
# 라이브러리 하이재킹 피처(frac_lib_from_writable, n_exec_from_writable_log)는
# 한 번 도입했다가 되돌렸다. 보관: aggregate_v2_libhijack.py.bak
#
# 되돌린 이유: 그 축을 쓰는 기법이 pwnkit 하나뿐이라, 기법 홀드아웃에서
# 가르쳐 줄 형제가 없었다. pwnkit 이 학습에 있을 때만 AUC 0.95 가 나오는
# 기법 정체를 외우는 지름길 이었고, 실제로 LOTO 는 1.8% -> 0.0% 로 나빠졌다.
# 덤으로 dirty_pipe 가 90.2% -> 2.7% 로 무너졌는데, 그 90.2% 자체가 임계값
# 바로 위(중앙값 0.530)에 걸친 취약한 값이었음이 드러났다.
#
# 다시 도입하려면 먼저 같은 축을 쓰는 기법을 늘려야 한다:
#   - ldpreload_probe 가 실제로 /tmp 에 .so 를 만들어 LD_PRELOAD 로 로드하도록 수정
#   - path_hijack 에 .so 하이재킹 변종 추가
# 그래야 pwnkit 을 빼도 형제가 그 축을 가르쳐 준다.

DIRS_SENSITIVE = ("/etc", "/root", "/home", "/var/spool")


class PermLookup:
    """경로 -> (권한비트, 소유uid, 존재여부). 학습과 추론이 같은 규칙을 쓰도록 공유한다.

    /proc/<pid>/* 는 stat 하지 않는다 — 학습/추론 불일치의 원인이었다
    ------------------------------------------------------------------
    이 경로들은 프로세스 생명주기에 묶여 있어서 사후 stat 이 원리적으로 무의미하다.
    실측: 전체 파일 접근의 65.2% 가 /proc/<pid> 이고, 수집 몇 시간 뒤 피처를
    계산하니 한 버킷에서 72,409개 중 71,299개가 '존재하지 않음' 으로 잡혔다.
    그런데 실시간 탐지에서는 그 PID 들이 대부분 살아 있으므로 반대 값이 나온다.
    즉 모델이 학습한 값과 운용에서 들어올 값이 정반대가 된다.

    -> 규약값으로 고정한다. /proc/<pid>/ 하위는 존재하고, 0444(world-readable),
       소유자 root 로 본다. 대부분의 /proc 항목이 실제로 그렇고, 무엇보다
       **시점에 무관하게 같은 값**이 된다.
       (근본 해결은 에이전트가 접근 시점의 inode i_mode/i_uid 를 실어 주는 것.
        FEATURES.md 의 스키마 확장 과제.)
    """

    def __init__(self):
        self.c = {}

    @staticmethod
    def _is_proc_pid(p):
        parts = p.split("/", 3)
        return len(parts) >= 3 and parts[1] == "proc" and parts[2].isdigit()

    def get(self, p):
        v = self.c.get(p)
        if v is None:
            if self._is_proc_pid(p):
                v = (0o444, 0, True)          # 규약값 - 시점에 무관
            else:
                try:
                    st = os.stat(p)
                    v = (st.st_mode & 0o7777, st.st_uid, True)
                except OSError:
                    v = (0, -1, False)
            self.c[p] = v
        return v


def bucket_features(recs, perm):
    """한 버킷(같은 시간창의 레코드 묶음) -> FEATURES 순서의 25차원 벡터.

    detect 와 학습이 반드시 이 함수를 공유해야 한다. 같은 계산을 두 곳에
    따로 구현하면 학습 피처와 추론 피처가 조용히 어긋난다.
    레코드는 full 형식(syscalls 배열)과 slim 형식(n_syscalls 통계) 모두 받는다.
    """
    nw = len(recs)
    tgids = {r["tgid"] for r in recs}
    comms = {r.get("comm", "?") for r in recs}
    seq_total = 0
    uniq_sys = set()
    n_uniq_sum = 0
    files, nets, nexec = [], 0, 0
    for r in recs:
        sq = r.get("syscalls")
        if sq is None:
            seq_total += r.get("n_syscalls", 0)
            n_uniq_sum += r.get("n_uniq_syscalls", 0)
        else:
            seq_total += len(sq)
            uniq_sys.update(sq)
        files += r.get("files", [])
        nets += len(r.get("net", []))
        nexec += len(r.get("execs", []))

    nf = len(files)
    uniq_paths, dirs, depths = set(), set(), []
    missing = notwr = other = setuid = hidden = writes = 0
    proc_pids, sens_dirs = set(), set()
    uid0 = recs[0].get("uid", -1)
    for f in files:
        p = f.get("p", "")
        uniq_paths.add(p)
        mode, owner, exists = perm.get(p)
        if not exists:
            missing += 1
        else:
            if not (mode & 0o004):
                notwr += 1
            if mode & 0o4000:
                setuid += 1
            if owner != uid0:
                other += 1
        if f.get("m", 0) & 2:
            writes += 1
        parts = [x for x in p.split("/") if x]
        depths.append(len(parts))
        if len(parts) > 1:
            dirs.add("/".join(parts[:-1]))
        if any(x.startswith(".") for x in parts):
            hidden += 1
        if len(parts) >= 2 and parts[0] == "proc" and parts[1].isdigit():
            proc_pids.add(parts[1])
        for sd in DIRS_SENSITIVE:
            if p.startswith(sd + "/"):
                sens_dirs.add("/".join(parts[:2]) if len(parts) > 1 else p)

    # 디렉터리 분포
    dfrac = [0] * (len(DIR_FRACS) + 1)
    for f in files:
        p = f.get("p", "")
        for i, d in enumerate(DIR_FRACS):
            if p.startswith(d):
                dfrac[i] += 1
                break
        else:
            dfrac[-1] += 1

    n_uniq = len(uniq_sys) if uniq_sys else n_uniq_sum
    g = max(nf, 1)
    row = [
        np.log1p(nw), np.log1p(len(tgids)), np.log1p(len(comms)),
        np.log1p(seq_total), n_uniq / max(seq_total, 1),
        np.log1p(nf), np.log1p(len(uniq_paths)), np.log1p(len(dirs)),
        nf / max(len(tgids), 1),
        missing / g, notwr / g, other / g, setuid / g, hidden / g, writes / g,
        np.log1p(len(proc_pids)), len(proc_pids) / max(len(uniq_paths), 1),
        float(len(sens_dirs)),
        float(max(depths) if depths else 0), float(np.mean(depths) if depths else 0),
        np.log1p(nets), np.log1p(nets), np.log1p(nexec),
        nexec / max(len(tgids), 1), np.log1p(n_uniq),
    ] + [x / g for x in dfrac]
    assert len(row) == len(FEATURES), f"{len(row)} vs {len(FEATURES)}"
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("records")
    ap.add_argument("out")
    ap.add_argument("--bucket-sec", type=float, default=5.0)
    a = ap.parse_args()
    BN = int(a.bucket_sec * 1e9)

    buckets = defaultdict(list)
    for line in open(a.records):
        r = json.loads(line)
        buckets[(r.get("session", ""), r.get("start", 0) // BN)].append(r)

    perm = PermLookup()

    X, ys, techs, sess, mixed = [], [], [], [], 0
    for (s_, b), recs in sorted(buckets.items()):
        labs = {r["label"] for r in recs}
        if len(labs) > 1:
            mixed += 1
        # 섞인 버킷은 공격이 하나라도 있으면 공격으로 본다(탐지 관점에서 보수적)
        lab = "attack" if "attack" in labs else "normal"
        tset = {r["technique"] for r in recs if r["label"] == lab}
        X.append(bucket_features(recs, perm))
        ys.append(lab); sess.append(s_)
        techs.append(sorted(tset)[0] if tset else "")

    X = np.array(X, dtype=np.float32)
    np.savez_compressed(a.out, X=X, labels=np.array(ys), techniques=np.array(techs),
                        sessions=np.array(sess), names=np.array(FEATURES))
    u, c = np.unique(ys, return_counts=True)
    print(f"버킷 {len(X)}개 (폭 {a.bucket_sec}초), 피처 {X.shape[1]}차원")
    print(f"라벨 분포: {dict(zip(u, c))}")
    print(f"두 클래스가 섞인 버킷: {mixed}개 ({100*mixed/max(len(X),1):.1f}%)")
    if mixed / max(len(X), 1) > 0.2:
        print("  ⚠ 섞임이 20%를 넘으면 버킷 라벨 자체가 신뢰하기 어렵다 - 버킷 폭을 줄일 것")


if __name__ == "__main__":
    main()
