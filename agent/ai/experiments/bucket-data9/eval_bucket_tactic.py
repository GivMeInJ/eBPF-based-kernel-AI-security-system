"""
버킷 모델의 계열 홀드아웃 — 확정된 배포 구성만 빠르게 평가한다.

정책 비교에서 버킷 단독이 두 조건 모두 최고였으므로, 이후 실험은 이 구성만
본다. 25차원 2천여 버킷이라 전체 평가가 수십 초면 끝난다.

임계값은 반드시 '보류 계열을 제외한 정상 버킷'의 분위수로 잡는다.
고정 0.5 를 쓰면 계열이 빠질 때 점수 분포가 통째로 이동해 성능이 왜곡된다
(실측: 81.8% -> 20.0%).

사용: python3 eval_bucket_tactic.py agg.npz [--budget 0.005]
"""
import argparse, json
import numpy as np
import warnings
warnings.filterwarnings("ignore")
from sklearn.ensemble import RandomForestClassifier

TACTICS = {
    "자격증명접근": ["read_shadow", "read_ssh_keys", "read_sudoers", "history_harvest"],
    "정찰":        ["suid_enum", "proc_enum", "env_harvest", "network_enum",
                    "user_enum", "cap_enum", "writable_probe"],
    "영속성":      ["cron_tamper", "authkeys_tamper", "systemd_tamper",
                    "rc_local_tamper", "profile_tamper", "ldpreload_probe"],
    "방어회피":    ["obfuscated_exec", "history_evasion",
                    "log_tamper", "timestomp", "attr_probe"],
    "권한상승":    ["sudo_probe", "dirty_pipe", "pwnkit", "path_hijack",
                    # 팀원 CVE 조사 3건이 공통으로 지목한 네임스페이스/마운트 계열.
                    # MITRE 기준으로 컨테이너 탈출(Escape to Host)도 권한상승에 속한다.
                    "ns_probe", "mount_probe", "symlink_race", "cgroup_probe",
                    "overlay_probe", "xattr_probe"],
    "유출/C2":     ["reverse_shell", "bulk_exfil", "c2_beacon",
                    "dns_exfil", "staged_archive"],
    "임팩트":      ["ransom_sim", "wiper_sim", "resource_hijack"],
    "수집":        ["screengrab_probe", "clipboard_probe"],
    "실행":        ["interp_exec", "at_schedule"],
}


def rf():
    return RandomForestClassifier(n_estimators=300, max_features="sqrt",
                                  class_weight="balanced", random_state=42, n_jobs=-1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("aggregate")
    ap.add_argument("--budget", type=float, default=0.005)
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    d = np.load(a.aggregate, allow_pickle=True)
    X = d["X"]
    y = (d["labels"].astype(str) == "attack").astype(int)
    sess, tech = d["sessions"].astype(str), d["techniques"].astype(str)
    present = set(tech[y == 1])
    out = {}

    print(f"버킷 {len(y):,}  (정상 {int((y==0).sum()):,} / 공격 {int((y==1).sum()):,})")
    print(f"세션 {len(set(sess))}개,  기법 {len(present)}종,  오탐 예산 {100*a.budget}%\n")

    # ---------- LOSO ----------
    oof = np.zeros(len(y))
    for u in sorted(set(sess)):
        te = sess == u
        oof[te] = rf().fit(X[~te], y[~te]).predict_proba(X[te])[:, 1]
    thr = np.quantile(oof[y == 0], 1 - a.budget)
    p = oof >= thr
    dr, fpr = p[y == 1].mean(), p[y == 0].mean()
    prec = (y[p] == 1).mean() if p.sum() else 1.0
    print(f"=== LOSO (알려진 공격, 못 본 세션) ===")
    print(f"  탐지율 {100*dr:.2f}%  오탐률 {100*fpr:.2f}%  정밀도 {100*prec:.2f}%")
    print(f"  [TN={int(((~p)&(y==0)).sum())} FP={int((p&(y==0)).sum())} "
          f"FN={int(((~p)&(y==1)).sum())} TP={int((p&(y==1)).sum())}]")
    out["loso"] = {"DR": float(dr), "FPR": float(fpr), "PREC": float(prec)}
    print()

    # ---------- LOTACTO ----------
    print("=== LOTACTO (계열 전체가 미지) ===")
    print(f"  {'계열':13s} {'기법':>4s} {'버킷':>6s}  {'탐지율':>8s}  {'중앙값 점수':>10s}")
    rows = {}
    for tac, members in TACTICS.items():
        mem = [m for m in members if m in present]
        hold = (y == 1) & np.isin(tech, mem)
        if hold.sum() == 0:
            continue
        trn = ~hold
        m = rf().fit(X[trn], y[trn])
        sc_all = m.predict_proba(X)[:, 1]
        t = np.quantile(sc_all[trn & (y == 0)], 1 - a.budget)
        dr_t = float((sc_all[hold] >= t).mean())
        rows[tac] = {"n_tech": len(mem), "n": int(hold.sum()), "DR": dr_t,
                     "median": float(np.median(sc_all[hold]))}
        print(f"  {tac:13s} {len(mem):4d} {int(hold.sum()):6d}  {100*dr_t:7.2f}%  "
              f"{np.median(sc_all[hold]):10.3f}")
    v = [r["DR"] for r in rows.values()]
    print(f"  {'평균':13s} {'':4s} {'':6s}  {100*np.mean(v):7.2f}%")
    out["lotacto"] = rows
    out["lotacto_mean"] = float(np.mean(v))

    if a.out:
        json.dump(out, open(a.out, "w"), indent=2, ensure_ascii=False, default=float)
        print(f"\n저장: {a.out}")


if __name__ == "__main__":
    main()
