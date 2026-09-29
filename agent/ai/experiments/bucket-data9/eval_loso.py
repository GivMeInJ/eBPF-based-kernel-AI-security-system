"""
누수 없는 평가 — leave-one-session-out (LOSO) + leave-one-technique-out (LOTO).

왜 LOSO 인가
------------
이전 데이터는 '정상=세션 A, 공격=세션 B' 구조여서 클래스와 캡처 세션이 교락돼
있었다. 그 결과 아무 일도 하지 않는 /bin/true 조차 AUC=1.0000 으로 갈렸다.
bench.sh 로 한 세션 안에 두 클래스를 섞어 다시 모았으므로, 이제
'세션 하나를 통째로 빼고 학습 -> 그 세션으로만 평가' 가 가능하다.
이것이 실제 운영 상황("학습 때 본 적 없는 날, 본 적 없는 머신")에 가장 가깝다.

세 가지를 같이 낸다
  1) LOSO: 못 본 세션에서의 탐지율/오탐률   <- 대표 수치
  2) LOTO: 못 본 기법을 잡는가 (세션 교차 학습 위에서)
  3) 매칭 comm 분리도: 같은 프로그램끼리도 구분되는가 (누수 잔존 여부 감시)

사용: python3 eval_loso.py features.npz [--drop-session s1] [--out report.json]
"""
import argparse, json
import numpy as np
import warnings
warnings.filterwarnings("ignore")
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.model_selection import StratifiedKFold


def make_rf(seed=42):
    return RandomForestClassifier(n_estimators=400, max_features="sqrt",
                                  class_weight="balanced", random_state=seed, n_jobs=-1)


def metrics(y, p):
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    return dict(TN=int(tn), FP=int(fp), FN=int(fn), TP=int(tp),
                DR=tp / max(tp + fn, 1), FPR=fp / max(fp + tn, 1),
                PREC=tp / max(tp + fp, 1))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("features")
    ap.add_argument("--drop-session", default="", help="쉼표로 구분. 예: s1")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    d = np.load(a.features, allow_pickle=True)
    X, names = d["X"], d["names"].astype(str)
    y = (d["labels"].astype(str) == "attack").astype(int)
    sess = d["sessions"].astype(str)
    techs = d["techniques"].astype(str)
    # 집계(버킷) 피처에는 comm 이 없다 - 3번 검증은 건너뛴다.
    comms = d["comms"].astype(str) if "comms" in d.files else None

    if a.drop_session:
        keep = ~np.isin(sess, a.drop_session.split(","))
        X, y, sess, techs = X[keep], y[keep], sess[keep], techs[keep]
        if comms is not None:
            comms = comms[keep]
        print(f"세션 제외: {a.drop_session}  -> 남은 샘플 {len(y)}")

    us = sorted(set(sess))
    print(f"샘플 {len(y)}  (정상 {int((y==0).sum())} / 공격 {int((y==1).sum())})")
    print(f"세션 {len(us)}개: {us}")
    print()
    out = {}

    # ---------- 1. LOSO ----------
    print("=== 1. leave-one-session-out (대표 수치) ===")
    print("   세션 하나를 통째로 빼고 학습 -> 그 세션으로만 평가")
    print()
    loso, scores = {}, np.zeros(len(y))
    for s in us:
        te = sess == s
        c = make_rf().fit(X[~te], y[~te])
        p = c.predict_proba(X[te])[:, 1]
        scores[te] = p
        m = metrics(y[te], (p >= a.threshold).astype(int))
        m["AUC"] = float(roc_auc_score(y[te], p)) if len(set(y[te])) > 1 else float("nan")
        loso[s] = m
        print(f"  {s}  n={int(te.sum()):5d}  탐지율={100*m['DR']:6.2f}%  "
              f"오탐률={100*m['FPR']:5.2f}%  정밀도={100*m['PREC']:6.2f}%  AUC={m['AUC']:.4f}")
    agg = metrics(y, (scores >= a.threshold).astype(int))
    agg["AUC"] = float(roc_auc_score(y, scores))
    print(f"  --- 전체 합산: 탐지율={100*agg['DR']:.2f}%  오탐률={100*agg['FPR']:.2f}%  "
          f"정밀도={100*agg['PREC']:.2f}%  AUC={agg['AUC']:.4f} ---")
    print(f"      [TN={agg['TN']} FP={agg['FP']} FN={agg['FN']} TP={agg['TP']}]")
    out["loso"] = {"per_session": loso, "pooled": agg}
    print()

    # ---------- 2. LOTO (세션 교차 위에서) ----------
    print("=== 2. leave-one-technique-out (학습에 없던 기법을 잡는가) ===")
    lt = {}
    for t in sorted(set(techs[y == 1])):
        hold = (y == 1) & (techs == t)
        c = make_rf().fit(X[~hold], y[~hold])
        p = c.predict_proba(X[hold])[:, 1]
        dr = float((p >= a.threshold).mean())
        lt[t] = {"n": int(hold.sum()), "DR": dr, "median": float(np.median(p))}
    for t, v in sorted(lt.items(), key=lambda kv: -kv[1]["DR"]):
        print(f"  {t:20s} n={v['n']:4d}  미학습 탐지율={100*v['DR']:6.2f}%  "
              f"중앙값={v['median']:.3f}")
    drs = [v["DR"] for v in lt.values()]
    print(f"  --- 평균 {100*np.mean(drs):.2f}%  중앙값 {100*np.median(drs):.2f}% ---")
    out["loto"] = lt
    print()

    # ---------- 3. 매칭 comm 분리도 (누수 감시) ----------
    if comms is None:
        print("=== 3. 생략 (집계 피처에는 comm 정보가 없음) ===")
        if a.out:
            json.dump(out, open(a.out, "w"), indent=2, ensure_ascii=False, default=float)
            print(f"저장: {a.out}")
        return

    print("=== 3. 같은 프로그램끼리도 구분되는가 (누수 감시) ===")
    print("   AUC 가 1.0 에 붙어 있으면 아직 행위가 아닌 무언가를 학습 중")
    print()
    matched = {}
    for comm in sorted(set(comms)):
        m = comms == comm
        na, nn = int((m & (y == 1)).sum()), int((m & (y == 0)).sum())
        if na < 10 or nn < 10:
            continue
        s = np.zeros(int(m.sum()))
        Xm, ym = X[m], y[m]
        if min(np.bincount(ym)) < 5:
            continue
        for tr, te in StratifiedKFold(5, shuffle=True, random_state=0).split(Xm, ym):
            c = make_rf().fit(Xm[tr], ym[tr])
            s[te] = c.predict_proba(Xm[te])[:, 1]
        auc = float(roc_auc_score(ym, s))
        matched[comm] = {"n_attack": na, "n_normal": nn, "auc": auc}
        print(f"  {comm:16s} 공격 {na:4d} / 정상 {nn:4d}   AUC={auc:.4f}")
    if matched:
        v = [x["auc"] for x in matched.values()]
        print(f"  --- 평균 AUC {np.mean(v):.4f}  (1.0 에 붙어 있으면 누수 의심) ---")
    out["matched_comm"] = matched
    print()

    if a.out:
        json.dump(out, open(a.out, "w"), indent=2, ensure_ascii=False, default=float)
        print(f"저장: {a.out}")


if __name__ == "__main__":
    main()
