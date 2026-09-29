"""
배포용 버킷 모델 학습 + 임계값 결정.

왜 이 구성인가 (실측 근거)
--------------------------
정책 비교에서 버킷 모델 단독이 두 조건 모두에서 가장 좋았다.

  정책              LOSO 탐지  LOSO 오탐  미지 계열
  버킷 단독           98.06%    0.63%     81.8%
  윈도우(1715차원)     97.08%    0.51%     34.6%
  윈도우 AND 버킷      95.46%    0.11%     31.2%

윈도우 모델과 결합하면 미지 계열이 81.8% -> 31.2% 로 떨어진다. 결합은
두 모델이 비슷하게 유능할 때만 이득인데 여기서는 한쪽이 명확히 우월하다.

임계값
------
고정 0.5 를 쓰지 않는다. 학습 분포가 바뀌면 점수 분포가 통째로 이동하는데
분위수 기준은 그 이동을 자동으로 흡수한다(실측: 고정 0.5 는 미지 계열
탐지를 81.8% -> 20.0% 로 떨어뜨렸다).
임계값은 **정상 버킷의 교차검증 점수** 분위수로 잡는다. 자기 자신을 학습한
모델의 점수로 잡으면 낙관적으로 치우친다.

사용: python3 train_bucket.py agg.npz --out model_dir [--budget 0.005]
"""
import argparse, json, os
import numpy as np
import warnings
warnings.filterwarnings("ignore")
from sklearn.ensemble import RandomForestClassifier


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("aggregate")
    ap.add_argument("--out", required=True)
    ap.add_argument("--budget", type=float, default=0.005,
                    help="목표 오탐률(버킷 단위). 0.005 권장 — 0.001 로 조이면 "
                         "미지 계열 탐지가 81.8%%에서 50.6%%로 떨어진다")
    ap.add_argument("--bucket-sec", type=float, default=1.0)
    a = ap.parse_args()

    d = np.load(a.aggregate, allow_pickle=True)
    X = d["X"]
    y = (d["labels"].astype(str) == "attack").astype(int)
    sess = d["sessions"].astype(str)
    names = d["names"].astype(str)
    os.makedirs(a.out, exist_ok=True)

    def rf():
        return RandomForestClassifier(n_estimators=300, max_features="sqrt",
                                      class_weight="balanced", random_state=42,
                                      n_jobs=-1)

    # 임계값용 점수는 세션 교차검증으로 뽑는다(자기 학습 점수 금지)
    oof = np.zeros(len(y))
    for u in sorted(set(sess)):
        te = sess == u
        oof[te] = rf().fit(X[~te], y[~te]).predict_proba(X[te])[:, 1]
    thr = float(np.quantile(oof[y == 0], 1 - a.budget))

    pred = oof >= thr
    dr = float(pred[y == 1].mean()); fpr = float(pred[y == 0].mean())
    prec = float((y[pred] == 1).mean()) if pred.sum() else 1.0
    print(f"교차검증 성능: 탐지율 {100*dr:.2f}%  오탐률 {100*fpr:.2f}%  정밀도 {100*prec:.2f}%")
    print(f"임계값 = {thr:.6f}  (정상 버킷 {100*(1-a.budget):.1f} 분위수)")

    model = rf().fit(X, y)          # 배포 모델은 전체로 학습
    import joblib
    joblib.dump(model, os.path.join(a.out, "bucket_model.pkl"))
    meta = {
        "kind": "bucket", "bucket_sec": a.bucket_sec, "threshold": thr,
        "budget": a.budget, "feature_names": names.tolist(),
        "trained_on": os.path.abspath(a.aggregate),
        "n_buckets": int(len(y)), "n_attack": int(y.sum()),
        "cv": {"DR": dr, "FPR": fpr, "PREC": prec},
    }
    json.dump(meta, open(os.path.join(a.out, "meta.json"), "w"),
              indent=2, ensure_ascii=False)
    imp = sorted(zip(names, model.feature_importances_), key=lambda kv: -kv[1])
    print("\n상위 피처:")
    for n, v in imp[:8]:
        print(f"  {n:28s} {v:.4f}")
    json.dump([[n, float(v)] for n, v in imp],
              open(os.path.join(a.out, "importance.json"), "w"),
              indent=2, ensure_ascii=False)
    print(f"\n저장: {a.out}/bucket_model.pkl, meta.json, importance.json")


if __name__ == "__main__":
    main()
