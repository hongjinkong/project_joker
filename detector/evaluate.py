"""baseline(Prompt Guard 2 원본) vs JOKER-KO(파인튜닝) — test.jsonl 로 나란히 비교.

발표 하이라이트: "기성 보안 모델은 한국어 공격을 놓치는데, 우리 데이터로 특화하니 잡더라."
Kakao 등 상용 모델을 --extra 로 더 넣으면 '경쟁자(벤치마크)'로 같이 세울 수 있다(선생 아님).

실행: python detector/evaluate.py --finetuned detector/artifacts/joker-ko
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

DET = Path(__file__).resolve().parent
DATA = DET / "data"
DEFAULT_BASELINE = "meta-llama/Llama-Prompt-Guard-2-86M"


def load_jsonl(p) -> list[dict]:
    return [json.loads(x) for x in Path(p).read_text(encoding="utf-8").splitlines() if x.strip()]


def _positive_index(id2label, override):
    if override is not None:
        return override
    for idx, name in id2label.items():
        if any(k in str(name).lower() for k in ("inject", "malicious", "jailbreak", "unsafe", "attack", "1")):
            return int(idx)
    return max(int(i) for i in id2label)


def predict(model_id, texts, max_len, pos_override):
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id)
    model.eval()
    pos = _positive_index(model.config.id2label, pos_override)
    print(f"  [{model_id}] id2label={model.config.id2label} · 양성(공격) 인덱스={pos}")
    preds, probs = [], []
    with torch.no_grad():
        for i in range(0, len(texts), 32):
            batch = tok(texts[i:i + 32], truncation=True, max_length=max_len,
                        padding=True, return_tensors="pt")
            p = torch.softmax(model(**batch).logits, dim=-1)[:, pos]
            probs.extend([float(x) for x in p.tolist()])
            preds.extend((p >= 0.5).int().tolist())
    return preds, probs


def report(name, y_true, y_pred):
    from sklearn.metrics import (accuracy_score, confusion_matrix,
                                 precision_recall_fscore_support)
    p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    acc = accuracy_score(y_true, y_pred)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    print(f"\n[{name}]  Acc {acc:.3f} · P {p:.3f} · R {r:.3f} · F1 {f:.3f}")
    print(f"          TP{tp} FP{fp} FN{fn} TN{tn} · FPR {fpr:.3f} · FNR {fnr:.3f}(놓친 공격 비율)")
    return {"name": name, "acc": acc, "p": p, "r": r, "f1": f, "fpr": fpr, "fnr": fnr}


def diagnose(name, y, preds, probs, texts):
    """양성확률 분포 + 놓친 공격(FN)·오탐(FP) 텍스트. 로직 아닌 진단 출력 전용."""
    import statistics
    atk = [probs[i] for i in range(len(y)) if y[i] == 1]
    if atk:
        b = {"<0.1": 0, "0.1-0.3": 0, "0.3-0.5": 0, ">=0.5": 0}
        for p in atk:
            k = "<0.1" if p < 0.1 else "0.1-0.3" if p < 0.3 else "0.3-0.5" if p < 0.5 else ">=0.5"
            b[k] += 1
        print(f"  [{name} 진단] 공격 {len(atk)}건 양성확률 "
              f"min {min(atk):.3f} / median {statistics.median(atk):.3f} / max {max(atk):.3f}")
        print(f"       분포 {b}   (<0.5 = 0.5 문턱 못 넘어 '놓침'. 전부 <0.1 이면 진짜 블라인드)")
    fn = [(probs[i], texts[i]) for i in range(len(y)) if y[i] == 1 and preds[i] == 0]
    if fn:
        print(f"  [{name}] 놓친 공격(FN) {len(fn)}건:")
        for pr, t in fn[:10]:
            print(f"     p={pr:.3f} | {t[:80]}")
    fp = [(probs[i], texts[i]) for i in range(len(y)) if y[i] == 0 and preds[i] == 1]
    if fp:
        print(f"  [{name}] 오탐(FP) {len(fp)}건:")
        for pr, t in fp[:10]:
            print(f"     p={pr:.3f} | {t[:80]}")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", default=DEFAULT_BASELINE)
    ap.add_argument("--finetuned", default=str(DET / "artifacts" / "joker-ko"))
    ap.add_argument("--extra", nargs="*", default=[], help="추가 비교 모델(예: Kakao). 경쟁자 벤치마크")
    ap.add_argument("--test", default=str(DATA / "test.jsonl"))
    ap.add_argument("--max-len", type=int, default=512)
    ap.add_argument("--baseline-pos-index", type=int, default=None)
    args = ap.parse_args(argv)

    rows = load_jsonl(args.test)
    texts = [r["text"] for r in rows]
    y = [int(r["label"]) for r in rows]
    print(f"[테스트] {len(rows)}행 (공격 {y.count(1)} · 정상 {y.count(0)})")

    results = []
    print("\n=== baseline: 파인튜닝 전 원본 ===")
    b_pred, b_prob = predict(args.baseline, texts, args.max_len, args.baseline_pos_index)
    results.append(report("baseline(원본)", y, b_pred))
    diagnose("baseline(원본)", y, b_pred, b_prob, texts)
    for m in args.extra:
        print(f"\n=== 비교 모델: {m} ===")
        e_pred, e_prob = predict(m, texts, args.max_len, None)
        results.append(report(f"비교:{m}", y, e_pred))
        diagnose(f"비교:{m}", y, e_pred, e_prob, texts)

    ft = Path(args.finetuned)
    if ft.exists():
        print("\n=== JOKER-KO: 파인튜닝 후 ===")
        f_pred, f_prob = predict(str(ft), texts, args.max_len, None)
        results.append(report("JOKER-KO(파인튜닝)", y, f_pred))
        diagnose("JOKER-KO(파인튜닝)", y, f_pred, f_prob, texts)
    else:
        print(f"\n[안내] 파인튜닝 모델 없음({ft}) — train.py 먼저. baseline/비교만 출력.")

    print("\n" + "=" * 60)
    print(f"{'모델':<24}{'F1':>8}{'Recall':>8}{'FNR':>8}")
    for r in results:
        print(f"{r['name']:<24}{r['f1']:>8.3f}{r['r']:>8.3f}{r['fnr']:>8.3f}")
    print("→ Recall↑ / FNR↓ = 놓치던 한국어 공격을 잡게 됐다 = 프로젝트 핵심 주장")


if __name__ == "__main__":
    main()
