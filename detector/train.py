"""Fine-tune Llama-Prompt-Guard-2-86M → JOKER-KO (한국어 프롬프트 인젝션 1차 탐지기).

★ 게이트 모델. 먼저: 1) huggingface-cli login  2) 모델 페이지에서 라이선스 동의(Access 승인)
GPU 권장(Colab 무료 T4 로 충분 — 86M).
실행:  python detector/train.py --class-weights
출력:  detector/artifacts/joker-ko/
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

DET = Path(__file__).resolve().parent
DATA = DET / "data"
DEFAULT_MODEL = "meta-llama/Llama-Prompt-Guard-2-86M"
DEFAULT_OUT = DET / "artifacts" / "joker-ko"


def load_jsonl(p) -> list[dict]:
    return [json.loads(x) for x in Path(p).read_text(encoding="utf-8").splitlines() if x.strip()]


def main(argv=None):
    ap = argparse.ArgumentParser(description="JOKER-KO fine-tuning")
    ap.add_argument("--model", default=DEFAULT_MODEL,
                    help="기반 모델(게이트). 대체/비교: protectai/deberta-v3-base-prompt-injection-v2")
    ap.add_argument("--epochs", type=float, default=4)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--max-len", type=int, default=512)   # Prompt Guard 2 = 512 토큰 한계
    ap.add_argument("--class-weights", action="store_true", help="불균형(정상<공격) 손실 보정")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args(argv)

    import torch
    from datasets import Dataset
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                              DataCollatorWithPadding, Trainer, TrainingArguments)

    tok = AutoTokenizer.from_pretrained(args.model)

    def to_ds(rows):
        ds = Dataset.from_list([{"text": r["text"], "label": int(r["label"])} for r in rows])
        return ds.map(lambda b: tok(b["text"], truncation=True, max_length=args.max_len), batched=True)

    train_rows = load_jsonl(DATA / "train.jsonl")
    train_ds, val_ds = to_ds(train_rows), to_ds(load_jsonl(DATA / "val.jsonl"))

    model = AutoModelForSequenceClassification.from_pretrained(
        args.model, num_labels=2,
        id2label={0: "SAFE", 1: "INJECTION"}, label2id={"SAFE": 0, "INJECTION": 1},
        ignore_mismatched_sizes=True,
    )

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        p, r, f, _ = precision_recall_fscore_support(labels, preds, average="binary", zero_division=0)
        return {"accuracy": accuracy_score(labels, preds), "precision": p, "recall": r, "f1": f}

    class WeightedTrainer(Trainer):
        def __init__(self, *a, class_weight=None, **k):
            super().__init__(*a, **k)
            self.class_weight = class_weight

        def compute_loss(self, model, inputs, return_outputs=False, **kw):
            labels = inputs.pop("labels")
            out = model(**inputs)
            w = self.class_weight.to(out.logits.device) if self.class_weight is not None else None
            loss = torch.nn.CrossEntropyLoss(weight=w)(out.logits.view(-1, 2), labels.view(-1))
            return (loss, out) if return_outputs else loss

    cw = None
    if args.class_weights:
        labs = [int(r["label"]) for r in train_rows]
        n0, n1 = labs.count(0), labs.count(1)
        tot = n0 + n1
        cw = torch.tensor([tot / (2 * max(n0, 1)), tot / (2 * max(n1, 1))], dtype=torch.float)
        print(f"[class-weights] SAFE={cw[0]:.2f} · INJECTION={cw[1]:.2f} (정상 {n0}·공격 {n1})")

    targs = TrainingArguments(
        output_dir=args.out, num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch, per_device_eval_batch_size=args.batch,
        learning_rate=args.lr, weight_decay=0.01,
        eval_strategy="epoch", save_strategy="epoch",   # transformers<4.46 이면 evaluation_strategy
        load_best_model_at_end=True, metric_for_best_model="f1",
        logging_steps=20, seed=42, report_to=[],
    )
    trainer = WeightedTrainer(
        model=model, args=targs, train_dataset=train_ds, eval_dataset=val_ds,
        tokenizer=tok, data_collator=DataCollatorWithPadding(tok),
        compute_metrics=compute_metrics, class_weight=cw,
    )
    trainer.train()
    trainer.save_model(args.out)
    tok.save_pretrained(args.out)
    print("[VAL 최종]", {k: round(v, 4) for k, v in trainer.evaluate().items() if k.startswith("eval_")})
    print(f"[완료] JOKER-KO 저장 → {args.out}\n다음: python detector/evaluate.py --finetuned {args.out}")


if __name__ == "__main__":
    main()
