"""OOD 재현율 — 학습 생성기 밖에서 손으로 쓴 공격을 필터가 잡는가.

왜 필요한가:
    F1 0.981 도, held-out 차단율 88% 도, 변형 99% 도 전부 `data/attacks` 템플릿과 그 자동 변형
    안에서 나온 수치다. "처음 보는 공격은?" 에 답할 수 있는 유일한 세트가 OOD 다.
    → 세트 생성은 `scripts/build_ood_set.py` 참조(사람이 쓴 문장, 학습셋·시드와 중복 제거).

무엇을 내나:
    · 층별(규칙 / ML / 결합) 재현율 + 95% Wilson CI
    · 출처별 분해 — 한 사람의 문체에만 강한 게 아닌지 확인
    · 같은 문서에 FPR(정상 오탐) 을 함께 — 재현율만 단독으로 읽으면 과장이 된다

읽는 법:
    · 이 수치가 in-distribution(88%) 보다 낮은 게 정상이다. 낮은 폭이 곧 '한계의 크기'다.
    · 규칙 층은 학습을 안 했으므로 OOD 에서도 성격이 같다 — ML 이 떨어질 때 얼마나 받쳐주는지 본다.
    · 공격만 있는 세트라 정밀도는 계산할 수 없다(정상 표본은 FPR 로 따로 본다).

실행: python scripts/ood_recall.py
      python scripts/ood_recall.py --rules-only        # torch 없이 규칙 층만
      python detector/evaluate.py --test detector/data/ood_attacks.jsonl   # baseline 대비(별도)
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# 통계·필터 적용 로직은 defense_matrix 와 한 벌이다(두 번 짜면 조용히 어긋난다).
_spec = importlib.util.spec_from_file_location("defense_matrix", ROOT / "scripts" / "defense_matrix.py")
dm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dm)  # type: ignore[union-attr]


def load_rows(path: Path) -> list[dict]:
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    bad = [r for r in rows if r.get("label") != 1 or not (r.get("text") or "").strip()]
    if bad:
        raise SystemExit(f"[중단] OOD 세트에 공격(label=1)이 아닌 행이 {len(bad)}개 있습니다: {path}")
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="OOD 공격 재현율")
    ap.add_argument("--ood", default=str(ROOT / "detector" / "data" / "ood_attacks.jsonl"))
    ap.add_argument("--rules-only", action="store_true")
    ap.add_argument("--model-path", default=None)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--out", default=str(ROOT / "docs"))
    args = ap.parse_args(argv)

    ood = Path(args.ood)
    if not ood.exists():
        raise SystemExit(f"[중단] OOD 세트가 없습니다: {ood}\n먼저 `python scripts/build_ood_set.py` 를 돌리세요.")
    rows = load_rows(ood)
    texts = [r["text"] for r in rows]
    benign = dm.benign_from_jsonl(ROOT / "detector" / "data")

    layers = ("rule",) if args.rules_only else dm.LAYERS
    print(f"[진행] OOD 공격 {len(texts)}건 · 정상(FPR용) {len(benign)}건 "
          f"→ 분류 ({'규칙만' if args.rules_only else 'ML+규칙'})")
    blocked = dm.compute_blocked(sorted(set(texts) | set(benign)), args.rules_only,
                                 args.model_path, args.threshold)

    by_src: dict[str, list[str]] = {}
    for r in rows:
        by_src.setdefault(r.get("source", "unknown"), []).append(r["text"])

    L: list[str] = []
    a = L.append
    a(f"# OOD 재현율 — 학습 생성기 밖의 공격 · {datetime.now():%Y-%m-%d %H:%M}")
    a("")
    a(f"- 세트: `{ood.name}` · 공격 {len(texts)}건 (사람이 손으로 쓴 문장, 템플릿·자동변형 아님)")
    a(f"- 필터: `{'규칙만(ML 제외)' if args.rules_only else (args.model_path or 'detector/artifacts/joker-ko')}`"
      f" (threshold {args.threshold})")
    a("- 학습셋(train/val)·시드 코퍼스와 정규화 비교해 중복을 제거한 세트다.")
    a("")
    a("## ⚠️ 읽는 법")
    a("")
    a("1. **이 수치가 in-distribution 보다 낮은 것이 정상이다.** 그 낙차가 곧 한계의 크기다.")
    a("2. **정밀도는 계산할 수 없다** — 공격만 있는 세트다. 오탐은 아래 FPR 로 따로 본다.")
    a("3. **추출 노이즈는 재현율을 낮추는 쪽으로만 작용한다** — 설명문이 섞이면 '놓친 공격'으로 세인다. "
      "즉 이 수치는 보수적이다.")
    a("4. 편입된 시드가 편집됐다면 정규화 비교로 못 걸러낼 수 있다 — 완전한 OOD 라고 단정하지 않는다.")
    a("")
    a("## 층별 재현율")
    a("")
    a("| 층 | 재현율(차단율) |")
    a("|---|---|")
    for l in layers:
        a(f"| {dm.LAYER_LABEL[l]} | {dm.fmt(dm.block_rate(texts, blocked, l))} |")
    a("")
    a("## 출처별 (한 사람의 문체에만 강한 게 아닌지)")
    a("")
    a("| 출처 | " + " | ".join(dm.LAYER_LABEL[l] for l in layers) + " |")
    a("|---" * (len(layers) + 1) + "|")
    for src, ts in sorted(by_src.items()):
        a(f"| `{src}` | " + " | ".join(dm.fmt(dm.block_rate(ts, blocked, l)) for l in layers) + " |")
    a("")
    a("## 정상 문장 오탐률 (FPR) — 재현율과 반드시 함께 읽는다")
    a("")
    if benign:
        a(f"출처: detector/data/test.jsonl (label 0 · 학습·검증 미사용) · 표본 {len(benign)}건")
        a("")
        a("| 층 | FPR |")
        a("|---|---|")
        for l in layers:
            a(f"| {dm.LAYER_LABEL[l]} | {dm.fmt(dm.block_rate(benign, blocked, l))} |")
    else:
        a("⚠️ `detector/data/test.jsonl` 이 없어 FPR 을 못 쟀다. 재현율만 단독 인용하지 말 것.")
    a("")
    missed = [t for t in texts if not blocked[t]["both" if not args.rules_only else "rule"]]
    if missed:
        a(f"## 놓친 공격 {len(missed)}건 (앞 10건 · 다음 학습 데이터의 우선순위)")
        a("")
        for t in missed[:10]:
            a(f"- {t[:110]}")
        a("")
    a("---")
    a("생성: `python scripts/ood_recall.py`")
    md = "\n".join(L) + "\n"

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"ood_recall_{datetime.now():%Y%m%d_%H%M%S}.md"
    out.write_text(md, encoding="utf-8")
    print()
    print(md)
    print(f"[완료] {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
