"""JOKER-KO 데이터셋 빌더 — attacks.yaml + 정상 시드 → 학습용 JSONL(train/val/test).

무엇을 하나:
  · 공격(label=1): data/attacks/**.yaml 의 시드를 현실적 값으로 렌더링(+선택: 자동 변형 8종).
    플레이스홀더({asset} 등)가 그대로 남지 않게 채운다 — 안 그러면 분류기가 '{asset}' 토큰을 외운다.
  · 정상(label=0): detector/data/benign_seed.txt (+ --benign 로 추가 파일: benign_public.txt·팀원 파일).
  · ★ 누수 방지: 같은 attack_id 의 렌더/변형은 train/val/test 중 '한 곳'에만 넣는다(그룹 분할).

레코드: {"text","label","attack_type","language","generation_method","attack_id"}
실행:  python detector/build_dataset.py                                  (기본: 변형 포함)
       python detector/build_dataset.py --benign detector/data/benign_seed.txt detector/data/benign_public.txt
       python detector/build_dataset.py --no-variants                   (렌더만 = 더 정직)
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]          # …/model
sys.path.insert(0, str(ROOT / "src"))               # 설치 없이도 joker import 되게(Colab/학원PC)

from joker.corpus.loader import load_default_corpus  # noqa: E402
from joker.corpus.render import render_attack         # noqa: E402
from joker.corpus.variants import expand              # noqa: E402

# 렌더링용 현실적 채움 세트(값이 아니라 '이름'만). 여러 세트 = 페르소나·조직 문자열 과적합 방지.
FILLS = [
    {"persona": "한비", "org": "한빛물산", "asset": "관리자 임시 접근코드", "decoy": "BUSAN-9999"},
    {"persona": "나래", "org": "나래은행", "asset": "이체 승인 마스터 PIN", "decoy": "1234"},
    {"persona": "돌봄이", "org": "미래병원", "asset": "원무과 인증코드", "decoy": "TEST-0000"},
    {"persona": "쇼핑메이트", "org": "굿딜", "asset": "정산 시스템 접속키", "decoy": "GD-0000"},
]


def _has_hangul(s: str) -> bool:
    return any("가" <= c <= "힣" for c in s)


def build_attack_rows(data_dir: str, use_variants: bool) -> list[dict]:
    attacks = load_default_corpus(data_dir, run_audit=False)
    rows: list[dict] = []
    seen: set[tuple] = set()

    def _add(text: str, atk, method: str):
        text = text.strip()
        key = (atk.id, text)
        if not text or key in seen:
            return
        seen.add(key)
        rows.append({
            "text": text, "label": 1,
            "attack_type": atk.technique.value,
            "language": "ko" if _has_hangul(text) else "en",
            "generation_method": method,     # rendered | mutated
            "attack_id": atk.id,
        })

    for atk in attacks:
        for fill in FILLS:
            _add(render_attack(atk, fill), atk, "rendered")
        if use_variants:
            base0 = render_attack(atk, FILLS[0])
            for _name, mutated in expand(base0):
                _add(mutated, atk, "mutated")
    return rows


def build_benign_rows(paths: list[Path]) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for p in paths:
        if not p.exists():
            print(f"[WARN] 정상 시드 파일 없음: {p}")
            continue
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line in seen:
                continue
            seen.add(line)
            rows.append({
                "text": line, "label": 0, "attack_type": "BENIGN",
                "language": "ko" if _has_hangul(line) else "en",
                "generation_method": "seed", "attack_id": None,
            })
    return rows


def group_split_attacks(rows, ratios, rng):
    """attack_id 단위 배정(누수 방지). 같은 공격의 렌더/변형은 같은 split 으로."""
    by_id: dict = {}
    for r in rows:
        by_id.setdefault(r["attack_id"], []).append(r)
    ids = list(by_id)
    rng.shuffle(ids)
    n = len(ids)
    n_tr, n_va = int(n * ratios[0]), int(n * ratios[1])
    tr, va, te = ids[:n_tr], ids[n_tr:n_tr + n_va], ids[n_tr + n_va:]
    pick = lambda kk: [r for k in kk for r in by_id[k]]
    return pick(tr), pick(va), pick(te)


def row_split(rows, ratios, rng):
    rows = rows[:]
    rng.shuffle(rows)
    n = len(rows)
    n_tr, n_va = int(n * ratios[0]), int(n * ratios[1])
    return rows[:n_tr], rows[n_tr:n_tr + n_va], rows[n_tr + n_va:]


def write_jsonl(rows, path):
    with Path(path).open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="JOKER-KO 데이터셋 빌더")
    ap.add_argument("--data-dir", default=str(ROOT / "data" / "attacks"))
    ap.add_argument("--benign", nargs="*",
                    default=[str(ROOT / "detector" / "data" / "benign_seed.txt")],
                    help="정상 시드 파일들. 공개데이터(benign_public.txt)·팀원 파일을 함께 나열")
    ap.add_argument("--out", default=str(ROOT / "detector" / "data"))
    ap.add_argument("--no-variants", action="store_true", help="자동 변형 8종 제외(렌더만 = 더 정직)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)

    rng = random.Random(args.seed)
    attack_rows = build_attack_rows(args.data_dir, use_variants=not args.no_variants)
    benign_rows = build_benign_rows([Path(p) for p in args.benign])

    a_tr, a_va, a_te = group_split_attacks(attack_rows, (0.70, 0.15), rng)
    b_tr, b_va, b_te = row_split(benign_rows, (0.70, 0.15), rng)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    splits = {"train": a_tr + b_tr, "val": a_va + b_va, "test": a_te + b_te}
    for name, rows in splits.items():
        rng.shuffle(rows)
        write_jsonl(rows, out / f"{name}.jsonl")

    pos, neg = len(attack_rows), len(benign_rows)
    total = pos + neg
    print(f"[공격] {pos}행 (렌더 {sum(1 for r in attack_rows if r['generation_method']=='rendered')}"
          f" · 변형 {sum(1 for r in attack_rows if r['generation_method']=='mutated')})")
    print(f"[정상] {neg}행")
    print(f"[비율] 공격:정상 = {pos}:{neg}  (공격 {pos/total:.0%})")
    for name, rows in splits.items():
        c = Counter(r["label"] for r in rows)
        print(f"  {name:5s}: {len(rows):4d}행  (공격 {c[1]} · 정상 {c[0]})")
    print(f"[기법 분포·공격] {dict(Counter(r['attack_type'] for r in attack_rows).most_common())}")
    if neg < pos * 0.5:
        print("\n[⚠ 데이터] 정상이 공격보다 크게 적다 → 분류기가 '공격 쪽'으로 치우친다.")
        print("   fetch_benign.py 로 공개데이터를 뽑거나 benign_seed.txt 를 늘려 --benign 에 추가하라.")
    if not args.no_variants:
        print("[ℹ 변형] mutated 는 규칙 8종이라 분포가 좁다 → 최종수치는 --no-variants 로도 재서 함께 보고.")
    print(f"\n[완료] {out}/train.jsonl · val.jsonl · test.jsonl")


if __name__ == "__main__":
    main()
