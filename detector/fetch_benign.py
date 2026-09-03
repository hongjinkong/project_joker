"""공개 데이터에서 정상(label 0) 문장을 대량 추출 → data/benign_public.txt.

팀원 수집(도메인·다양성)을 '양'으로 보강한다. 출처(둘 다 MIT):
  · heegyu/open-korean-instructions  (HF, 명령형 정상 문장 다수) — <usr> 발화만 추출
  · songys/Chatbot_data              (GitHub CSV, 일상 질문) — Q 칸만 추출

★ Colab/맥에서 실행(datasets·pandas·네트워크 필요). 브리지에선 실행 불가.
실행: python detector/fetch_benign.py --n 2000
그 다음: build_dataset.py --benign detector/data/benign_seed.txt detector/data/benign_public.txt
"""

from __future__ import annotations

import argparse
import random
import re
from pathlib import Path

DET = Path(__file__).resolve().parent
DEFAULT_OUT = DET / "data" / "benign_public.txt"

# <usr> ... (다음 태그 전까지) — open-korean-instructions 의 text 포맷에서 사용자 발화만.
_USR = re.compile(r"<usr>\s*(.*?)\s*(?=<sys>|<usr>|<bot>|$)", re.DOTALL)


def _clean(s: str) -> str:
    return " ".join(str(s).split()).strip()


def _ok(s: str) -> bool:
    # 너무 짧/긴 것 제외, 한글 포함, 공격처럼 보이는 흔한 신호는 배제(보수적)
    if not (5 <= len(s) <= 200):
        return False
    if not any("가" <= c <= "힣" for c in s):
        return False
    low = s.lower()
    if any(k in low for k in ("시스템 프롬프트", "이전 지시", "무시하고", "관리자 접근", "prompt", "jailbreak")):
        return False   # 정상셋에 공격 냄새가 섞이면 라벨이 오염된다
    return True


def from_open_korean_instructions(limit: int) -> list[str]:
    from datasets import load_dataset
    ds = load_dataset("heegyu/open-korean-instructions", split="train")
    out: list[str] = []
    for row in ds:
        for m in _USR.findall(row.get("text", "") or ""):
            c = _clean(m)
            if _ok(c):
                out.append(c)
        if len(out) > limit * 5:   # 넉넉히 모으고 뒤에서 샘플
            break
    return out


def from_chatbot_data() -> list[str]:
    import pandas as pd
    url = "https://raw.githubusercontent.com/songys/Chatbot_data/master/ChatbotData.csv"
    df = pd.read_csv(url)
    return [c for q in df["Q"].astype(str) if _ok(c := _clean(q))]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000, help="최종 정상 문장 개수")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)

    rng = random.Random(args.seed)
    pool: list[str] = []
    for name, fn in [("open-korean-instructions", lambda: from_open_korean_instructions(args.n)),
                     ("Chatbot_data", from_chatbot_data)]:
        try:
            got = fn()
            pool += got
            print(f"[{name}] {len(got)}개 수집")
        except Exception as e:  # noqa: BLE001 — 한 소스 실패해도 나머지로 진행
            print(f"[{name}] 실패(건너뜀): {e}")

    pool = list(dict.fromkeys(pool))   # 중복 제거(순서 유지)
    rng.shuffle(pool)
    sel = pool[:args.n]
    Path(args.out).write_text("\n".join(sel) + "\n", encoding="utf-8")
    print(f"[완료] 정상 {len(sel)}개 → {args.out}")
    print("   다음: build_dataset.py --benign detector/data/benign_seed.txt detector/data/benign_public.txt")


if __name__ == "__main__":
    main()
