"""OOD 공격 세트 만들기 — 사람이 손으로 쓴 공격문에서 '학습에 안 들어간 것'만 추린다.

왜 필요한가:
    지금까지의 탐지 수치(F1 0.981 · held-out 차단율 88%)는 전부 `data/attacks` 시드와 그 자동
    변형에서 나왔다. held-out 도 '학습에서 뺀 id' 일 뿐 같은 템플릿·같은 생성기다. 그래서
    "처음 보는 공격은?" 에 답할 수가 없었다. 이 세트가 그 공백을 메운다.

무엇이 OOD 인가 (이 스크립트의 기준):
    · 사람이 자유 문장으로 쓴 것 — 템플릿에서 렌더된 것이 아니다.
    · 자동 변형 8종(expand)을 거치지 않았다.
    · 탐지 학습셋(train/val.jsonl)과 시드 코퍼스 어디에도 같은 문장이 없다(정규화 비교로 확인).

정직성 메모:
    · 추출이 헤더·설명 줄을 잘못 집으면 그건 '공격이 아닌 문장'이라 탐지기가 SAFE 로 판정하고,
      우리는 그걸 '놓친 공격'으로 세게 된다 → **recall 이 실제보다 낮게 나온다.** 즉 추출 노이즈는
      우리에게 유리한 쪽이 아니라 불리한 쪽으로 작용한다(보수적). 그래서 패턴을 좁게 잡았다.
    · 편입된 시드 원문이 편집됐다면 정규화 비교로 못 걸러낼 수 있다 — 리포트에 남긴다.

실행: python scripts/build_ood_set.py            (기본 출력 detector/data/ood_attacks.jsonl)
      python scripts/build_ood_set.py --dump     (추출 결과를 화면에 전부 찍어 눈으로 검수)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]          # …/model
sys.path.insert(0, str(ROOT / "src"))

DEFAULT_SRC = ROOT.parent / "팀원들공격문구"

# 플레이스홀더 채움 — build_dataset.FILLS[0] 과 같은 값(비교 가능하게).
FILL = {"persona": "한비", "org": "한빛물산", "asset": "관리자 임시 접근코드", "decoy": "BUSAN-9999"}

# 설명·표 헤더로 시작하면 공격문이 아니다(좁게 잡는다 — 노이즈는 recall 을 깎는 쪽이라).
_DROP_PREFIX = re.compile(
    r"^\s*(?:번호|현상|기법|왜\s|왜통|한국어\s*고유|공격\s*문장\s*요약|판정\s*근거|출처|비고|예:|※)")
# 기법 라벨이 문장에 박혀 있으면 목차·표 행이다(공격문은 자기 기법명을 말하지 않는다).
_DROP_LABEL = re.compile(r"(?:ROLE|INDIRECT(?:_DOC)?|OBFUSC|AUTH|FORMAT)\b|^[①②③④⑤⑥⑦⑧]")
# 설명문("…는 한국어 고유 구조") 은 명사로 끝난다. 공격문은 요청·명령으로 끝난다.
_REQUEST_END = re.compile(
    r"(?:줘|줄래|주세요|바랍니다|바라옵니다|하라|해라|거라|어라|아라|아뢰라|불러|불러봐|말해|말해봐"
    r"|알려|채워|채워줘|기재|보고해|답해|출력|보여줘|해봐|하시오|하십시오|해|다|까|나|오니|소서"
    r"|것|습니다|합니다|이니라|하옵니다|주시옵소서|[?？])\s*$")
_MIN_LEN = 15


def _norm(s: str) -> str:
    """비교용 정규화 — NFC + 공백 접기 + 따옴표류 제거."""
    s = unicodedata.normalize("NFC", s or "")
    s = re.sub(r"[\"'“”‘’「」『』]", "", s)
    return re.sub(r"\s+", " ", s).strip()


def _render(s: str) -> str:
    for k, v in FILL.items():
        s = s.replace("{" + k + "}", v).replace("(" + k + ")", v)
    return s


def _has_hangul(s: str) -> bool:
    return any("가" <= c <= "힣" for c in s)


def _candidates(line: str) -> str | None:
    """한 줄 → 공격문 후보(없으면 None). 파일마다 서식이 달라 접두어를 모아 처리한다."""
    t = line.strip()
    if not t or _DROP_PREFIX.match(t):
        return None
    # 라벨 접두어 제거: "공격문장:", "· 공격 문장:", "1)", "1:", "1.", "- ", "1) "
    t = re.sub(r"^[·•\-\s]*공격\s*문장\s*[:：]\s*", "", t)
    t = re.sub(r"^\s*\d+\s*[).:：]\s*", "", t)
    t = re.sub(r"^[·•\-]\s*", "", t)
    t = t.strip().strip('"“”')
    if len(t) < _MIN_LEN or not _has_hangul(t):
        return None
    if _DROP_PREFIX.match(t) or _DROP_LABEL.search(t):
        return None
    if "\t" in line and re.match(r"^\s*\d", line):      # 요약 표의 행
        return None
    # 요청·명령으로 끝나지 않으면 설명문으로 본다. 진짜 공격문 일부를 잃지만,
    # 설명문을 공격으로 세면 탐지기가 SAFE 로 맞춰도 '놓쳤다'가 되어 수치가 왜곡된다.
    tail = re.sub(r'[\s"“”\'’.。!·—–\-]+$', "", _norm(t))   # 끝의 마침표·줄표를 떼고 어미만 본다
    if not _REQUEST_END.search(tail):
        return None
    return t


def extract(src_dir: Path) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for p in sorted(src_dir.glob("*.txt")):
        for raw in p.read_text(encoding="utf-8").splitlines():
            c = _candidates(raw)
            if not c:
                continue
            text = _render(c)
            key = _norm(text)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"text": text, "label": 1, "attack_type": "OOD",
                         "language": "ko", "generation_method": "human_written",
                         "attack_id": None, "source": p.name})
    return rows


def training_texts() -> set[str]:
    """학습·검증에 실제로 들어간 문장 + 시드 코퍼스 렌더본. 정규화해서 반환."""
    out: set[str] = set()
    for name in ("train.jsonl", "val.jsonl"):
        p = ROOT / "detector" / "data" / name
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    out.add(_norm(json.loads(line).get("text", "")))
    try:
        from joker.corpus.loader import load_default_corpus
        from joker.corpus.render import render_attack
        for atk in load_default_corpus(str(ROOT / "data" / "attacks"), run_audit=False):
            out.add(_norm(render_attack(atk, FILL)))
    except Exception as e:  # noqa: BLE001
        print(f"[주의] 시드 코퍼스 비교 생략: {e}")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="OOD 공격 세트 빌더")
    ap.add_argument("--src", default=str(DEFAULT_SRC), help="사람이 쓴 공격문 txt 폴더")
    ap.add_argument("--out", default=str(ROOT / "detector" / "data" / "ood_attacks.jsonl"))
    ap.add_argument("--dump", action="store_true", help="추출 결과 전부 출력(검수용)")
    args = ap.parse_args(argv)

    src = Path(args.src)
    if not src.exists():
        raise SystemExit(f"[중단] 원본 폴더가 없습니다: {src}")

    rows = extract(src)
    train = training_texts()
    kept = [r for r in rows if _norm(r["text"]) not in train]
    dropped = len(rows) - len(kept)

    print(f"[추출] {len(rows)}건 → 학습셋·시드와 겹쳐 제외 {dropped}건 → **OOD {len(kept)}건**")
    by_src: dict[str, int] = {}
    for r in kept:
        by_src[r["source"]] = by_src.get(r["source"], 0) + 1
    for k, v in sorted(by_src.items()):
        print(f"    {k:32s} {v:3d}건")
    if dropped == 0:
        print("[주의] 겹치는 문장이 0건입니다. 시드로 편입될 때 문구가 편집됐다면 정규화 비교로는")
        print("       못 걸러냅니다 — 'OOD 순수성'을 단정하지 말고 리포트에 이 한계를 남기세요.")

    if args.dump:
        for i, r in enumerate(kept, 1):
            print(f"{i:3d}. [{r['source']}] {r['text']}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for r in kept:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"[완료] {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
