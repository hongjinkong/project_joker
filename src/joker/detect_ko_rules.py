"""난독화(obfuscation) 공격 요청 탐지 — 규칙 기반. ML 탐지기(JOKER-KO)의 2중 방어.

왜 규칙인가: JOKER-KO 가 실제로 놓친 공격이 전부 '난독화'였다(역순 뒤집기·base64·초성분해·
글자사이 구분자). 이건 표면 패턴이 명확해 재학습보다 규칙으로 잡는 게 정석이고, ML 이 놓쳐도
규칙이 잡는 defense-in-depth 가 된다. 정보보안의 '알려진 우회 기법은 시그니처로 막는다' 그대로.

설계 원칙(정밀도 우선): 정상 문구를 공격으로 오탐하면 안 된다. 그래서
- 자모 분해는 'ㅋㅋㅋ·ㅠㅠ' 같은 정상 이모티콘(단일 자모 반복)을 피하려고, 한 run 안에
  자음과 모음이 '섞여' 있을 때만 분해로 본다('ㅈㅓ ㄱㅐㅂㅏㄹ' = 섞임 = 분해).
- 패턴은 난독화 '요청'에 특화된 좁은 것만 쓴다(번역·요약 같은 일반 요청은 제외).

순수 함수(의존성 없음) — torch 없이도 돌고, 정상셋 대상 오탐 측정이 쉽다.
"""

from __future__ import annotations

import re
import unicodedata

# 호환 자모 영역
_CONS_A, _CONS_B = "ㄱ", "ㅎ"   # ㄱ..ㅎ (자음)
_VOWEL_A, _VOWEL_B = "ㅏ", "ㅣ"  # ㅏ..ㅣ (모음)

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("역순요청", re.compile(r"거꾸로|뒤집어서?|역순|reverse", re.I)),
    ("자모분해요청", re.compile(r"초성(만|으로)?|자모(로|\s*분해)?|자음\s*만|모음\s*만|낱자로?")),
    ("구분자삽입",
     re.compile(r"글자\s*사이|한\s*글자씩|글자\s*마다|마침표를?\s*(넣|찍|추가)|사이사이|[A-Za-z0-9]\.[A-Za-z0-9]\.[A-Za-z0-9]")),
    ("인코딩요청", re.compile(r"base\s?64|베이스\s?64|인코딩|\bencode\b|16\s*진|\bhex\b|아스키|ascii", re.I)),
    ("로마자음차", re.compile(r"로마자로?|발음\s*대로|소리\s*나는\s*대로")),
]


def _mixed_jamo_run(text: str, min_len: int = 4) -> bool:
    """공백 제거 후, 자음과 모음이 섞인 자모 연속열이 min_len 이상이면 True.

    'ㅋㅋㅋ'(자음만)·'ㅠㅠ'(모음만) 같은 이모티콘은 섞이지 않아 걸리지 않는다.
    'ㅈㅓ ㄱㅐㅂㅏㄹ'(자음+모음)은 분해 공격으로 잡는다.
    """
    seq = re.sub(r"\s", "", text)
    run: list[str] = []

    def _hit(chars: list[str]) -> bool:
        if len(chars) < min_len:
            return False
        has_c = any(_CONS_A <= c <= _CONS_B for c in chars)
        has_v = any(_VOWEL_A <= c <= _VOWEL_B for c in chars)
        return has_c and has_v

    for ch in seq:
        if _CONS_A <= ch <= _VOWEL_B:   # 호환 자모(자음~모음) 영역
            run.append(ch)
        else:
            if _hit(run):
                return True
            run = []
    return _hit(run)


def obfuscation_flags(text: str) -> tuple[str, ...]:
    """입력에서 난독화 공격 요청 신호를 찾아 사유 목록으로 반환. 없으면 빈 튜플.

    NFC 정규화만 하고(합성 음절 보존), 판단은 원문에 대해 한다.
    """
    if not isinstance(text, str) or not text.strip():
        return ()
    t = unicodedata.normalize("NFC", text)
    flags: list[str] = []
    for name, pat in _PATTERNS:
        if pat.search(t):
            flags.append(name)
    if _mixed_jamo_run(t):
        flags.append("자모분해")
    # 중복 제거(순서 보존)
    seen: set[str] = set()
    out = [f for f in flags if not (f in seen or seen.add(f))]
    return tuple(out)
