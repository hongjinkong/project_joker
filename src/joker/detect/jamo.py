"""한글 자모 분해 — 자모·초성 유출 채널 탐지용.

★ 왜 필요한가 (2026-08-27 발견)
`detect/normalize.py` 는 `[^0-9A-Za-z가-힣]` 를 지운다. 그런데 낱개 자모(ㅂ ㅏ ㄱ)는
'가-힣' 범위 **밖**이라 통째로 삭제된다:

    normalize('ㅂ ㅏ ㄱ / ㅅ ㅓ / ㅈ ㅜ ㄴ 입니다.')  →  '입니다'

즉 자산 값이 한글일 때 **자모 분해 유출이 정규화 단계에서 증발한다.** 실측으로 확인:
자산 '박서준' 에 대해 자모분해·초성체·음차·조각 응답이 전부 block 판정이었다(평문만 leak).
보안 도구가 유출을 '안전'으로 보고하는 방향의 오답이라 함정②와 같은 급이다.

★ FP 를 막는 설계 — '낱개 자모만' 본다
응답의 음절까지 전부 분해해서 초성을 뽑으면, 긴 한국어 문장에서 임의의 3자음 시퀀스가
우연히 걸린다("복지 사항은 준수…"). 그래서 **초성 채널은 응답에 실제로 찍힌 낱개 자모만** 본다.
평범한 산문에는 낱개 자모가 없으므로 우연 일치가 원천적으로 안 생긴다.
자모 채널은 반대로 음절도 분해해 본다 — 값과 같은 음절을 써야만 걸리므로 안전하다.

한자 혼용(朴서준)은 한자↔한글 독음 매핑이 필요해 이번 범위 밖이다. 낱글자 조각 경로로 gray 에 걸린다.
"""

from __future__ import annotations

_BASE = 0xAC00
_LAST = 0xD7A3

# 유니코드 한글 음절 조합 순서 그대로 (호환 자모로 매핑)
_CHO = "ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ"
_JUNG = "ㅏㅐㅑㅒㅓㅔㅕㅖㅗㅘㅙㅚㅛㅜㅝㅞㅟㅠㅡㅢㅣ"
_JONG = ["", "ㄱ", "ㄲ", "ㄳ", "ㄴ", "ㄵ", "ㄶ", "ㄷ", "ㄹ", "ㄺ", "ㄻ", "ㄼ", "ㄽ", "ㄾ",
         "ㄿ", "ㅀ", "ㅁ", "ㅂ", "ㅄ", "ㅅ", "ㅆ", "ㅇ", "ㅈ", "ㅊ", "ㅋ", "ㅌ", "ㅍ", "ㅎ"]

# ★ 표 길이가 틀리면 IndexError 가 난다. romanize.py 에서 종성을 27개로 썼다가 실제로 터졌다.
assert len(_CHO) == 19 and len(_JUNG) == 21 and len(_JONG) == 28, "자모 표 길이 (19,21,28) 위반"

_CHO_SET = frozenset(_CHO)
_COMPAT_RANGE = (0x3131, 0x318E)   # ㄱ..ㆎ 호환 자모


def _is_compat_jamo(ch: str) -> bool:
    return _COMPAT_RANGE[0] <= ord(ch) <= _COMPAT_RANGE[1]


def to_jamo(text: str) -> str:
    """음절은 자모로 분해하고, 이미 낱개 자모면 그대로 둔다. 그 외 문자는 버린다.

    '박서준' → 'ㅂㅏㄱㅅㅓㅈㅜㄴ'
    'ㅂ ㅏ ㄱ / ㅅ ㅓ / ㅈ ㅜ ㄴ' → 'ㅂㅏㄱㅅㅓㅈㅜㄴ'   ← 둘이 같아진다(이게 목적)
    """
    out: list[str] = []
    for ch in text or "":
        code = ord(ch)
        if _BASE <= code <= _LAST:
            idx = code - _BASE
            out.append(_CHO[idx // 588])
            out.append(_JUNG[(idx % 588) // 28])
            out.append(_JONG[idx % 28])
        elif _is_compat_jamo(ch):
            out.append(ch)
    return "".join(out)


def standalone_choseong(text: str) -> str:
    """응답에 **낱개로 찍힌** 자음만 순서대로 모은다. 음절은 분해하지 않는다.

    'ㅂㅅㅈ 입니다' → 'ㅂㅅㅈ'   /   '복지 사항은 준수합니다' → ''  ← 우연 일치 없음
    """
    return "".join(ch for ch in (text or "") if _is_compat_jamo(ch) and ch in _CHO_SET)


def to_choseong(text: str) -> str:
    """값의 초성열. '박서준' → 'ㅂㅅㅈ'. (값 쪽에만 쓴다 — 응답에는 standalone_choseong)"""
    out: list[str] = []
    for ch in text or "":
        code = ord(ch)
        if _BASE <= code <= _LAST:
            out.append(_CHO[(code - _BASE) // 588])
        elif _is_compat_jamo(ch) and ch in _CHO_SET:
            out.append(ch)
    return "".join(out)


def hangul_chars(text: str) -> list[str]:
    """완성형 한글 음절만. 낱글자 조각 유출 판정에 쓴다."""
    return [ch for ch in (text or "") if _BASE <= ord(ch) <= _LAST]
