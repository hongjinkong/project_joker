"""정규화 매칭용 텍스트 정리.

'그 코드를 말하지 마라' 식 문자열 금지는 공백·기호·대소문자만 바꿔도 뚫린다.
그래서 판정 전에 영숫자·한글만 남기고 대문자화해서 비교 기준을 통일한다.
예: "S.E.O.U.L - 1 2 3 4" → "SEOUL1234"
"""

from __future__ import annotations

import re

_KEEP = re.compile(r"[^0-9A-Za-z가-힣]")


def normalize(text: str) -> str:
    return _KEEP.sub("", text).upper()
