"""공격문 플레이스홀더 치환. str.format() 금지 — replace() 로만(함정④).

공격문에는 JSON·딕셔너리 예시가 들어 있어 중괄호가 리터럴로 존재한다. str.format() 은
그 중괄호를 치환 필드로 오해해 터진다. 그래서 우리가 정한 플레이스홀더 4개만
문자열 replace 로 바꾼다. 나머지 중괄호는 그대로 둔다.
"""

from __future__ import annotations

from joker.models import PLACEHOLDERS, Attack

# ("{asset}", "{persona}", "{org}", "{decoy}") → 키 이름만 뽑아둔다
_KEYS = tuple(p.strip("{}") for p in PLACEHOLDERS)


def render_attack(attack: Attack, context: dict[str, str]) -> str:
    """attack.text 안의 {asset}/{persona}/{org}/{decoy} 만 context 값으로 치환.

    context 에 없는 키는 그대로 둔다(치환 실패로 죽지 않는다).
    """
    text = attack.text
    for key in _KEYS:
        if key in context and context[key] is not None:
            text = text.replace("{" + key + "}", str(context[key]))
    return text
