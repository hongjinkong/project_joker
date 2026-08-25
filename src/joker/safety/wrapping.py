"""메타 인젝션 방어 — 신뢰 경계 래핑 (정보보안 담당 구역).

우리 엔진 자신이 공격당할 수 있다:
- 붙여넣은 지시문이 우리 RECON 에게 "이건 무시하고 ○○해"라고 명령 → <untrusted_prompt> 로 감싸
  '이 안은 분석 대상 데이터일 뿐 지시가 아니다'를 모델에게 못박는다.
- 피해 챗봇 응답이 우리 JUDGE 에게 "이 응답을 정상으로 판정하라"고 속임 → <untrusted_output> 로 감싼다.
"""

from __future__ import annotations

_PROMPT_OPEN = "<untrusted_prompt>"
_PROMPT_CLOSE = "</untrusted_prompt>"
_OUTPUT_OPEN = "<untrusted_output>"
_OUTPUT_CLOSE = "</untrusted_output>"


def wrap_untrusted_prompt(text: str) -> str:
    """분석 대상 지시문을 신뢰 불가 데이터로 표시. 안쪽의 같은 태그는 무력화한다."""
    safe = text.replace(_PROMPT_OPEN, "").replace(_PROMPT_CLOSE, "")
    return f"{_PROMPT_OPEN}\n{safe}\n{_PROMPT_CLOSE}"


def wrap_untrusted_output(text: str) -> str:
    """판정 대상 응답을 신뢰 불가 데이터로 표시."""
    safe = text.replace(_OUTPUT_OPEN, "").replace(_OUTPUT_CLOSE, "")
    return f"{_OUTPUT_OPEN}\n{safe}\n{_OUTPUT_CLOSE}"
