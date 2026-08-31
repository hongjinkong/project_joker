"""입력단 개인정보·API 키 마스킹. 기본 미저장(NFR-DV-002)의 실체.

사용자가 붙여넣은 지시문에 진짜 API 키·개인정보가 섞여 있을 수 있다. 로그·저장 전에 가린다.
완벽한 PII 탐지가 목표가 아니라, '흔한 키 형태'를 놓치지 않는 1차 방어선이다.
"""

from __future__ import annotations

import re

_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),          # OpenAI 계열 키
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b"),     # AWS 액세스 키
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),           # GitHub 토큰
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),   # Slack 토큰
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),  # 이메일
    re.compile(r"\b\d{3}-\d{3,4}-\d{4}\b"),            # 전화번호
    re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b"),       # 길이 긴 토큰/base64
]

_MASK = "[REDACTED]"


def mask_secrets(text: str) -> str:
    out = text
    for pat in _PATTERNS:
        out = pat.sub(_MASK, out)
    return out


def _value_variants(v: str) -> list[str]:
    """자산 값 + '조각내 흘리기' 변형. 값을 영숫자 토큰으로 쪼갠 뒤 흔한 구분자로 다시 이어
    붙인 형태만 만든다(예 'SEOUL-1234' → 'SEOUL 1234' · 'SEOUL\n1234' · 'SEOUL1234').

    ★ 개별 토큰('SEOUL' 단독)은 넣지 않는다 — 도시명·흔한 단어를 본문 전역에서 과잉
      마스킹하면 excerpt 가 못 읽게 된다. 토큰이 '함께' 나올 때만(값의 구조) 가린다.
    """
    variants = {v}
    tokens = re.findall(r"[A-Za-z0-9]+", v)
    if len(tokens) >= 2:
        for sep in ("", " ", "\n", "-", " - ", "\n\n", "\t", ": "):
            variants.add(sep.join(tokens))
    return [x for x in variants if len(x) >= 3]


def redact_values(text: str, values, mask: str = _MASK) -> str:
    """알려진 자산 '값' 원문을 텍스트에서 지운다(저장 전 1차 방어선).

    계약 약속 "response_excerpt 에 비밀값 원문은 오지 않는다" 의 실체.
    mask_secrets 는 sk-/AWS/이메일 같은 '키 형태'만 잡고, RECON 이 그 진단에서 찾은
    자산 값(예: SEOUL-1234)은 못 잡는다 — 그 값을 워커가 저장 전에 여기서 지운다.

    리터럴 + '조각내 흘리기' 변형(구분자만 바꾼 것)까지 잡는다. 역순·base64·초성 같은
    인코딩 변형은 여전히 못 잡는다(그건 규칙 탐지가 leak 으로 잡아 등급에는 반영된다).
    """
    if not text or not values:
        return text
    variants: list[str] = []
    for v in values:
        if v:
            variants.extend(_value_variants(v))
    out = text
    # 긴 변형부터 지운다(부분 문자열이 먼저 지워져 긴 변형을 못 잡는 일 방지)
    for v in sorted(set(variants), key=len, reverse=True):
        out = out.replace(v, mask)
    return out
