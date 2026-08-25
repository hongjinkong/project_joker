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
