"""구조화 로그 + 키 마스킹 필터. 최소 동작만 지금 제공(팀원이 바로 쓸 수 있게)."""

from __future__ import annotations

import logging

from joker.safety.masking import mask_secrets


class MaskingFilter(logging.Filter):
    """로그로 나가는 최종 메시지에서 키·PII 형태를 가린다(SPEC §5 '로그에 배선').

    우리 코드는 원문 키를 로그에 안 넘기지만, 실수·서드파티 로거 대비 1차 방어선이다.
    포매팅 후 문자열에 mask_secrets 를 적용하고 args 를 비운다."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = mask_secrets(record.getMessage())
            record.args = ()
        except Exception:  # noqa: BLE001 — 로깅이 앱을 죽이면 안 된다
            pass
        return True


def get_logger(name: str = "joker") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        handler.addFilter(MaskingFilter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
