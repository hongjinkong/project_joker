"""구조화 로그 + 키 마스킹 필터. 최소 동작만 지금 제공(팀원이 바로 쓸 수 있게)."""

from __future__ import annotations

import logging


def get_logger(name: str = "joker") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
