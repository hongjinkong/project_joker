"""Deps — 노드에 주입하는 의존성 묶음.

노드는 providers 를 '직접 import 하지 않는다'(경계 규칙). 대신 이 Deps 를 인자로 받아
deps.victim.complete(...) 처럼 쓴다. 그래서 테스트에서 MockProvider 를 꽂아
모델 없이 전체 루프를 돌릴 수 있다.

Deps 는 providers.base 의 Protocol 만 참조한다(구현체 import 아님) → 경계 위반 아님.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from joker.config import Settings
from joker.models import Attack, DefensePattern
from joker.providers.base import LLMProvider


@dataclass(frozen=True)
class Deps:
    settings: Settings
    victim: LLMProvider           # 공격 대상 재현본(기본 로컬)
    recon: LLMProvider            # 정찰
    judge: LLMProvider            # 판정(gray 만)
    attacks: tuple[Attack, ...] = ()
    patterns: tuple[DefensePattern, ...] = ()
