"""Provider 인터페이스. local / openai / mock 이 '같은 인터페이스'를 갖게 하는 계약.

이게 있어야 나중에 유료 API 로 갈아탈 때 코드 수정이 0줄이 된다(NFR-DV-003).
노드는 이 Protocol 만 알고, 어떤 구현이 주입됐는지 모른다 → mock 으로 단위 테스트가 된다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class Usage:
    """호출 1회의 사용량. budget.py 가 상한·비용 집계에 쓴다."""

    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@dataclass(frozen=True)
class CallResult:
    text: str
    model: str
    usage: Usage = field(default_factory=Usage)
    latency_ms: int = 0


@runtime_checkable
class LLMProvider(Protocol):
    """모든 provider 가 지켜야 하는 단 하나의 메서드."""

    def complete(
        self,
        *,
        system: str,
        user: str,
        temperature: float,
        seed: int,
    ) -> CallResult:
        ...
