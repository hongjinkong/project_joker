"""호출 상한 + 토큰 집계 래퍼. 유료 API 대비 비용 방어.

어떤 provider 든 이걸로 감싸면 진단 1회 호출 상한을 넘는 순간 예외로 막는다.
토큰 누적은 사용량·비용 집계의 근거가 된다.
"""

from __future__ import annotations

from joker.providers.base import CallResult, LLMProvider


class BudgetExceeded(Exception):
    pass


class BudgetProvider:
    def __init__(self, inner: LLMProvider, *, max_calls: int) -> None:
        self.inner = inner
        self.max_calls = max_calls
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def complete(self, *, system: str, user: str, temperature: float, seed: int) -> CallResult:
        if self.calls >= self.max_calls:
            raise BudgetExceeded(f"호출 상한 {self.max_calls}회 초과")
        self.calls += 1
        res = self.inner.complete(system=system, user=user, temperature=temperature, seed=seed)
        self.prompt_tokens += res.usage.prompt_tokens
        self.completion_tokens += res.usage.completion_tokens
        return res
