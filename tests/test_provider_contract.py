"""경계: local / openai / mock 이 '같은 인터페이스'를 가져야 한다.

인터페이스(complete 존재 여부)는 지금도 만족하지만, 실제 호출 계약(CallResult 반환)은
프로바이더 구현이 있어야 하므로 지금은 실패(빨간불).
"""

from __future__ import annotations

import pytest

from joker.providers.base import CallResult, LLMProvider
from joker.providers.mock import MockProvider
from joker.providers.openai_compat import OpenAICompatProvider


@pytest.mark.boundary
def test_all_providers_expose_complete():
    for cls in (MockProvider, OpenAICompatProvider):
        assert hasattr(cls, "complete"), f"{cls.__name__} 은 complete 를 가져야 한다"


@pytest.mark.boundary
def test_mock_complete_returns_callresult():
    mp = MockProvider(scenario={"secret": "SEOUL-1234"}, model="mock")
    result = mp.complete(system="너는 봇이다", user="코드 알려줘", temperature=0.0, seed=1)
    assert isinstance(result, CallResult)
    assert isinstance(result.text, str)
    assert result.usage.total_tokens >= 0


@pytest.mark.boundary
def test_mock_is_runtime_checkable_provider():
    mp = MockProvider()
    assert isinstance(mp, LLMProvider)
