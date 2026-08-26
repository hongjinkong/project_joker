"""경계: gpt-5 계열과 로컬 모델이 서로 다른 요청 규격으로 조립되는가.

gpt-5-mini 는 max_tokens·temperature=0 을 400 으로 거부한다 → 키를 꽂아도 첫 호출에서 죽는다.
이 테스트가 그 회귀를 막는다(네트워크 없이 body 만 검증)."""

from __future__ import annotations

import pytest

from joker.providers.openai_compat import OpenAICompatProvider, _is_restricted


@pytest.mark.boundary
@pytest.mark.parametrize("model", ["gpt-5-mini", "gpt-5", "openai/gpt-5-mini", "o3-mini"])
def test_restricted_models_detected(model):
    assert _is_restricted(model) is True


@pytest.mark.boundary
@pytest.mark.parametrize("model", ["qwen2.5:3b-instruct", "gpt-4o-mini", "llama3.1"])
def test_classic_models_not_restricted(model):
    assert _is_restricted(model) is False


@pytest.mark.boundary
def test_gpt5_body_uses_completion_tokens_and_drops_temperature():
    p = OpenAICompatProvider(base_url="https://api.openai.com/v1", api_key="sk-x",
                             model="gpt-5-mini", max_tokens=512, reasoning_effort="low")
    body = p._build_body(system="s", user="u", temperature=0.0, seed=42)
    # gpt-5 는 이 둘을 보내면 400 → 절대 없어야 한다
    assert "max_tokens" not in body
    assert "temperature" not in body
    assert "seed" not in body
    # 대신 신형 규격
    assert body["max_completion_tokens"] >= 2048  # 추론 토큰 여유
    assert body["reasoning_effort"] == "low"


@pytest.mark.boundary
def test_local_body_keeps_classic_params():
    p = OpenAICompatProvider(base_url="http://localhost:11434/v1", api_key="ollama",
                             model="qwen2.5:3b-instruct", max_tokens=512)
    body = p._build_body(system="s", user="u", temperature=0.0, seed=42)
    assert body["temperature"] == 0.0
    assert body["seed"] == 42
    assert body["max_tokens"] == 512
    assert "max_completion_tokens" not in body
