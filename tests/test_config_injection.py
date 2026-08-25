"""경계: 설정은 불변 객체 1개를 주입한다. 전역 변수 mutation 이 없어야 한다.

이건 지금 구현돼 있으므로 '통과(초록)'가 정상이다.
"""

from __future__ import annotations

import dataclasses

import pytest

from joker.config import Profile, Settings, mask_secret


@pytest.mark.boundary
def test_settings_is_frozen():
    s = Settings()
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.temperature = 0.7  # type: ignore[misc]


@pytest.mark.boundary
def test_from_env_reads_mapping():
    s = Settings.from_env(
        {"JOKER_PROFILE": "local", "LLM_API_KEY": "secret123", "JOKER_TEMPERATURE": "0"}
    )
    assert s.profile is Profile.LOCAL
    assert s.llm_api_key == "secret123"
    assert s.temperature == 0.0


@pytest.mark.boundary
def test_override_returns_new_instance_without_mutating_original():
    s = Settings()
    s2 = s.with_(temperature=0.7)
    assert s2.temperature == 0.7
    assert s.temperature == 0.0, "원본이 바뀌면 안 된다(전역 mutation 없음)"
    assert s is not s2


@pytest.mark.boundary
def test_from_env_overrides_do_not_touch_environment():
    env = {"JOKER_PROFILE": "mock"}
    s = Settings.from_env(env, temperature=0.0, seed=7)
    assert s.seed == 7
    assert env == {"JOKER_PROFILE": "mock"}, "환경 딕셔너리를 건드리면 안 된다"


@pytest.mark.boundary
def test_api_key_never_appears_in_repr():
    s = Settings(llm_api_key="sk-abcd1234efgh")
    assert "sk-abcd1234efgh" not in repr(s)
    assert mask_secret("sk-abcd1234efgh") in repr(s)
