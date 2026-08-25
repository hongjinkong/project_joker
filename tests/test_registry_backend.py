"""경계: 역할별 backend 혼합 조립(victim=로컬 + recon/judge=openai)이 올바른 접속을 만드는가."""

from __future__ import annotations

import pytest

from joker.config import Settings
from joker.providers.registry import build_providers


def _inner(prov):
    return getattr(prov, "inner", prov)  # budget 래퍼 벗기기


@pytest.mark.boundary
def test_backend_for_defaults_to_profile():
    s = Settings.from_env({"JOKER_PROFILE": "local"})
    assert s.backend_for("victim") == "local"
    assert s.backend_for("recon") == "local"


@pytest.mark.boundary
def test_mixed_backend_routes_each_role():
    s = Settings.from_env({
        "JOKER_PROFILE": "local",
        "RECON_BACKEND": "openai", "JUDGE_BACKEND": "openai",
        "OPENAI_API_KEY": "sk-test", "RECON_MODEL": "gpt-5-mini", "JUDGE_MODEL": "gpt-5-mini",
    })
    assert (s.backend_for("victim"), s.backend_for("recon"), s.backend_for("judge")) == ("local", "openai", "openai")

    p = build_providers(s)
    # victim 은 로컬 엔드포인트·로컬 모델을 유지해야 한다(정직한 재현 원칙)
    assert _inner(p["victim"]).base_url == "http://localhost:11434/v1"
    assert _inner(p["victim"]).model == "qwen2.5:3b-instruct"
    # recon/judge 는 상용 엔드포인트·gpt-5-mini
    assert _inner(p["recon"]).base_url == "https://api.openai.com/v1"
    assert _inner(p["recon"]).model == "gpt-5-mini"
    assert _inner(p["judge"]).base_url == "https://api.openai.com/v1"


@pytest.mark.boundary
def test_mock_profile_builds_role_mocks():
    s = Settings.from_env({"JOKER_PROFILE": "mock"})
    p = build_providers(s)
    # mock 은 네트워크 없는 대역 — complete 호출이 되면 CallResult 를 준다
    r = p["victim"].complete(system="s", user="u", temperature=0, seed=1)
    assert isinstance(r.text, str)
