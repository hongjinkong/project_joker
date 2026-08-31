"""api/presets — 진단 대상 프리셋 카탈로그 + 요청 target 해석(계약 v0.3).

GET /api/models 목록에 내부 override 필드가 새지 않는가, resolve_target 이 프리셋/BYOK 를
Settings 로 옳게 바꾸고 잘못된 입력을 400 으로 막는가, BYOK 키가 repr 로 새지 않는가.
"""

from __future__ import annotations

import pytest

from joker.api import presets
from joker.config import Profile, Settings


def test_list_models_hides_internal_fields():
    m = presets.list_models()
    assert m["default"] == "local_qwen3b"
    ids = [p["id"] for p in m["presets"]]
    assert "local_qwen3b" in ids and "byok" in ids
    for p in m["presets"]:
        assert not any(k.startswith("_") for k in p), "내부 override 필드(_victim_*)가 응답에 새면 안 된다"


def test_default_preset_is_proxy_model():
    s, e = presets.resolve_target(None, Settings.from_env(environ={}))
    assert e is None
    assert s.target_preset == "local_qwen3b" and s.is_proxy_model


def test_mock_profile_keeps_victim_mock():
    # 백업 경로(JOKER_PROFILE=mock)는 프리셋이 있어도 victim 이 mock 이라 즉시 완주해야 한다.
    s, e = presets.resolve_target(None, Settings(profile=Profile.MOCK))
    assert e is None and s.backend_for("victim") == "mock"


def test_local_profile_forces_local_victim():
    s, e = presets.resolve_target(None, Settings(profile=Profile.LOCAL))
    assert e is None and s.backend_for("victim") == "local"


def test_byok_maps_settings_and_hides_key():
    body = {"preset": "byok", "model": "gpt-4o-mini",
            "base_url": "https://api.openai.com/v1", "api_key": "sk-secret999888"}
    s, e = presets.resolve_target(body, Settings(profile=Profile.MOCK))
    assert e is None
    assert not s.is_proxy_model and s.backend_for("victim") == "openai"
    assert s.victim_model == "gpt-4o-mini" and s.victim_api_key == "sk-secret999888"
    assert "sk-secret999888" not in repr(s), "BYOK 키가 repr 로 새면 안 된다(계약 BYOK 규칙)"


@pytest.mark.parametrize("body,code", [
    ({"preset": "nope"}, "unknown_preset"),
    ({"preset": "byok", "base_url": "https://x/v1", "api_key": "k"}, "target_model_required"),
    ({"preset": "byok", "model": "m", "base_url": "ftp://x", "api_key": "k"}, "bad_base_url"),
    ({"preset": "byok", "model": "m", "base_url": "https://x/v1"}, "api_key_required"),
])
def test_resolve_target_400(body, code):
    s, e = presets.resolve_target(body, Settings(profile=Profile.MOCK))
    assert s is None and e["status"] == 400 and e["code"] == code
