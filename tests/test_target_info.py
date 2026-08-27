"""진단 대상 모델(계약 v0.2) — 역할별 접속정보 + 리포트의 target 블록.

배경 (2026-08-27): 리포트가 "당신 챗봇은 B등급"이라고 말했지만 실제로 잰 건
"qwen2.5:3b 에 당신 지시문을 붙였을 때 B등급" 이었다. 고객사마다 쓰는 모델이 다르므로
모델명 없는 등급은 **다른 대상의 결과를 자기 결과로 오독시킨다** — 함정②와 같은 급의 오답.

또 하나: `openai_base_url/key` 가 1쌍뿐이라 backend="openai" 인 모든 역할이 같은 엔드포인트를
공유했다. victim=고객 모델(BYOK) + judge=우리 OpenAI 조합이 구조적으로 불가능했다.
"""

from __future__ import annotations

import dataclasses

from joker.config import Profile, Settings, mask_secret
from joker.pipeline import run_pipeline
from joker.providers.mock import MockProvider
from joker.providers.registry import build_providers
from joker.state import STATE_KEYS

from conftest import TARGET_NO_SECRET, TARGET_WITH_SECRET

LOCAL = Settings(profile=Profile.LOCAL, victim_model="qwen2.5:3b-instruct",
                 llm_base_url="http://localhost:11434/v1", llm_api_key="ollama")


# ── 역할별 접속정보 ──────────────────────────────────────────
def test_endpoint_falls_back_to_backend_default():
    """역할별 지정이 없으면 예전과 똑같이 동작한다(.env 안 바꾼 팀원 환경 보호)."""
    s = LOCAL.with_(recon_backend="openai", openai_base_url="https://api.openai.com/v1",
                    openai_api_key="sk-test")
    assert s.endpoint_for("victim") == ("http://localhost:11434/v1", "ollama")
    assert s.endpoint_for("recon") == ("https://api.openai.com/v1", "sk-test")


def test_per_role_endpoint_allows_mixing_vendors():
    """victim=타 벤더 + judge=OpenAI. 이게 안 되면 BYOK 진단이 불가능하다."""
    s = LOCAL.with_(
        recon_backend="openai", judge_backend="openai",
        openai_base_url="https://api.openai.com/v1", openai_api_key="sk-ours",
        victim_base_url="https://example-vendor/v1", victim_api_key="cust-key",
    )
    assert s.endpoint_for("victim") == ("https://example-vendor/v1", "cust-key")
    assert s.endpoint_for("judge") == ("https://api.openai.com/v1", "sk-ours")


def test_registry_uses_the_per_role_endpoint():
    s = LOCAL.with_(victim_base_url="https://example-vendor/v1", victim_api_key="cust-key")
    pr = build_providers(s)
    inner = getattr(pr["victim"], "inner", pr["victim"])   # BudgetProvider 래핑
    assert inner.base_url == "https://example-vendor/v1"
    assert inner.api_key == "cust-key"


def test_settings_repr_never_leaks_a_key():
    s = LOCAL.with_(victim_api_key="cust-supersecret", openai_api_key="sk-supersecret")
    text = repr(s)
    assert "cust-supersecret" not in text
    assert "sk-supersecret" not in text


def test_mask_secret_does_not_reveal_length():
    """마스킹 문자열이 키 길이를 알려주면 안 된다 — 별표 개수 고정."""
    short = mask_secret("sk-" + "a" * 20)
    long = mask_secret("sk-" + "a" * 200)
    assert len(short) == len(long)
    assert "a" * 5 not in short


# ── target 블록 ─────────────────────────────────────────────
def test_target_is_declared_in_the_state_schema():
    """★ 함정③ — State TypedDict 에 없는 키는 LangGraph 가 조용히 버린다."""
    assert "target" in STATE_KEYS


def _mock_deps(base, **over):
    return dataclasses.replace(base, settings=base.settings.with_(**over)) if over else base


def test_report_carries_what_was_diagnosed(mock_deps_vulnerable):
    state = run_pipeline(TARGET_WITH_SECRET, mock_deps_vulnerable, run_id="t_target")
    t = state["target"]
    assert t.model == mock_deps_vulnerable.settings.victim_model
    assert t.temperature == mock_deps_vulnerable.settings.temperature
    assert t.seed == mock_deps_vulnerable.settings.seed


def test_default_preset_is_flagged_as_approximation(mock_deps_vulnerable):
    """대리 모덴로 쟀으면 그렇다고 말해야 한다. 화면이 이 값으로 칩을 띄운다."""
    state = run_pipeline(TARGET_WITH_SECRET, mock_deps_vulnerable, run_id="t_appx")
    t = state["target"]
    assert t.is_approximation is True
    assert t.approximation_notice and t.model in t.approximation_notice


def test_byok_is_not_an_approximation(mock_deps_vulnerable):
    """사용자가 자기 모델을 지정했으면 진짜 그 모델을 잰 것이다."""
    deps = _mock_deps(mock_deps_vulnerable, target_preset="byok", victim_model="gpt-4o-mini")
    state = run_pipeline(TARGET_WITH_SECRET, deps, run_id="t_byok")
    t = state["target"]
    assert t.is_approximation is False
    assert t.approximation_notice is None
    assert t.model == "gpt-4o-mini"


def test_inconclusive_run_still_reports_the_target(mock_deps):
    """등급이 없어도 '무엇을 진단했는지'는 온다(계약 v0.2: status 무관)."""
    state = run_pipeline(TARGET_NO_SECRET, mock_deps, run_id="t_inc")
    assert state["report"].inconclusive is True
    assert state["target"] is not None


def test_target_info_contains_no_secret_value(mock_deps_vulnerable):
    """target 블록은 화면·이력에 그대로 나간다. 값이 섞이면 안 된다."""
    state = run_pipeline(TARGET_WITH_SECRET, mock_deps_vulnerable, run_id="t_novalue")
    blob = repr(state["target"])
    assert "SEOUL-1234" not in blob
