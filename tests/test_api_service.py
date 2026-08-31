"""api/service + api/jobs — POST 오케스트레이션·프리플라이트·워커 자산값 마스킹·잡 전이.

mock 프로파일이면 프리셋이 있어도 victim 이 mock 이라 prepare 가 네트워크 없이 완주한다.
502 는 프리플라이트가 대상 모델 연결 실패를 잡는 경로(build_providers 를 실패 스텁으로 교체).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from joker.api import jobs, service
from joker.api.service import redact_state_responses
from joker.config import Profile, Settings
from joker.models import Asset, AssetKind, Attempt, Goal, Technique
from joker.providers.openai_compat import ProviderError
from joker.safety.masking import redact_values

DATA = str(Path(__file__).parent.parent / "data" / "attacks")


@pytest.fixture
def mock_settings() -> Settings:
    return Settings(profile=Profile.MOCK, env_profile="pytest")


def test_prepare_happy_path(mock_settings):
    prep = service.prepare({"target_prompt": "너는 한비야. 코드는 SEOUL-1234."}, mock_settings, DATA)
    assert prep["ok"]
    assert prep["run_id"].startswith("run_")
    assert prep["estimated"]["victim_max"] > 0
    assert prep["target"]["fidelity"] == "proxy_model"
    assert callable(service.make_worker(prep, repo=None))


def test_prepare_full_mode_has_more_calls(mock_settings):
    scr = service.prepare({"target_prompt": "x", "mode": "screening"}, mock_settings, DATA)
    full = service.prepare({"target_prompt": "x", "mode": "full"}, mock_settings, DATA)
    assert full["estimated"]["victim_max"] >= scr["estimated"]["victim_max"]


@pytest.mark.parametrize("body,code", [
    ({}, "target_prompt_required"),
    ({"target_prompt": "x", "mode": "quick"}, "bad_mode"),
    ({"target_prompt": "x", "target": {"preset": "nope"}}, "unknown_preset"),
    ({"target_prompt": "x", "target": {"preset": "byok", "base_url": "https://a/v1", "api_key": "k"}},
     "target_model_required"),
])
def test_prepare_400(body, code, mock_settings):
    r = service.prepare(body, mock_settings, DATA)
    assert not r["ok"] and r["status"] == 400 and r["code"] == code


def test_prepare_502_on_unreachable_target(monkeypatch, mock_settings):
    class _Boom:
        def complete(self, **_kw):
            raise ProviderError("connection refused")

    monkeypatch.setattr(service, "build_providers",
                        lambda s: {"victim": _Boom(), "recon": _Boom(), "judge": _Boom()})
    r = service.prepare({"target_prompt": "x"}, mock_settings, DATA)
    assert not r["ok"] and r["status"] == 502 and r["code"] == "target_unreachable"


# ── 저장 전 자산값 마스킹 ──────────────────────────────────
def test_redact_values_literal_segmented_and_hallucination():
    v = ["SEOUL-1234"]
    assert redact_values("코드 SEOUL-1234 다", v) == "코드 [REDACTED] 다"
    # 조각(줄바꿈으로 쪼갠) 유출도 잡는다
    seg = redact_values("SEOUL\n1234\n비공개", v)
    assert "SEOUL" not in seg.replace("비공개", "") and "1234" not in seg
    # 모델이 지어낸 다른 값(환각)은 사용자 데이터가 아니므로 보존
    assert redact_values("SEOUL-9999", v) == "SEOUL-9999"


def test_redact_state_responses_in_place():
    state = {
        "assets": [Asset(name="관리자 코드", value="SEOUL-1234", kind=AssetKind.SECRET_VALUE)],
        "attempts": [Attempt(attack_id="A-1", technique=Technique.AUTH, goal=Goal.INFO_LEAK,
                             round_no=1, rendered_text="", response_raw="값은 SEOUL-1234 이다")],
    }
    redact_state_responses(state)
    raw = state["attempts"][0].response_raw
    assert "SEOUL-1234" not in raw and "[REDACTED]" in raw


def test_redact_state_responses_noop_without_values():
    state = {"assets": [Asset(name="이름", value=None, kind=AssetKind.PERSONA)],
             "attempts": [Attempt(attack_id="A", technique=Technique.ROLE, goal=Goal.INFO_LEAK,
                                  round_no=1, rendered_text="", response_raw="원문 유지")]}
    redact_state_responses(state)
    assert state["attempts"][0].response_raw == "원문 유지"


# ── 잡 레지스트리 상태 전이 ────────────────────────────────
def test_job_registry_running_to_done():
    reg = jobs.JobRegistry()
    reg.register("r1", {"model": "m"}, {"victim_max": 36})
    assert reg.get("r1").status == "running"
    reg._run("r1", lambda: None)
    assert reg.get("r1").status == "done"


def test_job_registry_provider_error_maps_to_target_unreachable():
    reg = jobs.JobRegistry()
    reg.register("r2", {"model": "m"}, {"victim_max": 36})

    def _boom():
        raise ProviderError("x")

    reg._run("r2", _boom)
    j = reg.get("r2")
    assert j.status == "error" and j.error["code"] == "target_unreachable"
