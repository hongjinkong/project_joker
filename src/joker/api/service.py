"""오케스트레이션 — POST /api/diagnose 가 부르는 fastapi-free 로직.

prepare(): 입력검증(400) → 프리셋 해석 → 코퍼스 로드 → 프로바이더 조립 →
  프리플라이트 1콜(연결 실패 502) → estimated_calls → run_id/target 확정.
make_worker(): prepare 결과로 '실제 진단 + DB 저장'을 하는 무인자 함수를 만든다(잡 워커가 호출).

★ fastapi 를 import 하지 않는다. app.py 는 이걸 배선만 한다.
★ 프리플라이트를 POST 에서 하는 이유: BYOK 는 잘못된 키로 3~4분·요금을 날리기 전에
  즉시 502 로 알려야 한다(사용자가 고른 설계).
"""

from __future__ import annotations

import datetime
import secrets
from pathlib import Path

from joker.api import presets
from joker.api.serialize import target_block
from joker.corpus.loader import load_default_corpus, load_patterns
from joker.deps import Deps
from joker.pipeline import run_pipeline
from joker.providers.openai_compat import ProviderError
from joker.providers.registry import build_providers
from joker.providers.usage import estimate_calls


def _err(status: int, code: str, message: str) -> dict:
    return {"ok": False, "status": status, "code": code, "message": message}


def prepare(body: dict, base_settings, data_dir: str) -> dict:
    prompt = (body.get("target_prompt") or "").strip()
    if not prompt:
        return _err(400, "target_prompt_required", "진단할 시스템 프롬프트(target_prompt)가 필요합니다.")

    mode = body.get("mode") or "screening"
    if mode not in ("screening", "full"):
        return _err(400, "bad_mode", "mode 는 screening 또는 full 이어야 합니다.")

    settings, err = presets.resolve_target(body.get("target"), base_settings)
    if err:
        return {"ok": False, **err}
    settings = settings.with_(full_sweep=(mode == "full"))

    dd = Path(data_dir)
    attacks = load_default_corpus(str(dd), run_audit=False)
    patterns = load_patterns(dd.parent / "defenses" / "patterns.yaml")
    providers = build_providers(settings)

    # 프리플라이트 1콜 — 대상 모델이 실제로 응답하는지 확인. 실패 시 즉시 502.
    try:
        providers["victim"].complete(
            system="ping", user="ping",
            temperature=settings.temperature, seed=settings.seed,
        )
    except ProviderError:
        return _err(502, "target_unreachable",
                    "대상 모델 연결에 실패했습니다. base_url·api_key·모델명을 확인하세요.")

    est = estimate_calls(len(attacks), full=settings.full_sweep)
    run_id = f"run_{datetime.datetime.now():%Y%m%d_%H%M%S}_{secrets.token_hex(2)}"
    return {
        "ok": True, "run_id": run_id, "settings": settings, "providers": providers,
        "attacks": attacks, "patterns": patterns, "estimated": est,
        "target": target_block(settings.target_info()), "prompt": prompt,
    }


def redact_state_responses(state) -> None:
    """저장 직전, 각 attempt.response_raw 에서 RECON 이 찾은 자산 값을 지운다(제자리 변경).

    계약 "response_excerpt 에 비밀값 원문은 오지 않는다" + NFR-DV-002('기본 미저장')의 실체.
    verdict/leak_channel 은 이미 판정이 끝난 상태라 증거 손실이 없다. 리터럴 + 조각 변형까지
    지운다(masking.redact_values). 역순·base64·초성은 규칙 탐지가 leak 으로 잡아 등급에 반영된다.
    """
    from joker.safety.masking import redact_values

    secret_values = [a.value for a in state.get("assets", []) if a.value]
    if not secret_values:
        return
    for at in state.get("attempts", []):
        at.response_raw = redact_values(at.response_raw, secret_values)


def make_worker(prep: dict, repo):
    """진단 실행 + 저장을 하는 무인자 함수. 여기서만 SQLite 에 쓴다(잡 워커 스레드)."""
    settings = prep["settings"]
    providers = prep["providers"]

    def _work() -> None:
        deps = Deps(
            settings=settings,
            victim=providers["victim"], recon=providers["recon"], judge=providers["judge"],
            attacks=tuple(prep["attacks"]), patterns=tuple(prep["patterns"]),
        )
        state = run_pipeline(prep["prompt"], deps, run_id=prep["run_id"])
        redact_state_responses(state)  # ★ 저장 전 자산값 마스킹(사용자 결정 0831)
        # 재현 맥락(SPEC §4) — target 을 파이프라인이 이미 넣지만, 옛 키 폴백도 채워둔다.
        state["env_profile"] = settings.env_profile
        state["backend"] = settings.backend_for("victim")
        state["victim_model"] = settings.victim_model
        repo.init_schema()
        repo.save_run(state)

    return _work
