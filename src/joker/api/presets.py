"""진단 대상 모델 프리셋 카탈로그 + 요청 target 블록 해석.

GET /api/models 가 이 목록을 그대로 준다 — 화면에 모델명을 하드코딩하지 않게 하기 위함(계약 §5).
resolve_target 은 POST 요청의 target 블록을 Settings override 로 바꾸고, 잘못된 입력을 400 으로 막는다.

★ fastapi 를 import 하지 않는다(브리지에서 단위 검증 가능).
★ BYOK 키는 여기서 Settings 로만 흘러가고 저장·로그·응답 어디에도 남지 않는다(계약 BYOK 규칙).
"""

from __future__ import annotations

from joker.config import Profile

# 프리셋 = '우리가 검증해 둔 진단 대상'. 밑줄(_) 필드는 override 레시피라 화면엔 안 나간다.
PRESETS: list[dict] = [
    {
        "id": "local_qwen3b",
        "label": "qwen2.5:3b (로컬 대리 모델)",
        "backend": "local",
        "requires_key": False,
        "verified": True,
        "fidelity": "proxy_model",
        "note": "기본값. 저가 모델을 쓰는 실제 챗봇 환경을 재현한다. 키가 필요 없다.",
        "_victim_backend": "local",
        "_victim_model": "qwen2.5:3b-instruct",
    },
    {
        "id": "local_gemma4b",
        "label": "gemma3:4b (로컬 대리 모델)",
        "backend": "local",
        "requires_key": False,
        "verified": True,
        "fidelity": "proxy_model",
        "note": "또 다른 저가 로컬 모델. 같은 지시문·공격이라도 처방 후 결과가 qwen 과 다르다 — '모델 선택도 보안 결정'(발표 포인트).",
        "_victim_backend": "local",
        "_victim_model": "gemma3:4b",
    },
    {
        "id": "byok",
        "label": "내 API 키로 실제 모델 진단",
        "backend": "openai_compat",
        "requires_key": True,
        "verified": True,
        "fidelity": "real_model",
        "note": "OpenAI 호환 엔드포인트만 지원. base_url·model·api_key 를 직접 입력한다.",
    },
]

DEFAULT_PRESET = "local_qwen3b"


def _public(spec: dict) -> dict:
    """밑줄로 시작하는 내부 override 필드를 걷어낸 화면용 뷰."""
    return {k: v for k, v in spec.items() if not k.startswith("_")}


def _by_id(preset_id: str) -> dict | None:
    return next((p for p in PRESETS if p["id"] == preset_id), None)


def list_models() -> dict:
    """GET /api/models 응답. 목록은 서버가 준다(계약 §5)."""
    return {"default": DEFAULT_PRESET, "presets": [_public(p) for p in PRESETS]}


def _err(status: int, code: str, message: str) -> dict:
    return {"status": status, "code": code, "message": message}


def _valid_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def resolve_target(target: dict | None, base):
    """요청 target 블록 → (Settings, None) 또는 (None, error).

    - 생략/기본 프리셋: victim 만 프리셋대로 고정하고 recon/judge 는 .env 를 유지한다.
    - byok: 사용자가 base_url·model·api_key 를 직접 준 것 → fidelity=real_model.
      키는 Settings.victim_api_key 로만 들어가고 그 밖으로 새지 않는다.
    """
    if not target:
        target = {"preset": DEFAULT_PRESET}
    preset = target.get("preset") or DEFAULT_PRESET
    spec = _by_id(preset)
    if spec is None:
        return None, _err(400, "unknown_preset", f"지원하지 않는 프리셋입니다: {preset}")

    if preset == "byok":
        model = (target.get("model") or "").strip()
        base_url = (target.get("base_url") or "").strip()
        api_key = target.get("api_key") or ""
        if not model:
            return None, _err(400, "target_model_required", "진단할 모델명(target.model)이 필요합니다.")
        if not _valid_url(base_url):
            return None, _err(400, "bad_base_url", "base_url 이 http(s):// 형식이 아닙니다.")
        if not api_key:
            return None, _err(400, "api_key_required", "BYOK 진단에는 api_key 가 필요합니다.")
        settings = base.with_(
            victim_backend="openai",
            victim_base_url=base_url,
            victim_api_key=api_key,
            victim_model=model,
            target_preset="byok",
        )
        return settings, None

    # 프리셋(로컬 대리) — victim 만 프리셋대로 고정하고 recon/judge 는 .env 유지.
    # ★ 프로파일이 mock 이면 backend 를 강제하지 않는다 → victim 도 mock 으로 떨어져
    #   발표 백업 경로(JOKER_PROFILE=mock)가 즉시·결정론적으로 완주한다.
    #   (target.backend 는 그때 mock 으로 정직히 찍힌다. 실측은 JOKER_PROFILE=local.)
    over = {"victim_model": spec["_victim_model"], "target_preset": preset}
    if base.profile is not Profile.MOCK:
        over["victim_backend"] = spec["_victim_backend"]
    settings = base.with_(**over)
    return settings, None
