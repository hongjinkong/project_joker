"""설정 객체. 이전 뼈대의 최대 약점(전역 변수 mutation)을 여기서 끊는다.

왜 frozen dataclass 인가:
- 이전에는 설정이 import 시점 전역 변수였고 CLI 가 모듈 속성을 덮어썼다. 어디서 값이 바뀌는지
  추적이 안 됐다. 여기서는 Settings 를 '불변 값 객체' 하나로 만들고, 바꿀 땐 with_() 로
  '새 인스턴스'를 만든다. 전역 상태가 없으니 테스트가 서로 오염되지 않는다.
- 접속 정보는 반드시 환경변수 3개(LLM_BASE_URL/LLM_API_KEY/모델명)로만 주입한다(재현성 규칙 4).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Mapping


def load_dotenv(path: str = ".env") -> None:
    """.env 파일의 KEY=VALUE 를 os.environ 에 채운다(이미 있는 진짜 환경변수는 안 덮음).

    표준 라이브러리만으로 처리(의존성 추가 없음). 인라인 주석(값 뒤 ' #')은 잘라낸다.
    CLI/스크립트 진입점에서 한 번 호출한다.
    """
    p = Path(path)
    if not p.exists():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.split(" #", 1)[0].strip().strip('"').strip("'")  # 인라인 주석·따옴표 제거
        if key:
            os.environ.setdefault(key, val)  # 인라인 export 가 우선(setdefault)


class Profile(str, Enum):
    """Provider 조립 분기의 유일한 근거. registry.py 만 이 값을 읽는다."""

    MOCK = "mock"              # 네트워크 없음. 팀원·CI·발표 백업 경로
    LOCAL = "local"           # Ollama (OpenAI 호환 엔드포인트)
    OPENAI = "openai"         # 상용 API
    FULL_LOCAL = "full_local"  # RECON 까지 로컬 — 지시문이 한 글자도 밖으로 안 나감(차별점)


def mask_secret(secret: str | None) -> str:
    """로그·repr 에 키 원문이 남지 않게 한다(키 유출 1차 방어선)."""
    if not secret:
        return "<none>"
    if len(secret) <= 4:
        return "****"
    # ★ 별표 개수를 고정한다(2026-08-27). 원래는 len(secret)-4 개라 마스킹된 문자열이
    #   **키 길이를 그대로 알려줬다.** 길이는 키 종류를 좁히는 단서이고, doctor 출력이
    #   한 줄에 200자씩 찍혀 읽히지도 않았다. 앞 2 + 고정 6 + 뒤 2.
    return f"{secret[:2]}{'*' * 6}{secret[-2:]}"


@dataclass(frozen=True)
class Settings:
    profile: Profile = Profile.MOCK
    llm_base_url: str = "http://localhost:11434/v1"
    llm_api_key: str = ""
    victim_model: str = "qwen2.5:3b-instruct"
    recon_model: str = "qwen2.5:3b-instruct"
    judge_model: str = "qwen2.5:3b-instruct"
    # ── 역할별 backend (혼합 배치) ──────────────────────────
    # 각 노드가 어느 백엔드를 쓸지 개별 지정. None 이면 profile 을 따른다.
    # 예) victim=로컬 유지 + recon/judge 만 openai → 지시문 원문 최소 노출 + 판정 정확도↑
    victim_backend: str | None = None   # "mock" | "local" | "openai"
    recon_backend: str | None = None
    judge_backend: str | None = None
    # OpenAI(상용) 접속 — 로컬(llm_*)과 별도. 그래서 victim=로컬, recon/judge=openai 를 섞을 수 있다
    openai_base_url: str = "https://api.openai.com/v1"
    openai_api_key: str = ""
    # ── 역할별 접속정보 (계약 v0.2 · 2026-08-27) ─────────────
    # 왜 필요한가: openai_* 가 1쌍뿐이라 backend="openai" 인 모든 역할이 같은 엔드포인트를 공유했다.
    #   → victim=Gemini + judge=OpenAI 처럼 **벤더를 섞는 게 구조적으로 불가능**했다.
    #   실제 고객사는 저마다 다른 모델을 쓰므로(BYOK) 역할별로 따로 꽂을 수 있어야 한다.
    # 비워 두면 기존 동작 그대로다(backend 에 따라 openai_* 또는 llm_* 로 폴백).
    victim_base_url: str | None = None
    victim_api_key: str | None = None
    recon_base_url: str | None = None
    recon_api_key: str | None = None
    judge_base_url: str | None = None
    judge_api_key: str | None = None
    # 진단 대상 프리셋. "byok" 면 사용자가 자기 모델·키를 직접 지정한 것 → 근사치가 아니다.
    target_preset: str = "local_qwen3b"
    temperature: float = 0.0   # 진단 실행은 temperature=0 고정(재현성 규칙 1)
    seed: int = 42
    max_calls: int = 200       # 진단 1회 호출 상한(유료 API 비용 방어)
    request_timeout: float = 120.0  # LLM 호출 1건 타임아웃(초). 8GB 맥북 로컬은 넉넉히
    max_tokens: int = 512      # 응답 길이 상한(폭주·느린 생성 방지)
    reasoning_effort: str = "low"  # gpt-5 계열 추론 강도(minimal|low|medium|high). 낮을수록 저비용·빠름
    full_sweep: bool = False   # True 면 R1 에서 적응형 샘플링을 끄고 시드 전량을 던진다(측정 전용)
    db_path: str = "joker.db"
    env_profile: str = "unknown"  # 실행 환경 태그. 결과 행마다 저장돼 재현 맥락이 된다

    def __post_init__(self) -> None:
        if self.temperature < 0:
            raise ValueError("temperature 는 0 이상이어야 한다")
        if self.max_calls <= 0:
            raise ValueError("max_calls 는 1 이상이어야 한다")
        if not isinstance(self.profile, Profile):
            # 문자열로 들어와도 관대하게 강제 변환 (frozen 이라 object.__setattr__)
            object.__setattr__(self, "profile", Profile(self.profile))

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None, **overrides) -> "Settings":
        """환경변수 → Settings. overrides 는 명시적 주입용(테스트·CLI).

        overrides 를 replace 로 처리하므로 전역 변수를 덮어쓰는 일이 없다.
        """
        env = os.environ if environ is None else environ
        base = cls(
            profile=Profile(env.get("JOKER_PROFILE", Profile.MOCK.value)),
            llm_base_url=env.get("LLM_BASE_URL", cls.llm_base_url),
            llm_api_key=env.get("LLM_API_KEY", cls.llm_api_key),
            victim_model=env.get("VICTIM_MODEL", cls.victim_model),
            recon_model=env.get("RECON_MODEL", cls.recon_model),
            judge_model=env.get("JUDGE_MODEL", cls.judge_model),
            temperature=float(env.get("JOKER_TEMPERATURE", cls.temperature)),
            seed=int(env.get("JOKER_SEED", cls.seed)),
            victim_backend=env.get("VICTIM_BACKEND") or None,
            recon_backend=env.get("RECON_BACKEND") or None,
            judge_backend=env.get("JUDGE_BACKEND") or None,
            openai_base_url=env.get("OPENAI_BASE_URL", cls.openai_base_url),
            openai_api_key=env.get("OPENAI_API_KEY", cls.openai_api_key),
            victim_base_url=env.get("VICTIM_BASE_URL") or None,
            victim_api_key=env.get("VICTIM_API_KEY") or None,
            recon_base_url=env.get("RECON_BASE_URL") or None,
            recon_api_key=env.get("RECON_API_KEY") or None,
            judge_base_url=env.get("JUDGE_BASE_URL") or None,
            judge_api_key=env.get("JUDGE_API_KEY") or None,
            target_preset=env.get("TARGET_PRESET", cls.target_preset),
            max_calls=int(env.get("JOKER_MAX_CALLS", cls.max_calls)),
            request_timeout=float(env.get("JOKER_TIMEOUT", cls.request_timeout)),
            max_tokens=int(env.get("JOKER_MAX_TOKENS", cls.max_tokens)),
            reasoning_effort=env.get("JOKER_REASONING_EFFORT", cls.reasoning_effort),
            full_sweep=env.get("JOKER_FULL_SWEEP", "").lower() in ("1", "true", "yes"),
            db_path=env.get("JOKER_DB_PATH", cls.db_path),
            env_profile=env.get("JOKER_ENV_PROFILE", cls.env_profile),
        )
        return replace(base, **overrides) if overrides else base

    def with_(self, **overrides) -> "Settings":
        """일부 값만 바꾼 '새' 인스턴스를 반환. 원본은 불변."""
        return replace(self, **overrides)

    def backend_for(self, role: str) -> str:
        """역할(victim/recon/judge)이 쓸 백엔드. 개별 지정 없으면 profile 을 따른다."""
        per_role = {"victim": self.victim_backend, "recon": self.recon_backend, "judge": self.judge_backend}
        return (per_role.get(role) or self.profile.value)

    def endpoint_for(self, role: str) -> tuple[str, str]:
        """역할이 쓸 (base_url, api_key). 역할별 지정이 있으면 그것을, 없으면 backend 기본값을.

        이 폴백이 있어서 .env 를 안 바꾼 팀원 환경이 그대로 돈다(계약 v0.2 이전과 동일 동작).
        """
        per_role = {
            "victim": (self.victim_base_url, self.victim_api_key),
            "recon": (self.recon_base_url, self.recon_api_key),
            "judge": (self.judge_base_url, self.judge_api_key),
        }
        base, key = per_role.get(role, (None, None))
        if base:
            return base, (key or "")
        if self.backend_for(role) == "openai":
            return self.openai_base_url, self.openai_api_key
        return self.llm_base_url, self.llm_api_key

    def model_for(self, role: str) -> str:
        return {"victim": self.victim_model, "recon": self.recon_model,
                "judge": self.judge_model}.get(role, self.victim_model)

    @property
    def is_proxy_model(self) -> bool:
        """대리 모델로 쟀는가. byok = 사용자가 자기 base_url/model/key 를 준 경우 → False."""
        return self.target_preset != "byok"

    # 하위호환. ★ 새 코드는 fidelity 를 봐라 — 이 이름이 "근사냐 아니냐" 로 읽혀서 BYOK 를
    #   '실제 챗봇 진단' 으로 오독시켰다(2026-08-27). 곧 제거한다.
    is_approximation = is_proxy_model

    def target_info(self):
        """리포트에 실을 '무엇을 진단했는가'. contracts 의 target 블록.

        ★ fidelity 는 PROXY_MODEL / REAL_MODEL 두 값만 낸다.
          REAL_SERVICE(배포 서비스 직접 진단)는 SPEC §10 2순위이고 **구현이 없다.**
          코드가 낼 수 없는 값을 리포트가 주장하면 그건 거짓말이다.
        """
        from joker.models import SCOPE_NOTICE, Fidelity, TargetInfo  # 지연 import (config 는 최하위층)

        proxy = self.is_proxy_model
        return TargetInfo(
            model=self.victim_model,
            backend=self.backend_for("victim"),
            preset=self.target_preset,
            temperature=self.temperature,
            seed=self.seed,
            fidelity=Fidelity.PROXY_MODEL if proxy else Fidelity.REAL_MODEL,
            scope_notice=SCOPE_NOTICE,      # 항상 붙는다
            model_notice=(
                f"고객님 챗봇의 실제 모델이 아니라 대리 모델({self.victim_model})로 진단했습니다. "
                "실제 모델에서는 결과가 다를 수 있습니다." if proxy else None
            ),
        )

    def __repr__(self) -> str:  # 키를 절대 노출하지 않는다
        return (
            f"Settings(profile={self.profile.value}, base_url={self.llm_base_url!r}, "
            f"api_key={mask_secret(self.llm_api_key)}, victim={self.victim_model!r}, "
            f"temperature={self.temperature}, env_profile={self.env_profile!r})"
        )
