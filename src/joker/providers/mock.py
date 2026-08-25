"""결정론적 mock provider. 네트워크 없음. 팀원·CI·발표 백업 경로.

role 로 세 노드를 흉내낸다(각 노드에 서로 다른 mock 인스턴스가 주입된다):
  - "recon"  : scenario(JSON payload)를 그대로 반환 → RECON 이 파싱
  - "victim" : system 에 방어 머리표가 있으면 거절, 없으면 secret 을 유출
  - "judge"  : scenario["judge"] 판정을 반환
  - "echo"   : scenario["reply"]/기본 거절문 (기본값, provider 계약 테스트용)

핵심: victim 은 '실제 취약점'을 재현하는 게 아니라, 파이프라인 오케스트레이션(스크리닝→집중→
replay→집계)을 결정론적으로 검증하기 위한 대역이다. 진짜 피해 모델은 로컬 LLM 이다.
"""

from __future__ import annotations

import json

from joker.providers.base import CallResult, Usage

_DEFAULT_REFUSAL = "요청하신 정보는 제공할 수 없습니다."
# 처방 머리표. nodes.patch.PATCH_HEADER 와 같은 값이어야 한다(레이어상 import 대신 상수 복제).
_DEFENSE_MARKER = "[보안 지침]"


class MockProvider:
    def __init__(self, scenario: dict | None = None, model: str = "mock", role: str = "echo") -> None:
        self.scenario = scenario or {}
        self.model = model
        self.role = role
        self.calls = 0

    def _dispatch(self, system: str, user: str) -> str:
        sc = self.scenario
        if self.role == "recon":
            payload = sc.get("payload", sc if "assets" in sc else {"assets": []})
            return json.dumps(payload, ensure_ascii=False)

        if self.role == "victim":
            marker = sc.get("defense_marker", _DEFENSE_MARKER)
            if marker and marker in system:
                return sc.get("refusal", _DEFAULT_REFUSAL)
            secret = sc.get("secret")
            if secret:
                return sc.get("leak_template", "네, 확인해 드릴게요. 값은 {s} 입니다.").replace("{s}", secret)
            return _DEFAULT_REFUSAL

        if self.role == "judge":
            return str(sc.get("judge", "block"))

        # echo
        if "reply" in sc:
            return str(sc["reply"])
        return str(sc.get("default", _DEFAULT_REFUSAL))

    def complete(self, *, system: str, user: str, temperature: float, seed: int) -> CallResult:
        self.calls += 1
        text = self._dispatch(system, user)
        usage = Usage(prompt_tokens=len(system) + len(user), completion_tokens=len(text))
        return CallResult(text=text, model=self.model, usage=usage, latency_ms=1)
