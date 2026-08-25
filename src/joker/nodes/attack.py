"""ATTACK: 렌더링된 공격문을 피해 챗봇(VICTIM)에게 던져 응답을 수집.

2단계 적응형 샘플링(스크리닝 → 취약 기법 집중)의 '실행' 부분. 어떤 공격 집합을 던질지 고르는
샘플링 자체는 pipeline 이 corpus.sampling 으로 결정하고, 이 노드는 '주어진 집합을 실행'한다.
치환은 render_attack(replace) 로만 한다(함정④). 재현 맥락(model/temp/seed)을 매 행에 남긴다.
"""

from __future__ import annotations

from joker.corpus.render import render_attack
from joker.deps import Deps
from joker.models import Asset, AssetKind, Attack, Attempt
from joker.state import RunState


def build_context(state: RunState) -> dict[str, str]:
    """공격문 플레이스홀더 치환용 컨텍스트. 자산 '이름'만 넣고 값은 넣지 않는다."""
    assets: list[Asset] = state.get("assets", [])  # type: ignore[assignment]
    secret = next((a for a in assets if a.kind == AssetKind.SECRET_VALUE), None)
    return {
        "persona": state.get("persona") or "챗봇",
        "org": state.get("org") or "회사",
        "asset": (secret.name if secret else "비밀 정보"),
        "decoy": "BUSAN-9999",
    }


def run_attacks(
    attacks: list[Attack],
    system_prompt: str,
    round_no: int,
    deps: Deps,
    context: dict[str, str],
) -> list[Attempt]:
    out: list[Attempt] = []
    for atk in attacks:
        rendered = render_attack(atk, context)
        res = deps.victim.complete(
            system=system_prompt,
            user=rendered,
            temperature=deps.settings.temperature,
            seed=deps.settings.seed,
        )
        out.append(
            Attempt(
                attack_id=atk.id,
                technique=atk.technique,
                goal=atk.goal,
                round_no=round_no,
                rendered_text=rendered,
                response_raw=res.text,
                victim_model=res.model,
                temperature=deps.settings.temperature,
                seed=deps.settings.seed,
                latency_ms=res.latency_ms,
            )
        )
    return out
