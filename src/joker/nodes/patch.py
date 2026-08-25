"""PATCH: 취약 기법에 맞는 방어 문구를 카탈로그에서 골라 '조립'만 한다.

함정⑥: 처방을 LLM 이 자유 생성하면 매번 달라져 Before/After 비교가 무의미해진다.
그래서 여기서는 패턴을 고르고(집합 교집합) id 로 정렬해 이어붙이기만 한다 → 같은 입력이면 완전 동일.
'[보안 지침]' 머리표는 재진단 때 방어가 적용됐음을 시스템이 인식하는 표식이기도 하다.
"""

from __future__ import annotations

from joker.deps import Deps
from joker.models import DefensePattern, PatchResult, Technique
from joker.state import RunState

PATCH_HEADER = "[보안 지침]"


def assemble_patch(
    target_prompt: str,
    vulnerable_techniques: list[Technique],
    patterns: list[DefensePattern],
) -> PatchResult:
    vt = set(vulnerable_techniques)
    selected = sorted(
        (p for p in patterns if vt & set(p.targets)),
        key=lambda p: p.id,
    )
    lines = "\n".join(f"- {p.template}" for p in selected)
    patched = f"{target_prompt.rstrip()}\n\n{PATCH_HEADER}\n{lines}".rstrip()
    return PatchResult(patched_prompt=patched, applied_patterns=[p.id for p in selected])


def patch(state: RunState, deps: Deps) -> RunState:
    result = assemble_patch(
        state["target_prompt"],
        list(state.get("vulnerable_techniques", [])),
        list(deps.patterns),
    )
    new: RunState = dict(state)  # type: ignore[assignment]
    new["patched_prompt"] = result.patched_prompt
    new["applied_patterns"] = result.applied_patterns
    return new
