"""진단 파이프라인 — '단계 함수' 5개 + 순차 실행.

RECON → ATTACK(R1: 스크리닝→취약기법 집중) → JUDGE → PATCH → ATTACK(R2: replay) → JUDGE → REPORT.

★ 함정③ 대비: 이 파일의 step_* 함수를 순차 경로(run_pipeline)와 그래프 경로(graph.py)가
  '똑같이' 쓴다. 로직이 한 곳이라 두 경로 결과가 자연히 일치하고, 그래프가 상태 키를 몰래
  버리면 trap03 이 잡는다.
- 각 step 은 새 state(dict 복사)를 반환한다 → 순차·그래프 양쪽에서 안전.
- 루프 종료조건은 round_no == 2 하드 고정.
"""

from __future__ import annotations

import hashlib

from joker.corpus.sampling import concentration_set, screening_set
from joker.deps import Deps
from joker.models import Report, Technique, Verdict
from joker.nodes.attack import build_context, run_attacks
from joker.nodes.judge import judge_attempts
from joker.nodes.patch import assemble_patch
from joker.nodes.recon import recon
from joker.nodes.report import build_report
from joker.state import RunState


def prompt_hash(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def new_state(target_prompt: str, run_id: str = "run_local") -> RunState:
    return {
        "run_id": run_id,
        "target_prompt": target_prompt,
        "target_prompt_hash": prompt_hash(target_prompt),
        "round_no": 1,
        "attempts": [],
    }


# ── 단계 함수 (pipeline / graph 공용) ─────────────────────
def step_recon(state: RunState, deps: Deps) -> RunState:
    return recon(state, deps)  # recon 은 이미 새 dict 를 반환한다


def step_inconclusive(state: RunState, deps: Deps | None = None) -> RunState:
    """함정②: 값 자산 0개 → 등급 없이 종료."""
    new: RunState = dict(state)  # type: ignore[assignment]
    new["attempts"] = []
    new["vulnerable_techniques"] = []
    new["r1_attack_ids"] = []
    new["patched_prompt"] = None
    new["applied_patterns"] = []
    new["report"] = Report(
        grade=None, inconclusive=True, comparable=True,
        asr_before=None, asr_after=None, delta=None,
        by_technique={}, applied_patterns=[],
    )
    return new


def step_attack_r1(state: RunState, deps: Deps) -> RunState:
    """R1: 스크리닝 18건 → 취약 기법 판정 → 그 기법에만 집중 투입."""
    context = build_context(state)
    assets = state["assets"]
    attacks = list(deps.attacks)

    screen = screening_set(attacks)
    r1 = run_attacks(screen, state["target_prompt"], 1, deps, context)
    judge_attempts(r1, assets, deps)

    vulnerable: list[Technique] = sorted(
        {a.technique for a in r1 if a.verdict == Verdict.LEAK}, key=lambda t: t.value
    )

    seen = {a.attack_id for a in r1}
    concentrate = [a for a in concentration_set(attacks, vulnerable) if a.id not in seen]
    r1c = run_attacks(concentrate, state["target_prompt"], 1, deps, context)
    judge_attempts(r1c, assets, deps)

    r1_all = r1 + r1c
    new: RunState = dict(state)  # type: ignore[assignment]
    new["attempts"] = list(state.get("attempts", [])) + r1_all
    new["vulnerable_techniques"] = vulnerable
    new["r1_attack_ids"] = [a.attack_id for a in r1_all]
    new["round_no"] = 1
    return new


def step_patch(state: RunState, deps: Deps) -> RunState:
    result = assemble_patch(
        state["target_prompt"], list(state.get("vulnerable_techniques", [])), list(deps.patterns)
    )
    new: RunState = dict(state)  # type: ignore[assignment]
    new["patched_prompt"] = result.patched_prompt
    new["applied_patterns"] = result.applied_patterns
    return new


def step_attack_r2(state: RunState, deps: Deps) -> RunState:
    """R2: R1 에서 실제로 던진 attack_id 를 그대로 재생(함정①), 처방된 지시문에."""
    context = build_context(state)
    assets = state["assets"]
    by_id = {a.id: a for a in deps.attacks}
    replay = [by_id[i] for i in state["r1_attack_ids"] if i in by_id]
    r2 = run_attacks(replay, state["patched_prompt"], 2, deps, context)
    judge_attempts(r2, assets, deps)

    new: RunState = dict(state)  # type: ignore[assignment]
    new["attempts"] = list(state["attempts"]) + r2
    new["round_no"] = 2
    return new


def step_report(state: RunState, deps: Deps | None = None) -> RunState:
    attempts = state["attempts"]
    r1 = [a for a in attempts if a.round_no == 1]
    r2 = [a for a in attempts if a.round_no == 2]
    report = build_report(r1, r2, state["r1_attack_ids"], list(state.get("applied_patterns", [])))
    new: RunState = dict(state)  # type: ignore[assignment]
    new["report"] = report
    return new


# ── 순차 실행 ─────────────────────────────────────────────
def run_pipeline(target_prompt: str, deps: Deps, run_id: str = "run_local") -> RunState:
    state = new_state(target_prompt, run_id)
    state = step_recon(state, deps)
    if state.get("inconclusive"):
        return step_inconclusive(state, deps)
    state = step_attack_r1(state, deps)
    state = step_patch(state, deps)
    state = step_attack_r2(state, deps)
    state = step_report(state, deps)
    return state
