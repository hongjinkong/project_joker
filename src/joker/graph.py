"""LangGraph 배선. 노드 로직은 pipeline.step_* 와 '완전히 동일'한 함수를 쓴다.

왜 로직을 여기서 다시 안 짜나:
- 함정③은 "그래프가 상태 키를 몰래 버려서" 났다. 그래프가 순차경로와 '같은 함수'를 쓰면
  로직 차이로 인한 오류는 없고, 남는 위험은 오직 'LangGraph 의 상태 병합에서 키가 사라지는가'
  뿐이다. trap03 이 정확히 그걸 검증한다(두 경로 결과 일치).

langgraph 는 주 의존성이라 최상단에서 import 한다. 미설치면 여기서 ImportError → trap03 은
skip 이 아니라 실패로 처리된다(§5).
"""

from __future__ import annotations

import langgraph  # noqa: F401  (주 의존성 — 없으면 ImportError)
from langgraph.graph import END, StateGraph

from joker.deps import Deps
from joker.pipeline import (
    new_state,
    step_attack_r1,
    step_attack_r2,
    step_inconclusive,
    step_patch,
    step_recon,
    step_report,
)
from joker.state import RunState


def _route_after_recon(state: RunState) -> str:
    # 함정②: 값 자산 0개면 처방·재진단을 건너뛰고 종료 노드로.
    return "inconclusive" if state.get("inconclusive") else "attack_r1"


def build_graph(deps: Deps):
    g = StateGraph(RunState)
    # deps 는 노드 함수에 클로저로 주입(LangGraph 노드는 state 만 받으므로)
    g.add_node("recon", lambda s: step_recon(s, deps))
    g.add_node("attack_r1", lambda s: step_attack_r1(s, deps))
    g.add_node("patch", lambda s: step_patch(s, deps))
    g.add_node("attack_r2", lambda s: step_attack_r2(s, deps))
    g.add_node("report", lambda s: step_report(s, deps))
    g.add_node("inconclusive", lambda s: step_inconclusive(s, deps))

    g.set_entry_point("recon")
    g.add_conditional_edges(
        "recon", _route_after_recon,
        {"inconclusive": "inconclusive", "attack_r1": "attack_r1"},
    )
    g.add_edge("attack_r1", "patch")
    g.add_edge("patch", "attack_r2")
    g.add_edge("attack_r2", "report")
    g.add_edge("report", END)
    g.add_edge("inconclusive", END)
    return g.compile()


def run_graph(target_prompt: str, deps: Deps) -> RunState:
    app = build_graph(deps)
    result = app.invoke(new_state(target_prompt, run_id="run_graph"))
    return dict(result)  # RunState dict 로 반환
