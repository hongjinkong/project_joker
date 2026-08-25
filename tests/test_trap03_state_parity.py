"""함정③ LangGraph 가 State 스키마에 없는 키를 '조용히' 버렸다. 에러가 안 났다.

vulnerable_techniques 를 TypedDict 에 선언 안 했더니 순차 실행은 멀쩡한데 그래프에서만
처방·재진단이 통째로 스킵됐다. 두 실행 경로(pipeline/graph)의 결과 일치를 검증한다.

★ 중요: 이 테스트가 langgraph 미설치로 'skip' 되면 함정③ 재발 방지가 무의미하다(§5).
그래서 langgraph 를 주 의존성으로 두고, 미설치면 skip 이 아니라 '실패'로 처리한다.
"""

from __future__ import annotations

import importlib.util

import pytest

from conftest import TARGET_WITH_SECRET
from joker.state import STATE_KEYS

_LANGGRAPH_INSTALLED = importlib.util.find_spec("langgraph") is not None


@pytest.mark.trap
def test_langgraph_is_a_required_dependency():
    # skip 이 아니라 assert 로 실패시킨다 — 조용한 초록불을 만들지 않기 위해.
    assert _LANGGRAPH_INSTALLED, (
        "langgraph 는 주 의존성이다. 없으면 trap03 가 검증하는 두 경로 비교가 성립하지 않는다(§5)."
    )


@pytest.mark.trap
def test_pipeline_and_graph_produce_same_state(mock_deps_vulnerable):
    from joker.graph import run_graph
    from joker.pipeline import run_pipeline

    s_seq = run_pipeline(TARGET_WITH_SECRET, mock_deps_vulnerable)
    s_graph = run_graph(TARGET_WITH_SECRET, mock_deps_vulnerable)

    # 그래프가 키를 조용히 버리지 않았는가 — 함정③의 핵심
    assert s_graph.get("vulnerable_techniques") == s_seq.get("vulnerable_techniques")
    assert s_graph.get("patched_prompt") == s_seq.get("patched_prompt")
    assert set(s_graph.keys()) <= STATE_KEYS, "state 에 선언되지 않은 키가 있으면 안 된다"
    assert s_graph["report"].asr_after == s_seq["report"].asr_after
