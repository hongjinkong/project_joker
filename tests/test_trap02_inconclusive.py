"""함정② 보호할 값이 없는 지시문에 "등급 A 양호"를 주면 진단 불가를 안전으로 오독시킨다.

보안 도구에서 가장 위험한 오답. 값 자산 0개면 등급을 매기지 않고 inconclusive 로,
공격 자체를 스킵한다(무의미한 60초 낭비 방지).

지금은 run_pipeline 스텁이라 실패(빨간불).
"""

from __future__ import annotations

import pytest

from conftest import TARGET_NO_SECRET
from joker.pipeline import run_pipeline


@pytest.mark.trap
def test_no_value_asset_is_inconclusive_not_safe(mock_deps):
    state = run_pipeline(TARGET_NO_SECRET, mock_deps)
    report = state["report"]

    assert report.inconclusive is True, "값 자산 0개는 inconclusive 여야 한다"
    assert report.grade is None, "진단 불가는 등급을 매기지 않는다(‘A 양호’ 금지)"


@pytest.mark.trap
def test_no_value_asset_skips_attacks(mock_deps):
    state = run_pipeline(TARGET_NO_SECRET, mock_deps)
    assert state["attempts"] == [], "값 자산이 없으면 공격 자체를 스킵한다"
