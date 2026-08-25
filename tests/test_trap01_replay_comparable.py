"""함정① 재진단이 1회차와 다른 공격 집합이면 Before/After 비교가 거짓말이 된다.

이전: R1=26건(스크리닝+집중), R2=18건(스크리닝만)으로 "34.6%→0%" 리포트 → 26건에 뚫린 걸 18건으로 잼.
방지: R2 는 R1 에서 실제로 던진 attack_id 집합을 '그대로' 재생하고, report.comparable 로 검증한다.

지금은 run_pipeline 이 스텁이라 이 테스트는 실패(빨간불)한다 — 5단계 구현이 초록으로 바꾼다.
"""

from __future__ import annotations

import pytest

from conftest import TARGET_WITH_SECRET
from joker.pipeline import run_pipeline


@pytest.mark.trap
def test_r2_replays_exact_r1_attack_ids(mock_deps_vulnerable):
    state = run_pipeline(TARGET_WITH_SECRET, mock_deps_vulnerable)

    r1 = {a.attack_id for a in state["attempts"] if a.round_no == 1}
    r2 = {a.attack_id for a in state["attempts"] if a.round_no == 2}

    assert r1, "R1 에 시도가 있어야 한다"
    assert r2 == r1, "재진단은 1회차에서 던진 attack_id 집합을 그대로 재생해야 한다"


@pytest.mark.trap
def test_report_marks_comparable_true(mock_deps_vulnerable):
    state = run_pipeline(TARGET_WITH_SECRET, mock_deps_vulnerable)
    assert state["report"].comparable is True
