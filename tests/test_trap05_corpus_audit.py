"""함정⑤ 한국어 고유(ko_native) 태그를 근거 없이 붙여 비율을 부풀렸다.

방지: audit() 이 PR 게이트 규칙 5개를 자동 검출한다(위반 목록 반환, 빈 리스트=통과).
  1. id 중복 없음 · 형식 TECHNIQUE-NN
  2. principle 비어 있지 않음
  3. ko_native=True ⇒ ko_native_reason 필수 ← 함정⑤
  4. technique/goal 허용값 안
  5. technique 당 screening=True 정확히 3개

지금은 audit() 스텁이라 실패(빨간불).
"""

from __future__ import annotations

import pytest

from joker.corpus.audit import audit
from joker.models import Attack, Goal, Technique


def _atk(id, tech, *, screening=False, ko=False, reason=None, principle="근거 한 줄"):
    return Attack(
        id=id, technique=tech, goal=Goal.INFO_LEAK,
        text="공격문", principle=principle, screening=screening,
        ko_native=ko, ko_native_reason=reason,
    )


@pytest.mark.trap
def test_ko_native_without_reason_is_flagged():
    bad = [_atk("OBFUSC-06", Technique.OBFUSC, ko=True, reason=None)]
    violations = audit(bad)
    assert any("ko_native_reason" in v for v in violations), violations


@pytest.mark.trap
def test_duplicate_id_is_flagged():
    dup = [_atk("ROLE-01", Technique.ROLE), _atk("ROLE-01", Technique.ROLE)]
    violations = audit(dup)
    assert any("ROLE-01" in v or "중복" in v for v in violations), violations


@pytest.mark.trap
def test_empty_principle_is_flagged():
    bad = [_atk("AUTH-01", Technique.AUTH, principle="")]
    violations = audit(bad)
    assert any("principle" in v for v in violations), violations


@pytest.mark.trap
def test_screening_must_be_exactly_three_per_technique():
    # ROLE 에 screening=True 가 2개뿐 → 위반
    attacks = [
        _atk("ROLE-01", Technique.ROLE, screening=True),
        _atk("ROLE-02", Technique.ROLE, screening=True),
        _atk("ROLE-03", Technique.ROLE, screening=False),
    ]
    violations = audit(attacks)
    assert any("screening" in v for v in violations), violations
