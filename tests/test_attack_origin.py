"""출처 표기(origin) — "직접 생산한 데이터" 주장의 근거를 지킨다.

왜 이 파일이 생겼나 (2026-08-26):
  ko_native/ 의 10개 시드에 `author: 류성환` 같은 팀원 이름이 붙어 있었는데,
  파일 헤더는 "예시 2개 채움" 이었다 — 팀원이 쓸 템플릿에 AI 가 미리 넣어둔 견본이었다.
  author 필드 하나만으로는 **AI 초안에 사람 이름이 붙어도 아무도 모른다.**

  SPEC §7: "발표에서 '직접 생산한 데이터'를 주장하려면 이게 남아야 한다."
  → author(담당·책임자)와 origin(실제 작성 주체)을 분리하고, audit 이 강제한다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from joker.corpus.audit import audit
from joker.corpus.loader import load_attacks
from joker.models import Attack, Goal, Origin, Technique

DATA = Path(__file__).parent.parent / "data" / "attacks"


def _atk(**kw) -> Attack:
    base = dict(id="ROLE-01", technique=Technique.ROLE, goal=Goal.INFO_LEAK,
                text="t", principle="p")
    return Attack(**{**base, **kw})


# ── 기본값은 '사람 작성이라고 주장하지 않는' 쪽 ────────────────
def test_origin_defaults_to_ai_draft():
    """미기재 시 AI 초안. 과장보다 과소가 안전하다."""
    assert _atk().origin is Origin.AI_DRAFT


def test_yaml_without_origin_loads_as_ai_draft(tmp_path):
    f = tmp_path / "x.yaml"
    f.write_text(
        "- id: ROLE-01\n  technique: ROLE\n  goal: INFO_LEAK\n"
        "  text: t\n  principle: p\n  author: 아무개\n",
        encoding="utf-8",
    )
    (loaded,) = load_attacks([f], run_audit=False)
    assert loaded.origin is Origin.AI_DRAFT, "author 만 있으면 사람이 썼다고 집계하면 안 된다"


# ── 규칙 6 ───────────────────────────────────────────────────
@pytest.mark.parametrize("origin", [Origin.POC_HUMAN, Origin.TEAM_MEMBER])
def test_human_origin_requires_author(origin):
    v = audit([_atk(origin=origin, author="", screening=True),
               _atk(id="ROLE-02", origin=origin, author="", screening=True),
               _atk(id="ROLE-03", origin=origin, author="", screening=True)])
    assert any("[규칙6]" in x and "author" in x for x in v)


def test_ai_draft_does_not_require_author():
    v = audit([_atk(origin=Origin.AI_DRAFT, author="", screening=True),
               _atk(id="ROLE-02", origin=Origin.AI_DRAFT, screening=True),
               _atk(id="ROLE-03", origin=Origin.AI_DRAFT, screening=True)])
    assert not any("[규칙6]" in x for x in v)


def test_invalid_origin_value_is_reported():
    v = audit([_atk(origin="made_up", author="누구", screening=True),
               _atk(id="ROLE-02", origin=Origin.AI_DRAFT, screening=True),
               _atk(id="ROLE-03", origin=Origin.AI_DRAFT, screening=True)])
    assert any("[규칙6]" in x and "허용값" in x for x in v)


# ── 실제 코퍼스 회귀 ──────────────────────────────────────────
def _corpus():
    return load_attacks([DATA / "core_25.yaml", DATA / "indirect_doc.yaml", DATA / "ko_native"],
                        run_audit=False)


def test_core_25_is_marked_as_poc_human():
    """8/14 PoC 원문 25개. PoC CSV 와 문자 일치가 확인된 유일한 '사람 작성' 근거다."""
    core = load_attacks([DATA / "core_25.yaml"], run_audit=False)
    assert len(core) == 25
    assert all(a.origin is Origin.POC_HUMAN for a in core)
    assert all(a.author.strip() for a in core)


def test_every_seed_declares_a_valid_origin():
    assert all(isinstance(a.origin, Origin) for a in _corpus())


def test_human_authored_count_never_silently_drops():
    """사람 작성 시드는 늘어날 수는 있어도 줄어들면 안 된다.

    ★ 정확히 25개로 고정하지 않는 이유: 팀 문구가 들어오면(origin: team_member) 매번 테스트가
      깨져서 금요일 작업이 막힌다. 여기서 막아야 할 회귀는 '늘어나는 것'이 아니라
      **누가 origin 을 ai_draft 로 되돌려 근거가 조용히 사라지는 것**이다.
      과대주장(author 없이 사람 출처)은 audit 규칙 6 이 따로 막는다.
    """
    atks = _corpus()
    human = [a for a in atks if a.origin is not Origin.AI_DRAFT]
    assert len(human) >= 25, (
        f"사람 작성 시드가 {len(human)}개로 줄었다(최소 25 = PoC core). "
        "누가 origin 을 ai_draft 로 되돌렸는지 확인할 것."
    )
    assert all(a.author.strip() for a in human), "사람 작성인데 author 가 빈 시드가 있다"
