"""경계/회귀: 실제 data/attacks/**.yaml 이 규칙을 통과하는지.

팀원이 시드를 추가하다 규칙을 깨면 이 테스트가 CI 에서 빨간불을 낸다.
경로는 cwd 와 무관하게 이 테스트 파일 기준으로 잡는다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from joker.corpus.audit import audit
from joker.corpus.loader import load_attacks
from joker.corpus.render import render_attack
from joker.corpus.sampling import screening_set

DATA = Path(__file__).parent.parent / "data" / "attacks"
PATHS = [DATA / "core_25.yaml", DATA / "indirect_doc.yaml", DATA / "ko_native"]

CONTEXT = {"persona": "한비", "org": "한빛물산", "asset": "관리자 임시 접근코드", "decoy": "BUSAN-9999"}


@pytest.fixture(scope="module")
def corpus():
    return load_attacks(PATHS, run_audit=False)


@pytest.mark.boundary
def test_real_corpus_passes_audit(corpus):
    violations = audit(corpus)
    assert violations == [], "실제 YAML 규칙 위반:\n" + "\n".join(violations)


@pytest.mark.boundary
def test_screening_is_exactly_18(corpus):
    scr = screening_set(corpus)
    assert len(scr) == 18, f"스크리닝은 6기법×3=18건이어야 한다 (현재 {len(scr)})"


@pytest.mark.boundary
def test_core_25_all_validated(corpus):
    # core 25개(PoC 실증)는 항상 validated 여야 한다. ko_native/DOC 은 실측 후 승격될 수 있음.
    core_ids = {f"{t}-0{n}" for t in ("ROLE", "AUTH", "INDIRECT", "OBFUSC", "FORMAT") for n in range(1, 6)}
    core = [a for a in corpus if a.id in core_ids]
    assert len(core) == 25
    assert all(a.validated for a in core), "core 25개는 전부 validated 여야 한다"


@pytest.mark.boundary
def test_ko_native_all_have_reason(corpus):
    for a in corpus:
        if a.ko_native:
            assert a.ko_native_reason, f"{a.id}: ko_native 인데 근거 없음"


@pytest.mark.boundary
def test_render_keeps_json_braces_from_real_seed(corpus):
    fmt01 = next(a for a in corpus if a.id == "FORMAT-01")
    rendered = render_attack(fmt01, CONTEXT)
    assert '"admin_temp_code"' in rendered  # JSON 중괄호 리터럴 보존
    assert "{asset}" not in rendered and "{persona}" not in rendered
