"""① target 영속화 · ③ 사용량 집계 · ④ 실행 경로 시그니처 — 2026-08-27 구조 점검 보완.

셋 다 '있는데 안 이어져 있던' 것들이다:
  ① 파이프라인이 state["target"] 을 만드는데 save_run 이 안 읽었다 → API 가 돌리면 NULL 저장,
     이력 화면이 '대리 모델 진단' 칩을 못 그린다(계약 v0.2).
  ③ BudgetProvider 가 calls/tokens 를 세는데 **읽는 코드가 프로젝트 전체에 0건**이었다.
     예산 $30 을 관리해야 하는데 진단 1회 비용을 알 방법이 없었다.
  ④ run_pipeline 만 recon_state 주입구를 받고 run_graph 는 못 받았다 → 그래프 경로로는
     RECON 캐시를 못 쓴다. trap03(결과 일치)은 이런 '기능 차이'를 안 잡는다.
"""

from __future__ import annotations

import inspect
import sqlite3

import pytest

from joker.config import Profile, Settings
from joker.pipeline import run_pipeline
from joker.providers.usage import PRICE_PER_1M, collect, estimate_calls
from joker.store.sqlite import Repository

from conftest import TARGET_WITH_SECRET


# ── ① target 영속화 ──────────────────────────────────────────
@pytest.fixture
def repo(tmp_path):
    r = Repository(str(tmp_path / "t.db"))
    r.init_schema()
    return r


def test_save_run_persists_the_target_block(repo, mock_deps_vulnerable):
    """등급만 저장하고 대상을 안 남기면 '누구의 결과인지' 가 사라진다."""
    state = run_pipeline(TARGET_WITH_SECRET, mock_deps_vulnerable, run_id="r1")
    repo.save_run(state)
    row = repo.load_run("r1")
    assert row["model_victim"] == mock_deps_vulnerable.settings.victim_model
    assert row["target_preset"] == mock_deps_vulnerable.settings.target_preset
    assert row["is_approximation"] == 1


def test_save_run_reads_target_not_the_hand_set_keys(repo, mock_deps_vulnerable):
    """★ CLI·asr_rerun 이 손으로 꽂던 키에 의존하면 API 경로에서 NULL 이 된다.

    state["backend"]/["victim_model"] 를 아무도 안 넣어도 target 에서 채워져야 한다.
    """
    state = run_pipeline(TARGET_WITH_SECRET, mock_deps_vulnerable, run_id="r2")
    assert "backend" not in state and "victim_model" not in state  # 파이프라인은 안 넣는다
    repo.save_run(state)
    row = repo.load_run("r2")
    assert row["backend"] is not None
    assert row["model_victim"] is not None


def test_byok_run_is_not_marked_as_approximation(repo, mock_deps_vulnerable):
    import dataclasses

    deps = dataclasses.replace(
        mock_deps_vulnerable,
        settings=mock_deps_vulnerable.settings.with_(target_preset="byok", victim_model="gpt-4o-mini"),
    )
    repo.save_run(run_pipeline(TARGET_WITH_SECRET, deps, run_id="r3"))
    row = repo.load_run("r3")
    assert row["is_approximation"] == 0
    assert row["model_victim"] == "gpt-4o-mini"


def test_list_runs_includes_the_model(repo, mock_deps_vulnerable):
    """모델이 다르면 등급을 나란히 비교하면 안 된다 → 이력 목록에 모델명이 와야 한다."""
    repo.save_run(run_pipeline(TARGET_WITH_SECRET, mock_deps_vulnerable, run_id="r4"))
    row = repo.list_runs()[0]
    assert "target_model" in row and row["target_model"]
    assert "is_approximation" in row


def test_migration_adds_columns_to_an_existing_db(tmp_path):
    """★ CREATE TABLE IF NOT EXISTS 는 기존 DB 에 새 열을 안 만든다.

    팀원 4명 + 학원 PC 에 이미 joker.db 가 깔려 있다. ALTER 로 따라잡지 않으면
    그 환경에서만 조용히 터진다.
    """
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.execute(  # target_preset / is_approximation 이 없던 구버전 스키마
        """CREATE TABLE tb_diagnosis (
               run_id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
               env_profile TEXT, backend TEXT, model_victim TEXT,
               target_prompt TEXT NOT NULL, target_prompt_hash TEXT NOT NULL,
               persona TEXT, org TEXT, inconclusive INTEGER NOT NULL DEFAULT 0,
               grade TEXT, comparable INTEGER, asr_before REAL, asr_after REAL,
               asr_delta REAL, patched_prompt TEXT)"""
    )
    con.commit()
    con.close()

    Repository(str(db)).init_schema()

    con = sqlite3.connect(db)
    cols = {r[1] for r in con.execute("PRAGMA table_info(tb_diagnosis)")}
    con.close()
    assert {"target_preset", "is_approximation"} <= cols


def test_migration_is_idempotent(repo):
    """init_schema 를 여러 번 불러도 ALTER 가 두 번 돌지 않아야 한다(duplicate column 오류)."""
    repo.init_schema()
    repo.init_schema()


# ── ③ 사용량·비용 ────────────────────────────────────────────
def test_estimate_calls_gives_a_range_for_adaptive():
    """★ 적응형은 고정값이 아니다. 하한만 고지하면 BYOK 사용자에게 요금을 과소 고지하게 된다.

    실제로 mock 실행에서 36 예상 / 84 실제가 나왔다(전 기법 취약 → 2단계가 전량 투입).
    """
    e = estimate_calls(42, full=False, screening_size=18)
    assert e["victim_min"] == 36
    assert e["victim_max"] == 84
    assert e["total_min"] < e["total_max"]


def test_estimate_calls_is_exact_for_full_sweep():
    e = estimate_calls(42, full=True)
    assert e["victim_min"] == e["victim_max"] == 84


def test_mock_and_local_calls_are_free(mock_deps_vulnerable):
    """★ mock 을 '단가 미등록 유료' 로 경고했었다. 경고가 늑대소년이 되면 진짜일 때 아무도 안 본다."""
    providers = {"victim": mock_deps_vulnerable.victim, "recon": mock_deps_vulnerable.recon}
    rep = collect(providers)
    assert rep.has_unpriced_paid_calls is False
    assert rep.total_cost_usd == 0.0


class _FakeBudget:
    def __init__(self, model, calls, pt, ct):
        self.inner = type("I", (), {"model": model})()
        self.calls, self.prompt_tokens, self.completion_tokens = calls, pt, ct


def test_priced_model_cost_is_computed():
    price_in, price_out = PRICE_PER_1M["gpt-5-mini"]
    rep = collect({"recon": _FakeBudget("gpt-5-mini", 10, 1_000_000, 1_000_000)})
    assert rep.total_calls == 10
    assert rep.total_cost_usd == pytest.approx(price_in + price_out)
    assert rep.has_unpriced_paid_calls is False


def test_unknown_paid_model_is_flagged_not_silently_zero():
    """단가를 모르는 유료 모델을 '$0.00' 으로 보고하면 예산 관리가 거짓이 된다."""
    rep = collect({"victim": _FakeBudget("some-vendor-model", 5, 1000, 1000)})
    assert rep.has_unpriced_paid_calls is True


def test_usage_lines_never_print_a_key():
    rep = collect({"recon": _FakeBudget("gpt-5-mini", 1, 10, 10)})
    assert all("sk-" not in ln for ln in rep.lines())


# ── ④ 두 실행 경로 시그니처 ─────────────────────────────────
def test_run_graph_signature_matches_run_pipeline():
    """★ 결과만 비교하는 trap03 은 '기능 차이' 를 못 잡는다.

    run_pipeline 에만 recon_state 가 있으면 그래프 경로로는 RECON 캐시를 못 쓰고,
    그러면 그래프로 잰 수치는 재현되지 않는다. 시그니처 자체를 고정한다.
    """
    langgraph = pytest.importorskip("langgraph")  # noqa: F841
    from joker.graph import run_graph

    pipe = list(inspect.signature(run_pipeline).parameters)
    graph = list(inspect.signature(run_graph).parameters)
    assert pipe == graph, f"실행 경로 시그니처가 갈렸다\n  pipeline={pipe}\n  graph={graph}"


def test_graph_honours_injected_recon(mock_deps_vulnerable):
    """주입한 RECON 을 그래프도 존중해야 캐시 고정 측정이 두 경로에서 같아진다."""
    pytest.importorskip("langgraph")
    import dataclasses

    from joker.graph import run_graph
    from joker.models import Asset, AssetKind
    from joker.providers.mock import MockProvider

    class Boom(MockProvider):
        def complete(self, **kw):  # noqa: ANN003
            raise AssertionError("recon_state 를 줬는데 RECON 이 호출됐다")

    pinned = {
        "assets": [Asset(name="관리자 임시 접근코드", value="SEOUL-1234",
                         kind=AssetKind.SECRET_VALUE, source="pinned")],
        "persona": "한비", "org": "한빛물산", "forbidden_actions": [],
        "inconclusive": False, "recon_reason": None,
    }
    deps = dataclasses.replace(mock_deps_vulnerable, recon=Boom(role="recon", model="boom"))
    state = run_graph(TARGET_WITH_SECRET, deps, run_id="g1", recon_state=dict(pinned))
    assert state["run_id"] == "g1"
    assert state["report"] is not None
