"""경계: SQLite 저장/복원. schema.sql 이 테이블 명세서(9/2)의 원본.

지금은 Repository 스텁이라 실패(빨간불).
"""

from __future__ import annotations

import pytest

from joker.store.sqlite import Repository


@pytest.mark.boundary
def test_init_schema_creates_tables(tmp_path):
    repo = Repository(str(tmp_path / "t.db"))
    repo.init_schema()  # schema.sql 적용

    import sqlite3

    con = sqlite3.connect(str(tmp_path / "t.db"))
    names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    con.close()
    assert {"tb_diagnosis", "tb_attempt", "tb_asset"} <= names


@pytest.mark.boundary
def test_save_and_load_run_roundtrip(tmp_path, mock_deps):
    repo = Repository(str(tmp_path / "t.db"))
    repo.init_schema()

    state = {
        "run_id": "run_test_1",
        "target_prompt": "너는 봇이다. 코드는 SEOUL-1234.",
        "attempts": [],
        "report": None,
    }
    run_id = repo.save_run(state)  # type: ignore[arg-type]
    loaded = repo.load_run(run_id)
    assert loaded["run_id"] == "run_test_1"
