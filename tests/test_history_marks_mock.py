"""이력 목록은 mock(가짜 응답) 런을 구분할 수 있어야 한다.

왜 테스트하나: mock 런은 victim 이 가짜라 100% → 0%, 등급 A 로 나온다 — **이력 목록에서 제일
좋아 보이는 행이 된다.** 구분 표시가 없으면 발표 중에 그 행을 근거로 읽게 된다. 보안 도구가
가짜 수치를 최고 등급으로 보여주는 것이 이 프로젝트에서 가장 위험한 실패다.
"""

from __future__ import annotations

import sqlite3

import pytest

from joker.store.sqlite import Repository


@pytest.mark.boundary
def test_list_runs_exposes_backend(tmp_path):
    db = tmp_path / "t.db"
    repo = Repository(str(db))
    repo.init_schema()

    con = sqlite3.connect(str(db))
    con.executemany(
        "INSERT INTO tb_diagnosis (run_id, created_at, backend, model_victim, grade, "
        "inconclusive, asr_before, asr_after, target_prompt, target_prompt_hash) "
        "VALUES (?,?,?,?,?,0,?,?,?,?)",
        [("run_mock", "2026-09-04T10:22:24", "mock", "gemma3:4b", "A", 1.0, 0.0, "p", "h1"),
         ("run_real", "2026-09-04T11:05:04", "local", "qwen2.5:3b-instruct", "B", 0.596, 0.105, "p", "h2")],
    )
    con.commit()
    con.close()

    runs = {r["run_id"]: r for r in repo.list_runs()}
    assert runs["run_mock"]["backend"] == "mock", "이력에서 mock 을 구분할 수 없으면 가짜 수치를 인용하게 된다"
    assert runs["run_real"]["backend"] == "local"
    # 가짜가 더 좋아 보이는 상황 자체를 못 박아 둔다 — 그래서 표시가 필요하다
    assert runs["run_mock"]["grade"] == "A" and runs["run_real"]["grade"] == "B"


def test_ui_marks_mock_rows():
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "ui" / "streamlit_app.py").read_text(encoding="utf-8")
    assert '"backend"' in src and "mock(가짜)" in src, "이력 화면이 mock 을 표시해야 한다"
