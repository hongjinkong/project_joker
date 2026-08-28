"""SQLite 저장소(Repository). 진단 결과를 파일 DB 하나(joker.db)에 넣고 뺀다.

DB 개념 요약(팀 공유용):
- SQLite = 서버 없이 '파일 하나'가 데이터베이스. 별도 설치·계정 없음.
- 테이블 = 엑셀 시트. schema.sql 이 4개 시트(tb_diagnosis/tb_attempt/tb_asset/tb_applied_pattern)의 정의.
- Repository = SQL 을 이 파일에만 가두는 설계. 노드·파이프라인은 SQL 을 몰라도 save_run/load_run 만 쓴다.

★ 보안: 모든 쿼리는 '?' 파라미터 바인딩만 쓴다. 값을 문자열로 이어붙이면 SQL 인젝션이 난다.
  (우리 서비스가 보안 도구인데 우리 DB가 인젝션 나면 안 되니까.)
"""

from __future__ import annotations

import datetime
import hashlib
import json
import sqlite3
from pathlib import Path

from joker.state import RunState

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def _val(x):
    """Enum 이면 .value, 그 외엔 그대로. DB 엔 문자열/숫자/None 만 들어간다."""
    return x.value if hasattr(x, "value") else x


def _now() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


class Repository:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path)
        con.execute("PRAGMA foreign_keys = ON")  # 부모 삭제 시 자식(attempt)도 정리되게
        return con

    # ── 스키마 생성 ────────────────────────────────────────
    def init_schema(self) -> None:
        """schema.sql 을 통째로 실행해 테이블을 만든다(이미 있으면 IF NOT EXISTS 로 넘어감)."""
        sql = _SCHEMA_PATH.read_text(encoding="utf-8")
        con = self._connect()
        try:
            con.executescript(sql)  # 여러 CREATE 문을 한 번에
            self._migrate(con)
            con.commit()
        finally:
            con.close()

    # 이미 존재하는 DB 에는 CREATE TABLE IF NOT EXISTS 가 새 열을 안 만든다.
    # 팀원 4명 + 학원 PC 에 이미 joker.db 가 깔려 있으므로 ALTER 로 따라잡는다.
    # (열 추가만 한다. 삭제·타입 변경은 하지 않는다 — 기존 데이터를 잃지 않는 범위.)
    _ADDED_COLUMNS = {
        "tb_diagnosis": [
            ("target_preset", "TEXT"),
            ("is_approximation", "INTEGER"),   # 레거시(파생)
            ("fidelity", "TEXT"),              # 정본
        ],
    }

    def _migrate(self, con: sqlite3.Connection) -> None:
        for table, cols in self._ADDED_COLUMNS.items():
            have = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
            for name, decl in cols:
                if name not in have:
                    con.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

    # ── 저장 ──────────────────────────────────────────────
    def save_run(self, state: RunState) -> str:
        """진단 1회(state)를 tb_diagnosis 1행 + tb_attempt N행 + 자산/패턴으로 저장."""
        run_id = state.get("run_id") or f"run_{_now()}"
        report = state.get("report")
        # target_prompt_hash 는 NOT NULL. 없으면 지시문에서 계산해 채운다(방어적).
        target_prompt = state.get("target_prompt") or ""
        prompt_hash = state.get("target_prompt_hash") or (
            "sha256:" + hashlib.sha256(target_prompt.encode("utf-8")).hexdigest()[:16]
        )
        # ★ '무엇을 진단했는가' 는 파이프라인이 state["target"] 에 넣는다(계약 v0.2).
        #   예전에는 CLI·asr_rerun 이 실행 후에 state["backend"]/["victim_model"] 을 손으로 꽂았는데,
        #   그러면 **API 가 파이프라인을 직접 돌릴 때 NULL 로 저장된다.** target 을 1순위로 읽고
        #   없을 때만 옛 키로 폴백한다.
        tgt = state.get("target")
        backend = (tgt.backend if tgt else None) or state.get("backend")
        victim_model = (tgt.model if tgt else None) or state.get("victim_model")

        con = self._connect()
        try:
            with con:  # 'with' 블록 = 트랜잭션. 중간에 실패하면 전부 롤백(반쪽 저장 방지)
                con.execute(
                    """INSERT OR REPLACE INTO tb_diagnosis
                       (run_id, created_at, env_profile, backend, model_victim,
                        target_preset, fidelity, is_approximation,
                        target_prompt, target_prompt_hash, persona, org,
                        inconclusive, grade, comparable, asr_before, asr_after, asr_delta, patched_prompt)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        run_id, _now(),
                        state.get("env_profile"), backend, victim_model,
                        tgt.preset if tgt else None,
                        _val(tgt.fidelity) if tgt else None,
                        (1 if tgt.is_proxy_model else 0) if tgt else None,   # 레거시 파생
                        target_prompt, prompt_hash,
                        state.get("persona"), state.get("org"),
                        1 if (report and report.inconclusive) else 0,
                        _val(report.grade) if report else None,
                        (1 if report.comparable else 0) if report else None,
                        report.asr_before if report else None,
                        report.asr_after if report else None,
                        report.delta if report else None,
                        state.get("patched_prompt"),
                    ),
                )

                for at in state.get("attempts", []):
                    con.execute(
                        """INSERT INTO tb_attempt
                           (run_id, round_no, attack_id, technique, goal, rendered_text, response_raw,
                            verdict, verdict_by, leak_channel, was_gray, hit_assets,
                            victim_model, temperature, seed, latency_ms,
                            defense_level, verdict_gold, verdict_raw, blocked_by_filter)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            run_id, at.round_no, at.attack_id, _val(at.technique), _val(at.goal),
                            at.rendered_text, at.response_raw,
                            _val(at.verdict), _val(at.verdict_by), _val(at.leak_channel),
                            1 if at.was_gray else 0, json.dumps(at.hit_assets, ensure_ascii=False),
                            at.victim_model, at.temperature, at.seed, at.latency_ms,
                            None, None, None, None,  # 레거시 4열: 신규 진단은 NULL
                        ),
                    )

                for a in state.get("assets", []):
                    con.execute(
                        "INSERT INTO tb_asset (run_id, name, kind, confidence, source) VALUES (?,?,?,?,?)",
                        (run_id, a.name, _val(a.kind), a.confidence, a.source),
                    )

                if report:
                    for pid in report.applied_patterns:
                        con.execute(
                            "INSERT INTO tb_applied_pattern (run_id, pattern_id) VALUES (?,?)",
                            (run_id, pid),
                        )
        finally:
            con.close()
        return run_id

    # ── 조회 ──────────────────────────────────────────────
    def load_run(self, run_id: str) -> dict:
        """run_id 로 진단 1건을 통째로 되살린다(리포트 요약 + 시도 목록 + 자산). dict 반환."""
        con = self._connect()
        con.row_factory = sqlite3.Row  # 결과를 컬럼명으로 접근 가능하게(row["grade"])
        try:
            head = con.execute("SELECT * FROM tb_diagnosis WHERE run_id = ?", (run_id,)).fetchone()
            if head is None:
                raise KeyError(f"run_id 없음: {run_id}")
            attempts = [dict(r) for r in con.execute(
                "SELECT * FROM tb_attempt WHERE run_id = ? ORDER BY attempt_id", (run_id,))]
            assets = [dict(r) for r in con.execute(
                "SELECT * FROM tb_asset WHERE run_id = ?", (run_id,))]
        finally:
            con.close()

        d = dict(head)
        d["attempts"] = attempts
        d["assets"] = assets
        return d

    def list_runs(self) -> list[dict]:
        """이력 화면용 요약 목록(최신순)."""
        con = self._connect()
        con.row_factory = sqlite3.Row
        try:
            rows = con.execute(
                """SELECT run_id, created_at, grade, inconclusive, asr_before, asr_after, persona,
                          model_victim AS target_model, fidelity, is_approximation
                   FROM tb_diagnosis ORDER BY created_at DESC"""
                # ★ 목록에도 모델이 온다(계약 v0.2). 모델이 다르면 등급을 나란히 비교하면 안 되므로
                #   이력 화면이 행마다 모델명을 찍어야 한다.
            ).fetchall()
        finally:
            con.close()
        return [dict(r) for r in rows]
