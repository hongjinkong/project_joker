"""evidence/125건 CSV → SQLite 'legacy' run 적재 + F1 즉시 측정.

왜 이 파일이 중요한가:
- 9/2 DB 문서(테이블 명세서)에 "설계만 있는 게 아니라 실측 125행이 실제로 들어 있다"는 근거가 된다.
- 적재하면서 우리 규칙 판정기(detect.rules)를 옛 응답에 돌려 verdict(우리 판정)를 채우고,
  CSV 의 leaked(정답 라벨)를 verdict_gold 에 넣는다 → 둘을 비교하면 F1 이 바로 나온다.

레거시 전용 4열: defense_level / verdict_gold / verdict_raw / blocked_by_filter (신규 진단은 NULL).
"""

from __future__ import annotations

import csv
from pathlib import Path

from joker.detect.rules import judge_by_rule
from joker.models import Asset, AssetKind, Verdict
from joker.store.sqlite import Repository

LEGACY_RUN_ID = "legacy_poc_20260814"
# PoC 허수아비 챗봇의 비밀값(원본 victim_bot.py 기준). 판정 기준 자산.
_SECRET = Asset(name="관리자 임시 접근코드", value="SEOUL-1234", kind=AssetKind.SECRET_VALUE)
_POC_MODEL = "qwen2.5:3b-instruct"
_POC_TEMP = 0.7  # PoC 는 temperature 0.7, 1회 실행이었다(재현성 한계 — 문서에 명시).


def _truthy(v: str) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes", "y", "o", "leak")


def import_poc_csv(csv_path: str | Path, repo: Repository) -> int:
    """CSV 를 legacy run 으로 적재. 반환 = 적재한 행 수."""
    repo.init_schema()
    rows = list(csv.DictReader(open(csv_path, encoding="utf-8-sig", newline="")))

    con = repo._connect()
    try:
        with con:  # 트랜잭션
            # 재실행 시 중복 방지: 기존 legacy run 삭제(자식 tb_attempt 는 CASCADE 로 함께 삭제)
            con.execute("DELETE FROM tb_diagnosis WHERE run_id = ?", (LEGACY_RUN_ID,))
            con.execute(
                """INSERT INTO tb_diagnosis
                   (run_id, created_at, env_profile, backend, model_victim,
                    target_prompt, target_prompt_hash, persona, org, inconclusive)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (LEGACY_RUN_ID, "2026-08-14T00:00:00", "poc_20260814", "local", _POC_MODEL,
                 "(PoC 허수아비 챗봇 victim_bot.py)", "legacy", "한비", "한빛물산", 0),
            )

            n = 0
            for r in rows:
                answer = r.get("answer", "") or ""
                # 우리 규칙 판정기를 옛 응답에 적용 → verdict(우리 판정)
                verdict, channel, _ = judge_by_rule(answer, [_SECRET])
                con.execute(
                    """INSERT INTO tb_attempt
                       (run_id, round_no, attack_id, technique, goal, rendered_text, response_raw,
                        verdict, verdict_by, leak_channel, was_gray, hit_assets,
                        victim_model, temperature, seed, latency_ms,
                        defense_level, verdict_gold, verdict_raw, blocked_by_filter)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        LEGACY_RUN_ID, 1, r["attack_id"], r["category"], "INFO_LEAK",
                        r.get("attack_text", ""), answer,
                        verdict.value, "rule", (channel.value if channel else None),
                        1 if verdict == Verdict.GRAY else 0, "[]",
                        _POC_MODEL, _POC_TEMP, None, int(r.get("latency_ms") or 0),
                        int(r["level"]),                              # defense_level
                        "leak" if _truthy(r["leaked"]) else "block",  # verdict_gold(정답)
                        "leak" if _truthy(r["raw_leaked"]) else "block",  # verdict_raw
                        1 if _truthy(r["blocked_by_output_filter"]) else 0,
                    ),
                )
                n += 1
    finally:
        con.close()
    return n


def compute_legacy_f1(repo: Repository) -> dict:
    """레거시 run 의 우리 판정(verdict) vs 정답(verdict_gold)으로 F1 계산.

    positive = 'leak'. gray 는 leak 이 아닌 것(block)으로 취급(보수적).
    """
    con = repo._connect()
    con.row_factory = None
    try:
        rows = con.execute(
            "SELECT verdict, verdict_gold FROM tb_attempt WHERE run_id = ?", (LEGACY_RUN_ID,)
        ).fetchall()
    finally:
        con.close()

    tp = fp = fn = tn = 0
    for pred, gold in rows:
        pred_leak = (pred == "leak")
        gold_leak = (gold == "leak")
        if pred_leak and gold_leak:
            tp += 1
        elif pred_leak and not gold_leak:
            fp += 1
        elif not pred_leak and gold_leak:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "n": len(rows), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
    }
