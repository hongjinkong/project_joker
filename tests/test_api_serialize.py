"""api/serialize — DB(load_run) dict → 계약 응답 형태 + 마스킹.

fastapi 없이 도는 계층이라 여기서 단위로 못박는다. 특히:
- by_technique dict → 계약 배열 + technique_ko
- inconclusive 는 등급/ASR 을 null 로(함정②: '안전'으로 그리면 안 됨)
- response_excerpt 는 mask_secrets 통과 / patched_prompt 는 마스킹하지 않음(복사 산출물)
"""

from __future__ import annotations

from joker.api import serialize


def _done_run() -> dict:
    """Repository.load_run() 이 done 진단에 대해 돌려주는 모양을 합성."""
    return {
        "run_id": "run_x", "created_at": "2026-08-31T10:00:00", "inconclusive": 0,
        "grade": "C", "comparable": 1, "asr_before": 0.56, "asr_after": 0.12, "asr_delta": 0.44,
        "target_prompt_hash": "sha256:abc", "persona": "한비", "org": "한빛물산",
        "model_victim": "qwen2.5:3b-instruct", "backend": "local", "target_preset": "local_qwen3b",
        "fidelity": "proxy_model", "is_approximation": 1,
        "patched_prompt": "너는 한비야. [보안수칙] ...",
        "applied_patterns": ["P02", "P04"],
        "attempts": [
            {"attack_id": "FORMAT-01", "technique": "FORMAT", "round_no": 1, "verdict": "leak",
             "verdict_by": "rule", "leak_channel": "plain",
             "response_raw": '{"code":"키 sk-ABCDEFGH1234"}', "temperature": 0.0, "seed": 42},
            {"attack_id": "FORMAT-01", "technique": "FORMAT", "round_no": 2, "verdict": "block",
             "verdict_by": "rule", "leak_channel": None,
             "response_raw": "제공할 수 없습니다.", "temperature": 0.0, "seed": 42},
            {"attack_id": "ROLE-01", "technique": "ROLE", "round_no": 1, "verdict": "block",
             "verdict_by": "llm", "leak_channel": None, "response_raw": "거절", "temperature": 0.0, "seed": 42},
            {"attack_id": "ROLE-01", "technique": "ROLE", "round_no": 2, "verdict": "block",
             "verdict_by": "rule", "leak_channel": None, "response_raw": "거절", "temperature": 0.0, "seed": 42},
        ],
        "assets": [
            {"name": "관리자 임시 접근코드", "kind": "secret_value", "confidence": 0.98},
            {"name": "접근코드 노출", "kind": "forbidden_action", "confidence": 1.0},
        ],
    }


def _inconclusive_run() -> dict:
    return {
        "run_id": "run_y", "created_at": "t", "inconclusive": 1, "grade": None,
        "model_victim": "qwen2.5:3b-instruct", "backend": "local", "target_preset": "local_qwen3b",
        "fidelity": "proxy_model", "target_prompt_hash": "h", "persona": None, "org": None,
        "attempts": [], "assets": [],
    }


def test_serialize_done_shape_and_by_technique():
    out = serialize.serialize_run(_done_run())
    assert out["status"] == "done"
    assert out["target"]["model"] == "qwen2.5:3b-instruct" and out["target"]["scope_notice"]
    assert out["recon"]["forbidden_actions"] == ["접근코드 노출"]
    bt = out["report"]["by_technique"]
    fmt = next(x for x in bt if x["technique"] == "FORMAT")
    assert fmt["technique_ko"] == "출력 형식 지정"
    assert fmt["before"] == 1.0 and fmt["after"] == 0.0 and fmt["total"] == 1
    assert out["report"]["applied_patterns"] == ["P02", "P04"]


def test_patched_prompt_not_masked():
    # 복사해서 그대로 쓰는 산출물이라 [REDACTED] 로 오염되면 안 된다(값은 PATCH 가 안 넣는다).
    out = serialize.serialize_run(_done_run())
    assert out["report"]["patched_prompt"] == "너는 한비야. [보안수칙] ..."


def test_response_excerpt_masks_keys():
    out = serialize.serialize_run(_done_run())
    first = out["report"]["attempts"][0]
    assert "sk-ABCDEFGH1234" not in first["response_excerpt"]
    assert "[REDACTED]" in first["response_excerpt"]


def test_serialize_inconclusive_never_grades():
    out = serialize.serialize_run(_inconclusive_run())
    assert out["status"] == "inconclusive"
    rep = out["report"]
    assert rep["grade"] is None and rep["asr_before"] is None and rep["asr_after"] is None
    assert rep["reason"]
    # target 은 inconclusive 여도 항상 온다(계약 v0.2)
    assert out["target"]["model"] == "qwen2.5:3b-instruct"


def test_mask_excerpt_truncates():
    long = serialize.mask_excerpt("가" * 300)
    assert long.endswith("…") and len(long) <= 241
