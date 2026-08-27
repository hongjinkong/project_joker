"""RunState — 파이프라인을 흐르는 상태의 '유일한 정의처'.

함정③이 정확히 여기서 났다: 노드가 쓰는 키(vulnerable_techniques)를 TypedDict 에
선언 안 했더니 LangGraph 가 그 키를 '조용히' 버렸다. 에러가 안 났다.
→ 노드가 읽거나 쓰는 모든 키는 반드시 여기에 있어야 한다. 새 키가 필요하면 노드가 아니라
  이 파일을 먼저 고친다. STATE_KEYS 로 두 실행 경로(pipeline/graph)의 키 누락을 테스트가 잡는다.
"""

from __future__ import annotations

from typing import TypedDict

from joker.models import Asset, Attempt, Report, TargetInfo, Technique


class RunState(TypedDict, total=False):
    # ── 입력 ──────────────────────────────────────────────
    run_id: str
    target_prompt: str            # 붙여넣은 지시문(신뢰 불가)
    target_prompt_hash: str       # 중복 진단 캐시 키
    settings_snapshot: dict       # 재현용 실행 맥락 스냅샷

    # ── RECON 출력 ────────────────────────────────────────
    assets: list[Asset]
    persona: str | None
    org: str | None
    forbidden_actions: list[str]
    priority: list[Technique]     # 어느 기법부터 볼지
    inconclusive: bool            # 값 자산 0개 → 진단 불가(함정②)
    recon_reason: str | None

    # ── ATTACK / JUDGE ────────────────────────────────────
    round_no: int                 # 현재 라운드(1 또는 2). 종료조건 round_no==2 하드 고정
    attempts: list[Attempt]       # R1·R2 시도가 누적된다
    vulnerable_techniques: list[Technique]  # ★ 함정③에서 누락됐던 바로 그 키
    r1_attack_ids: list[str]      # ★ 함정① — R2 는 이 목록을 그대로 재생한다

    # ── PATCH ─────────────────────────────────────────────
    patched_prompt: str | None
    applied_patterns: list[str]

    # ── REPORT ────────────────────────────────────────────
    report: Report | None
    target: TargetInfo | None     # '무엇을 진단했는가'(계약 v0.2). ★ 여기 선언 안 하면 함정③ 재발


# 두 실행 경로가 만든 state 의 키가 이 집합을 벗어나거나, 서로 다르면 테스트가 실패한다.
STATE_KEYS: frozenset[str] = frozenset(RunState.__annotations__.keys())
