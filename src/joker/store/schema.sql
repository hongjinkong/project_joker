-- 「뚫어보기」 SQLite 스키마 — 9/2 제출 '테이블 명세서'의 원본.
-- 이 파일 하나가 명세서의 진실이다. 문서(docs/db_tables.md)는 여기서 생성한다.
--
-- 설계 핵심:
--  1) round_no 하나로 Before(1)/After(2)를 한 테이블에 담는다 (테이블 분리 불필요).
--  2) 레거시 전용 4열(defense_level/verdict_gold/verdict_raw/blocked_by_filter)은
--     125건 PoC 실측을 담기 위한 것. 신규 진단 행에서는 항상 NULL.
--  3) victim_model/temperature/seed 3개가 없으면 결과를 재현할 수 없다 → 필수 저장.

PRAGMA foreign_keys = ON;

-- ────────────────────────────────────────────────────────────
-- 진단 1회 = 시스템 프롬프트 1건에 대한 진단→처방→재진단 전체
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tb_diagnosis (
    run_id              TEXT PRIMARY KEY,
    created_at          TEXT NOT NULL,               -- ISO8601
    -- 실행 환경 (재현 맥락)
    env_profile         TEXT,                        -- 예: macbook_m2_8gb
    backend             TEXT,                        -- mock | local | openai | full_local
    model_victim        TEXT,
    -- 대상 지시문
    target_prompt       TEXT NOT NULL,
    target_prompt_hash  TEXT NOT NULL,               -- 중복 진단 캐시 키
    -- RECON 요약
    persona             TEXT,
    org                 TEXT,
    -- 결과 요약
    inconclusive        INTEGER NOT NULL DEFAULT 0,  -- 1이면 값 자산 0개(함정②) → grade NULL
    grade               TEXT,                        -- A~F, 진단 불가면 NULL
    comparable          INTEGER,                     -- R1/R2 attack_id 집합 동일(함정①)
    asr_before          REAL,
    asr_after           REAL,
    asr_delta           REAL,
    patched_prompt      TEXT
);

CREATE INDEX IF NOT EXISTS ix_diagnosis_hash ON tb_diagnosis(target_prompt_hash);

-- ────────────────────────────────────────────────────────────
-- 공격 1회 시도 ★ 핵심 테이블
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tb_attempt (
    attempt_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              TEXT NOT NULL REFERENCES tb_diagnosis(run_id) ON DELETE CASCADE,
    round_no            INTEGER NOT NULL,            -- 1=처방전 2=처방후
    attack_id           TEXT NOT NULL,
    technique           TEXT NOT NULL,               -- ROLE|AUTH|INDIRECT|OBFUSC|FORMAT|INDIRECT_DOC
    goal                TEXT NOT NULL,               -- INFO_LEAK|POLICY_BREAK|PERSONA_BREAK
    rendered_text       TEXT NOT NULL,
    response_raw        TEXT,
    -- 판정
    verdict             TEXT,                        -- leak|block  (우리 판정기 출력)
    verdict_by          TEXT,                        -- rule|llm    (규칙이 몇 % 처리했는가의 근거)
    leak_channel        TEXT,                        -- plain|reversed|base64|semantic
    was_gray            INTEGER NOT NULL DEFAULT 0,
    hit_assets          TEXT,                        -- JSON 배열
    -- 재현 맥락 (없으면 재현 불가)
    victim_model        TEXT,
    temperature         REAL,
    seed                INTEGER,
    latency_ms          INTEGER,
    -- ── 레거시 실증 데이터 전용 (신규 진단 시 NULL) ──
    defense_level       INTEGER,                     -- PoC 허수아비 챗봇 방어 레벨 1~5
    verdict_gold        TEXT,                        -- 정답 라벨(사용자 전달 답변 기준) → F1 정답지
    verdict_raw         TEXT,                        -- 모델 원본 기준(출력필터 전)
    blocked_by_filter   INTEGER                      -- L5 출력필터가 잘랐는가
);

CREATE INDEX IF NOT EXISTS ix_attempt_run   ON tb_attempt(run_id);
CREATE INDEX IF NOT EXISTS ix_attempt_round ON tb_attempt(run_id, round_no);
CREATE INDEX IF NOT EXISTS ix_attempt_tech  ON tb_attempt(technique);

-- ────────────────────────────────────────────────────────────
-- RECON 이 뽑은 보호 자산 (진단별)
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tb_asset (
    asset_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              TEXT NOT NULL REFERENCES tb_diagnosis(run_id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    -- 주의: value(비밀값 원문)는 기본 저장하지 않는다(NFR-DV-002). 이름·종류만 남긴다.
    kind                TEXT NOT NULL,               -- secret_value|forbidden_action|persona|policy
    confidence          REAL DEFAULT 1.0,
    source              TEXT
);

CREATE INDEX IF NOT EXISTS ix_asset_run ON tb_asset(run_id);

-- ────────────────────────────────────────────────────────────
-- 처방에 적용된 방어 패턴 (진단별)
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tb_applied_pattern (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              TEXT NOT NULL REFERENCES tb_diagnosis(run_id) ON DELETE CASCADE,
    pattern_id          TEXT NOT NULL                -- P01..P08
);

CREATE INDEX IF NOT EXISTS ix_applied_run ON tb_applied_pattern(run_id);
