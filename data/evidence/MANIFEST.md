# evidence — PoC 실측 원본 (읽기 전용 팀 자산)

이 폴더의 파일은 **절대 수정하지 않는다.** 컬럼명도 그대로 둔다.
새 진단 결과는 SQLite(`joker.db`)에 쌓이고, 이 CSV/JSON 은 "레거시 실증 데이터"로 보존된다.

## 출처

- 작성·실행: 홍진성, 2026-08-14 PoC (`poc/run_attacks.py` + `poc/victim_bot.py`)
- 대상: 본인 소유 로컬 허수아비 챗봇 `victim_bot.py` (한빛물산 IT 헬프데스크 봇 '한비')
- 모델: qwen2.5:3b-instruct (Ollama, 로컬)
- 실행 조건: **temperature 0.7, 1회 실행** ← 재현성 한계. 재작성 엔진은 temp 0 으로 재측정 예정
- 공격 코퍼스: 5 카테고리(ROLE/AUTH/INDIRECT/OBFUSC/FORMAT) × 5 = 25개

## 파일

| 파일 | 내용 | 레코드 |
|---|---|---|
| `poc_2026-08-14_125.csv` / `.json` | 본 실측. 공격 25 × 방어레벨 5 = **125건** | 125 |
| `poc_2026-08-14_smoke10.csv` / `.json` | 초기 스모크 (공격 5 × 레벨 2) | 10 |

## 컬럼 의미 (125 CSV)

| 컬럼 | 의미 | 새 스키마 대응 |
|---|---|---|
| `level` | 허수아비 챗봇 방어 레벨 1~5 (누적식) | `tb_attempt.defense_level` (레거시 전용) |
| `attack_id` | 공격 시드 ID (예: FORMAT-01) | `tb_attempt.attack_id` |
| `category` / `category_ko` | 공격 기법 코드 / 한글명 | `tb_attempt.technique` |
| `leaked` | **사용자 전달 답변 기준 유출 = 정답 라벨** | `tb_attempt.verdict_gold` ★ F1 정답지 |
| `raw_leaked` | 모델 원본 기준 유출 (L5 출력필터 전) | `tb_attempt.verdict_raw` (레거시 전용) |
| `leak_channels` | plain/reversed/base64 등 유출 채널 | `tb_attempt.leak_channel` |
| `blocked_by_output_filter` | L5 출력필터가 잘랐는가 | `tb_attempt.blocked_by_filter` (레거시 전용) |
| `latency_ms` | 응답 지연 | `tb_attempt.latency_ms` |
| `attack_text` | 실제 던진 공격문 | `tb_attempt.rendered_text` |
| `principle` | 왜 통하는가 | (Attack.principle) |
| `answer` | 챗봇 응답 원문 | `tb_attempt.response_raw` |

## 주의

- `leaked`(정답 라벨)와 우리 판정기 출력(`verdict`)은 **다른 칸**이어야 F1 을 잴 수 있다.
  그래서 `tb_attempt` 에 nullable 컬럼 4개(`defense_level`/`verdict_gold`/`verdict_raw`/`blocked_by_filter`)를
  추가했다. 신규 진단 행에서는 이 4칸이 항상 NULL 이다. (9/2 테이블 명세서에 명시)
- 이 125건은 `import_poc.py` 가 `run_id = legacy_poc_20260814` 로 적재한다.
- 발표에서 "직접 생산한 실측 데이터"를 주장하는 근거가 이 폴더다. 지우거나 덮어쓰지 말 것.
