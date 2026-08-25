# joker — 「뚫어보기」 엔진

> **서비스명은 「뚫어보기」, 코드 패키지명은 `joker`(팀명).** 둘은 일부러 분리했다.
> 9/2 DB 문서와 같이 볼 때 `ddb` 가 "DataBase"로 오해돼서 `joker` 로 정했다.

한국어 프롬프트 인젝션 **진단 → 처방 → 재진단** 엔진. 기존 도구(garak/PyRIT/Promptfoo)는 진단까지만 한다.

## 5분 안에 돌려보기 (팀원용)

```bash
cd model
python -m venv .venv && source .venv/bin/activate   # (Windows: .venv\Scripts\activate)
pip install -e ".[dev]"        # joker 패키지 + pytest 설치
cp .env.example .env           # 접속 정보 (모델 없어도 mock 으로 돌아감)

joker doctor                   # 환경 상태 한 화면 점검 (langgraph/데이터/프로파일)
pytest                         # 테스트 실행
```

모델(Ollama)이 없어도 `JOKER_PROFILE=mock` 이면 엔진이 돈다. 발표 당일 백업 경로도 이것.

## 지금 상태 (2026-08-24, 1~3단계)

**뼈대 + 타입 + 계약 + 테스트(빨간불)** 까지. 노드·프로바이더·저장소 로직은 아직 스텁이다.
`pytest` 를 돌리면 **함정 6개 테스트가 실패(빨간불)** 로 나오는 게 정상이다 —
이후 구현이 이 빨간불을 하나씩 초록으로 바꾸는 방식(TDD)으로 진행한다.

| 단계 | 내용 | 상태 |
|---|---|---|
| 1 | pyproject + config + models + state | ✅ |
| 2 | contracts/ API 응답 계약 (화면팀 입력) | ✅ |
| 3 | tests/ 함정 6개 (전부 실패 상태) | ✅ |
| 4 | providers(mock) + corpus 로더 + YAML 이관 | ⬜ |
| 5 | detect + nodes 5개 + pipeline (mock 완주) | ⬜ |
| 6 | store(schema.sql) + import_poc 125건 | ⬜ |
| 7 | graph.py + trap03 통과 | ⬜ |

## 폴더 지도

```
data/        공격·방어 데이터(YAML) + evidence(PoC 125건). ★ 비개발 팀원 편집 구역, .py 없음
src/joker/   엔진. config/models/state = 상태의 단일 정의처
  ├ corpus/   YAML 로더·audit(PR 게이트)·sampling·render
  ├ providers/ local/openai/mock 같은 인터페이스 + budget(상한)
  ├ safety/   메타 인젝션 방어·마스킹·로깅 (정보보안 담당 구역)
  ├ detect/   규칙 판정(정규화·채널)
  ├ nodes/    recon/attack/judge/patch/report — 순수 함수 f(state, deps)
  ├ pipeline.py(순차)  graph.py(LangGraph 배선만)
  └ store/    schema.sql(9/2 문서 원본)·sqlite·import_poc
contracts/   API 응답 계약 — 코드보다 먼저 고정. 8/31 화면설계서 입력
tests/       함정 6개(trap01~06) + 경계 5개
```

## 규칙 (팀원 필독)

- **`.env` 는 절대 커밋 금지.** `.gitignore` 에 이미 있다. 키 유출 1차 방어선.
- 공격 시드는 `data/attacks/**.yaml` 만 고친다. `.py` 는 건드리지 않는다.
  틀리면 `joker audit` 이 잡아준다.
- `data/evidence/` 는 **읽기 전용**. 지우거나 덮어쓰지 말 것(발표 근거).
