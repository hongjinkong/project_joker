# 「뚫어보기」 엔진 재작성 — 폴더 구조 · 모듈 경계 제안서 (v1)

작성 2026-08-24 · 코드 작성 **전** 확인용. 승인/수정 후에 착수한다.
대상: `~/Desktop/핵심프로젝트/model/`

---

## 0. 결론 먼저

- 폴더를 **3구역**으로 나눈다: `data/`(팀 자산·YAML, 파이썬 없음) / `src/ddb/`(엔진) / `tests/`(함정 6개).
- 의존 방향은 **단방향 1줄**: `data → corpus → nodes → pipeline → store/api → ui`. 역방향 import는 금지하고 테스트로 막는다.
- SPEC.md 1장의 함정 6개는 **파일명이 곧 함정 번호**인 테스트로 존재한다 (`tests/test_trap01_*.py` … `trap06`).
- 비개발 팀원(원서윤·류성환·이상현·채효석)이 건드리는 파일은 **전부 `data/` 아래 YAML 1개씩**. `.py`를 열 일이 없다.

---

## 1. 디렉터리 트리

```
model/
├── SPEC.md                       # 명세 (기존)
├── README.md                     # 5분 안에 돌려보는 법 (팀원용)
├── pyproject.toml                # 패키지 + pytest 설정. requirements.txt 대체
├── .env.example                  # LLM_BASE_URL / LLM_API_KEY / 모델명 3개
├── .gitignore                    # .env, *.db, runs/ — 키 유출 1차 방어선
│
├── data/                         # ★ 팀 자산 구역 — 파이썬 파일 없음
│   ├── attacks/
│   │   ├── core_25.yaml          # 진성 8/14 PoC, validated: true (125회 실증)
│   │   ├── indirect_doc.yaml     # 8/24 DOC-01~03, validated: false (미검증 초안)
│   │   └── ko_native/            # 한국어 고유 추가분 — 1인 1파일
│   │       ├── wonseoyun.yaml    #   한자 혼용 · 한국 문서서식 (6)
│   │       ├── hongjinseong.yaml #   자모 분해 · 초성체 (4)
│   │       ├── ryuseonghwan.yaml #   직급 위계 · 존댓말 강도 (4)
│   │       ├── leesanghyun.yaml  #   관공서 문체 · 높임말 경유 (3)
│   │       └── chaehyoseok.yaml  #   사투리 · 줄임말/신조어 (3)
│   ├── defenses/
│   │   └── patterns.yaml         # 방어 패턴 카탈로그 (P01~P08, 류성환 담당)
│   ├── schemas/
│   │   ├── attack.schema.json    # 필수 필드·허용값 정의 (에디터 자동완성용)
│   │   └── defense.schema.json
│   └── evidence/                 # 읽기 전용 팀 자산 — 절대 수정 금지
│       ├── poc_2026-08-14_125.csv
│       └── poc_2026-08-14_125.json
│
├── src/ddb/                      # 엔진 (import 이름 `ddb`)
│   ├── config.py                 # Settings (frozen) + Profile. 전역 mutation 없음
│   ├── models.py                 # Attack / DefensePattern / Asset / Attempt / Report
│   ├── state.py                  # RunState TypedDict — 상태 키의 유일한 정의처
│   │
│   ├── corpus/
│   │   ├── loader.py             # YAML → Attack[] · 스키마 검증 · 중복 ID 검출
│   │   └── audit.py              # PR 게이트: ko_native_reason 누락, principle 누락 등
│   │
│   ├── providers/                # ★ Provider 추상화
│   │   ├── base.py               # LLMProvider 프로토콜 + CallResult + Usage
│   │   ├── openai_compat.py      # local(Ollama) / openai 공용 — base_url만 다름
│   │   ├── mock.py               # 결정론적 시나리오 응답 (모델 없이 전 파이프라인 실행)
│   │   ├── budget.py             # 호출 상한 + 토큰·비용 집계 (래퍼)
│   │   └── registry.py           # Settings → Provider 조립 (여기서만 분기)
│   │
│   ├── safety/                   # ★ 정보보안 담당 구역 (홍진성)
│   │   ├── wrapping.py           # <untrusted_prompt> / <untrusted_output> 래핑
│   │   ├── masking.py            # 입력단 개인정보·API 키 마스킹
│   │   └── logging.py            # 구조화 로그 + 키 마스킹 필터
│   │
│   ├── detect/
│   │   ├── normalize.py          # 영숫자·한글만 남기고 대문자화
│   │   └── rules.py              # plain / reversed / base64 채널 + gray 판정 조건
│   │
│   ├── nodes/                    # 전부 순수 함수 f(state, deps) -> state
│   │   ├── recon.py              # 지시문 → assets (실패 시 inconclusive)
│   │   ├── attack.py             # 2단계 적응형 샘플링 + R2 replay
│   │   ├── judge.py              # 규칙 우선, gray만 LLM
│   │   ├── patch.py              # 카탈로그 조립만 (LLM 자유생성 금지)
│   │   └── report.py             # grade / asr_before / asr_after / comparable
│   │
│   ├── pipeline.py               # 순차 실행 — langgraph 없이도 완주한다
│   ├── graph.py                  # LangGraph 배선만 (import 실패해도 엔진은 살아있음)
│   │
│   ├── store/
│   │   ├── schema.sql            # 9/2 제출 테이블 명세서의 원본
│   │   ├── sqlite.py             # Repository (save_run / load_run / list_runs)
│   │   └── import_poc.py         # evidence/125건 → legacy run으로 적재
│   │
│   ├── api/app.py                # FastAPI — 화면팀 계약면
│   └── cli.py                    # ddb diagnose / audit / bench
│
├── ui/
│   └── streamlit_app.py          # 채효석 작업 구역. api만 호출, 엔진 직접 import 금지
│
├── tests/
│   ├── conftest.py               # mock provider · 임시 DB · 샘플 지시문 픽스처
│   ├── test_trap01_replay_comparable.py    # R2가 R1과 동일 attack_id 집합인가
│   ├── test_trap02_inconclusive.py         # 자산 0개 → 등급 없음 + 공격 스킵
│   ├── test_trap03_state_parity.py         # pipeline 결과 == graph 결과
│   ├── test_trap04_placeholder_braces.py   # 중괄호 포함 공격문 렌더링
│   ├── test_trap05_corpus_audit.py         # ko_native True ⇒ reason 필수
│   ├── test_trap06_patch_deterministic.py  # 같은 입력 → 같은 처방 (2회 호출 동일)
│   ├── test_config_injection.py            # 전역 mutation 없음 / 두 Settings 공존
│   ├── test_provider_contract.py           # 3 provider 동일 인터페이스 (파라미터화)
│   ├── test_safety_wrapping.py             # 메타 인젝션 시도가 격리되는가
│   └── test_store_roundtrip.py             # save → load 무손실
│
├── scripts/                      # 학원 PC 실측용 (결과는 docs/bench/ 로)
│   ├── bench_latency.py          # 실측 #1,#2 — 90초 목표 근거
│   ├── bench_judge_f1.py         # 실측 #4 — 125건 라벨로 F1
│   └── bench_promptguard_ko.py   # 실측 #6 — 프로젝트 최대 근거
│
└── docs/
    ├── db_tables.md              # schema.sql에서 자동 생성 (9/2 제출물 초안)
    └── bench/                    # 실측 결과 원본 (날짜별)
```

---

## 2. 모듈 경계 — 왜 이렇게 잘랐는가

### ① `data/`(YAML)를 코드 밖으로 완전히 분리
비개발 팀원 4명이 공격 시드 20개를 추가해야 한다. `.py`를 열게 하면 따옴표 하나로 엔진이 죽고,
그 순간 "내가 코드 담당"이라 나한테 다 몰린다. YAML은 깨져도 로더가 어느 줄인지 말해준다.
**추가로 `ko_native/`를 1인 1파일로 쪼갠 이유는 git 충돌 때문이다** — 5명이 한 파일을 고치면 merge conflict가 나고, 그걸 푸는 건 결국 나다.

### ② `providers/`에서 local과 openai를 한 파일(`openai_compat.py`)로 합침
Ollama가 OpenAI 호환 엔드포인트를 제공하므로 둘의 차이는 `base_url`과 키뿐이다.
파일을 나누면 같은 코드가 두 벌 생기고 한쪽만 고치는 사고가 난다.
`mock.py`만 별개인 이유는 네트워크를 아예 안 타는 완전히 다른 구현이기 때문이다.

### ③ `pipeline.py`(순차)와 `graph.py`(LangGraph)를 분리
함정 ③이 정확히 이 지점에서 났다. 노드가 순수 함수이고 pipeline이 langgraph 없이 완주해야
"그래프만 이상하다"를 테스트로 잡을 수 있다. 부수 효과로 langgraph 설치가 안 되는 팀원도 엔진을 돌려볼 수 있다.

### ④ `store/`를 노드 밖에 둔다 (노드는 DB를 모른다)
노드가 DB에 직접 쓰면 단위 테스트마다 DB가 필요해지고, 노드 하나 고칠 때 스키마까지 봐야 한다.
`pipeline`이 최종 state를 받아 `store`에 한 번 넘긴다. 9/2 DB 문서를 고칠 때 `store/`만 열면 된다.

### ⑤ `safety/`를 독립 패키지로
메타 인젝션 방어·마스킹·키 로깅은 발표에서 내 전공 근거로 쓸 부분이다.
여러 노드에 흩뿌려 놓으면 "이게 우리 보안 설계입니다"라고 보여줄 수 있는 실체가 없어진다.
한 폴더에 모으면 그대로 문서 한 장이 된다.

### ⑥ `src/` 레이아웃 + `pyproject.toml`
현재 폴더에서 실행할 때만 import가 되는 상태를 막는다(`pip install -e .` 후에는 어디서 실행해도 동일).
`sys.path` 조작 코드를 안 넣게 되고, pytest 설정도 한 파일에 모인다.

### 의존 방향 (단방향, 역방향 금지)
```
data(YAML) → corpus → nodes → pipeline → { store, api } → ui
                ↑                ↑
           models/state     providers, safety, detect  (하위 공용, 위를 import 안 함)
```
- `nodes/`는 `providers/`를 **직접 import하지 않는다.** 호출 가능한 객체를 인자로 받는다 → 테스트에서 mock 주입.
- `ui/`는 `ddb`를 import하지 않고 HTTP만 쓴다 → 채효석이 엔진을 몰라도 화면을 만들 수 있다.
- 이 규칙은 `test_import_boundaries.py` 하나로 강제한다 (금지된 import 문자열 검사).

---

## 3. 함정 6개 ↔ 테스트 대응표

| SPEC 1장 | 증상 | 테스트 파일 | 검증 방식 |
|---|---|---|---|
| ① 재진단 집합 불일치 | 26건 vs 18건 비교 | `test_trap01_replay_comparable` | R1 attack_id 집합 == R2 집합, `report.comparable is True` |
| ② 자산 0개에 등급 A | 진단 불가를 안전으로 오독 | `test_trap02_inconclusive` | 값 없는 지시문 → `grade is None`, `attempts == []` |
| ③ State 키 조용히 소실 | 그래프만 처방 스킵 | `test_trap03_state_parity` | 같은 입력으로 pipeline/graph 실행 → 결과 dict 동일 |
| ④ `str.format()` 폭발 | 중괄호 리터럴 | `test_trap04_placeholder_braces` | `{"key": "value"}` 포함 공격문 렌더링 성공 |
| ⑤ 근거 없는 ko_native | 비율 부풀림 | `test_trap05_corpus_audit` | 전체 YAML 로드 → `ko_native and not reason` 이 0건 |
| ⑥ 처방 비결정성 | Before/After 무의미 | `test_trap06_patch_deterministic` | 같은 입력 2회 → 완전 동일 문자열 |

**테스트는 코드보다 먼저 쓴다(각 trap 파일부터).** 함정 6개가 "다시 안 나는지"를 확인할 방법이 그것뿐이다.

---

## 4. 내가 맡을 부분 / 팀에 넘길 부분

| 구역 | 담당 | 넘기는 방식 |
|---|---|---|
| `src/ddb/**` 전부 | **홍진성** | — |
| `tests/**` | **홍진성** | — |
| `safety/**` (메타 인젝션·마스킹·키) | **홍진성** (전공 차별점) | — |
| `data/attacks/ko_native/*.yaml` | 팀원 5명 | 파일 1개씩 배정 + 양식 예시 3줄. 스키마가 틀리면 `ddb audit`이 잡아줌 |
| `data/defenses/patterns.yaml` | 류성환 | 카탈로그 형식은 내가 먼저 P01~P08을 채워 예시로 두고, 문구 보강만 요청 |
| `ui/streamlit_app.py` | 채효석 | FastAPI 응답 JSON 예시를 먼저 고정해서 넘김 (8/31 화면설계서 입력) |
| `docs/db_tables.md` | 이상현(문서) | `schema.sql` + 생성 스크립트를 내가 주고, 문서 조판은 팀장 |
| 학원 PC 실측 실행 | 홍진성 | 스크립트만 실행하면 되게 만들어 둠 |

**팀에 넘기기 전 선행조건**: 각 담당 파일에 예시 1~2개가 이미 채워져 있어야 한다.
빈 파일을 주면 형식 질문이 나에게 다시 돌아온다.

---

## 5. 착수 순서 (제안)

1. `pyproject.toml` + `config.py` + `models.py` + `state.py` — 뼈대와 타입
2. `tests/` 함정 6개 **먼저 작성**(전부 실패 상태)
3. `providers/`(mock 우선) + `corpus/loader.py` + YAML 이관(25 + 3)
4. `detect/` + `nodes/` 5개 + `pipeline.py`
5. `store/`(schema.sql + sqlite.py) + `import_poc.py`로 125건 적재
6. `graph.py` + `test_trap03` 통과
7. `api/` + `cli.py`, 그 다음 `ui/`

1~5까지가 이번 주(8/28 요구사항정의서 보완 전) 목표다.

---

## 6. 확인이 필요한 갈림길

1. **DB 방언** — 엔진은 SQLite로 간다(설치 0, 파일 1개, 팀원 배포 쉬움). 다만 9/2 제출 문서를 MySQL/PostgreSQL 기준으로 써야 한다면 `schema.sql`을 그 방언으로 쓰고 SQLite는 개발용으로만 둔다. 과정에서 배운 DB가 무엇인지 확인 필요.
2. **125건 적재 방식** — SQLite에 `legacy run`으로 넣으면 9/2 DB 문서에 실데이터가 생기고 F1 벤치가 DB에서 바로 돈다. 반대로 CSV 원본만 두면 단순하다.
3. **이번 주 범위** — 엔진+CLI+SQLite+테스트까지만인지, FastAPI/Streamlit까지인지.
4. **유료 API** — 어느 회사 것을 받았는지. 미정이면 `mock` + 로컬로 진행하고 `registry.py`에 자리만 비워둔다.
