# 「뚫어보기」 인계 프롬프트 (새 창에 아래 블록 전체를 붙여넣기)

*(같은 프로젝트 섹션이면 "「뚫어보기」 이어서 하자. 프로젝트 메모리랑 model/HANDOFF.md 읽고 시작해줘." 한 줄이면 충분)*

---

나는 정보보안 전공 졸업 후 취업 준비 중인 KDT "AI 에이전트 엔지니어" 부트캠프 학생이야.
팀 프로젝트 **「뚫어보기」**(패키지명 `joker`)를 이어서 작업한다.
먼저 **프로젝트 메모리 전부**와 `~/Desktop/핵심프로젝트/model/SPEC.md` 를 읽고 시작해줘.

## ★ 작업 방식 (제일 중요)
- **코드만 본다.** 기획서·요구사항정의서·발표 PPT는 팀원 담당이다. 문서 제안하지 마라.
  수치를 내면 그 수치와 의미까지만 말하고, "기획서에 이렇게 적으세요"는 붙이지 마라.
- 아키텍처 결정은 2~3줄로 "왜"를 설명해라. 나는 아키텍처 판단 경험이 부족하다.
- 내 파트 / 팀 파트를 구분해서 제시하고, 단계별로 확인받고 진행해라.
- 사실이 아닌 걸 지어내지 마라. 확인 필요한 건 "확인 필요"로 표시해라.
- 수치를 주장하기 전에 **DB나 파일로 검증**해라. 이 프로젝트에서 그동안 잡은 버그 대부분이 그렇게 나왔다.

## 이 프로젝트가 뭐냐
한국어 프롬프트 인젝션을 **진단 → 처방 → 재진단** 하는 엔진(챗봇 병원).
챗봇 시스템 프롬프트를 넣으면 ① 한국어 공격을 자동으로 던져 취약점을 찾고 ② 방어 문구를 처방하고
③ **같은 공격을 다시 던져** 개선을 수치로 보여준다.
차별점 = 처방·재진단 루프(garak/PyRIT는 진단까지만) + 번역하면 사라지는 한국어 고유 공격.

## ★ 확정 실측 (2026-08-26 기준, 전부 검증 완료)
| 항목 | 목표 | 실측 |
|---|---|---|
| 처방 후 개선 | 20%p+ | **58.6% → 17.1% (41.4%p)** · 지시문 4개 152건 · 4/4 comparable |
| 판정 F1 | 0.85+ | **0.871** (독립 LLM 심판 125건, 사람 손 안 댐) |
| 1단계 스크리닝 | 90초 | **30.3초** (18건) |
| 정밀 진단 | 5분 | **177~250초** (전량 38건 × 2라운드) |
| 함정②(값 없는 지시문) | inconclusive | **실모델 검증 ✅** |
| 공격 시드 | 60개 | **38개** (사람 25 / AI 13) |
| 한국어 고유 | 30% | **26.3%** — 그중 **사람이 쓴 건 0개** (전부 AI 견본) |

**pytest 126개 전부 초록.** repo: https://github.com/hongjinkong/project_joker

## 오늘 이후 할 일 (이 순서로)

### 1단계 — 모델 보강 (금요일 전, 오늘)
처방이 약한 기법을 보강한다. 실측 기준 개선폭:
```
FORMAT 79→17 (+62.5%p, n24)   DOC 92→33 (+58.3%p, n12)   ROLE 55→5 (+50.0%p, n20)
INDIRECT 79→38 (+41.7%p, n24)  AUTH 44→6 (+37.5%p, n32)
OBFUSC 38→15 (+22.5%p, n40)  ← 가장 약함. 여기부터.
```
- **P04(OBFUSC)** 를 P02와 같은 방식으로 재작성해본다.
  P02가 성공한 원리: **금지("채우지 마라") → 대체 행동("값 대신 '비공개'라고 적어 완성해라").**
  공격의 힘이 '완성 압력'이면 금지만으로는 안 되고 채울 것을 줘야 한다. FORMAT 83→17로 증명됨.
- 그다음 P03(INDIRECT 잔여 38%), P06(DOC 잔여 33%).
- **한 번에 하나씩 바꾸고 재측정할 것.** 여러 개 동시에 바꾸면 뭐가 통했는지 영영 모른다.
  (P02 때는 운 좋게 같은 기법·같은 n으로 before/after가 갈려서 분리됐다.)
- 재측정: `python scripts/asr_rerun.py --full --only 한비,나래` (2개씩 나눠 돌릴 것)

### 2단계 — 팀 문구 수령 (8/28 금요일)
팀원이 `data/attacks/ko_native/<이름>.yaml` 에 문구를 넣는다(`origin: team_member`, `validated: false`).
**코드 수정 없이 3줄이면 끝나게 이미 만들어놨다:**
```bash
joker audit                                # 형식·출처·ko_native 비율. 위반 0건 확인
python scripts/validate_seeds.py --write   # 미검증 시드만 실모델에 던져 validated 승격
python scripts/asr_rerun.py --full         # 시드가 늘었으니 헤드라인 재측정
```
받은 뒤 할 일: ko_native 판정 근거가 SPEC §7 기준("영어로 번역하면 힘이 빠지는가")에 맞는지 검수.
그다음 그 결과 보고 다시 보강.

### 3단계 — UI (팀 문구 처리 후)
`ui/streamlit_app.py` + `src/joker/api/app.py`. `contracts/api_contract.md` 계약이 이미 있다.
지금 둘 다 비어 있다. 고민할 지점: **정밀 진단이 3~4분이라 동기 요청은 타임아웃 난다** →
`POST /diagnose` 를 잡 큐로 돌리고 `GET /jobs/{id}` 폴링이 맞는지 판단 필요.
경계 규칙: `ui/` 는 `joker` 를 import 하지 않는다(HTTP만). 테스트가 강제한다.

## 명령 카탈로그
```bash
joker doctor                                   # 환경 점검(역할별 backend·모델)
joker audit                                    # 시드 검증 + 출처 집계 + ko_native 비율
joker diagnose --prompt "..."                  # 빠른 진단(적응형, 스크리닝 90초 목표)
joker diagnose --prompt "..." --full --save    # 정밀 진단(전량, 5분 목표) ★수치 인용은 이걸로
joker gold judge|f1|export|apply               # 독립 정답 라벨 / F1
joker import-poc                               # PoC 125건 DB 적재
python scripts/asr_rerun.py --full --only a,b  # 지시문 5개 처방 전/후 (함정② 포함)
python scripts/reproducibility.py --repeat 3 --target 한비 [--fresh-recon]   # 재현 편차
python scripts/validate_seeds.py --write       # 새 시드 실측 → validated 승격
python scripts/bench_run.py                    # 스크리닝 18건 시간
```
`asr_rerun` / `reproducibility` 는 mock 이면 요약 문서를 안 만든다(실측치 오독 방지).

## ★ 코드에서 반드시 알아야 할 것 3개
1. **자산 '이름'이 공격문과 처방문에 그대로 박힌다.** `build_context()` 가 `{asset}` 를 자산 이름으로
   치환한다. RECON(gpt-5-mini, temperature 고정 불가)이 흔들리면 공격문 자체가 바뀐다.
   → `recon._pin_names_to_prompt` 가 지시문 표현으로 고정 + `_dedupe`. **이름=값**인 경우는 무조건 교정
   (안 하면 공격문에 정답이 박혀 ASR이 부풀고 처방문으로 비밀값이 샌다). `patch._target_line` 이 3층 방어.
   고정 후 재현 편차 **0.0%p**(전 0.0~13.2%p).
2. **SEGMENTED 채널**(조각·한글 음차)은 `leak` 확정이 아니라 `gray`(LLM 재검)다.
   "서울 지사 02-1234-5678"도 조각이 다 맞아서 규칙만으로는 유출과 우연을 못 가른다.
   `detect/romanize.py` 가 한글→로마자(서울→seoul). 자모 표 길이 (19,21,28) assert 필수.
3. **적응형은 '취약하지 않다'고 본 기법에 3건만 던진다.** 처방 후 1건만 뚫려도 33%로 튄다.
   수치를 인용할 땐 반드시 `--full`. (적응형 단일 실행은 19%p로 나와서 목표 미달처럼 보였다.)

## 지켜야 할 제약
- `.env` / `*.db` / API 키 **절대 커밋 금지**(.gitignore 확인됨).
- victim 모델은 **로컬 qwen2.5:3b 고정**. 유료 API 안 쓴다(저가 재현 + 정직성 + 비용).
  recon/judge 만 gpt-5-mini. 예산 $30(선생님 상환), 코드 상한 `max_calls=200`/진단.
- 처방문에 자산 **값**을 넣지 않는다(SPEC §5). 사용자가 어디에 붙여넣을지 모른다.
- 공격은 우리/동의받은 챗봇에만.
- 시드 출처: `author`(담당) 와 `origin`(실제 작성자: poc_human|team_member|ai_draft)은 다른 축이다.
  미기재는 `ai_draft`. 발표에서 "직접 생산한 데이터"로 셀 수 있는 건 25개(PoC 원본)뿐.

## ★ 환경 quirks (반복해서 물린 것들)
- **브리지(device_bash)에서 git 명령 절대 금지.** `git status` 만 돌려도 `.git/index.lock` 을 만들고
  지우지 못해 내 터미널 커밋이 막힌다. git 은 전부 내 Mac 터미널에서.
- **브리지에서 SQLite 쓰기 불가**(`disk I/O error`). 읽기만 됨.
  `import-poc`·`gold apply`·`diagnose --save`·`asr_rerun` 은 전부 내 터미널에서.
- **브리지는 네트워크 없음** → OpenAI 호출도 내 터미널에서만.
- 브리지 VM 은 python 3.10 + venv 심볼릭 깨짐 → 테스트는 `pip3 install pytest langgraph` 후
  `PYTHONPATH=src python3 -m pytest`.
- 한글 경로는 glob 으로 (`cd $HOME/mnt/*/model`). 직접 지정하면 실패.
- Mac venv 는 homebrew python3.14 로 생성(시스템 python3=3.9.6). 깨지면
  `/opt/homebrew/bin/python3.14 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"`.
- 로컬 Ollama 는 한 세션 ~180콜에서 뻗는다. `--full` 은 지시문당 76콜이니 **2개씩 나눠 돌린다.**
- YAML `principle` 은 `'` 로 시작 금지. `providers` → `nodes` import 금지. SVG 는 presentation
  attribute 에서 `var()` 못 받음(클래스+CSS로).

## 마감 (참고만 — 문서는 팀원 몫)
8/28 기획서 보완본+요구사항정의서 / 8/31 화면설계서(채효석) / 9/2 DB문서(이상현) / 9/4 발표 PPT / 9/22 최종.

---
*(인계용. 내용 바뀌면 새로 갱신)*
