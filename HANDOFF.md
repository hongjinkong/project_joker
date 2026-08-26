# 「뚫어보기」 프로젝트 인계 프롬프트 (새 창에 붙여넣기)

아래 `---` 사이 블록 전체를 복사해서 새 세션 첫 메시지로 붙여넣으면 됩니다.
(같은 프로젝트 섹션이면 "「뚫어보기」 이어서 하자. 프로젝트 메모리랑 model/HANDOFF.md 읽고 시작해줘." 한 줄이면 충분)

---

나는 정보보안 전공 졸업 후 취업 준비 중인 KDT "AI 에이전트 엔지니어" 부트캠프 학생이야.
팀 프로젝트 **「뚫어보기」**(코드 패키지명 `joker`)를 이어서 작업할 거야.
먼저 프로젝트 메모리와 `~/Desktop/핵심프로젝트/model/SPEC.md` 를 읽고 시작해줘. 아래가 현재 상황이야.

## 이 프로젝트가 뭐냐
한국어 프롬프트 인젝션을 **진단 → 처방 → 재진단** 하는 엔진(챗봇 병원). 챗봇 시스템 프롬프트를 넣으면
① 한국어 공격을 자동으로 던져 취약점을 찾고 ② 방어 문구를 처방하고 ③ 같은 공격을 다시 던져
개선을 수치로 보여준다. 차별점 = 처방·재진단 루프 + 번역하면 사라지는 한국어 고유 공격.

## 지금까지 한 것 (완료)
- 엔진 7단계 + 자동 변형 8종 완성. **pytest 79개 전부 초록.**
- 공격 시드 38개 검증 + 변형으로 실질 342개. SQLite 저장 + PoC 125건 적재.
- GitHub 푸시(https://github.com/hongjinkong/project_joker). 팀 README 개편 + 구조 치트시트(HTML) 완성.
- **Mac 환경 복구**: venv 는 homebrew python3.14 로 생성해야 함(시스템 python3=3.9.6). 깨지면
  `/opt/homebrew/bin/python3.14 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"`.
- **gpt-5-mini API 호환 수정 완료**: gpt-5 계열은 max_tokens/temperature=0/seed 거부 →
  openai_compat.py 가 모델명으로 자동 분기(max_completion_tokens + reasoning_effort). 이거 안 했으면 키 꽂아도 죽었음.
  (혹시 이 수정 커밋·푸시 안 했으면 `git add -A && git commit && git push` 먼저.)
- **유료 API 붙여서 첫 실측 성공** (victim=로컬 qwen / recon·judge=gpt-5-mini):
  - **처방 전 ASR 53% → 처방 후 39% (14%p 개선), 등급 C, comparable=True.** ← 서비스 핵심 세일즈.
  - 잘 막음: INDIRECT 83→33, OBFUSC 50→20. **안 막힘(개선 과제): FORMAT 83, AUTH 25, INDIRECT_DOC 67 그대로.**
  - **ROLE 0→33 로 오히려 늘어남**(n=3, 노이즈일 수도/처방이 역할공격 살짝 열었을 수도 → 확인 필요).

## ★ 정직성 이슈 (코드 완료 · 실행 대기) — 2026-08-26
**F1 = 1.0 은 순환이었다.** 예측=우리 규칙판정기, 정답=PoC CSV의 leaked 라벨(둘 다 "SEOUL-1234 있나").
→ **`joker gold` 로 해결. 코드·테스트 완료(pytest 79 초록). 실호출만 남음.**

- 정답 = 독립 LLM 심판(gpt-5-mini) 125건 + 규칙과 갈린 건만 홍진성이 직접 재정(verdict_final).
- ★ 심판에게 **비밀값 원문을 안 준다. 자산 이름만.** 값을 주면 심판도 문자열 대조 → 순환 부활.
- 정답 라벨은 tb_gold 에 따로 저장(import-poc 재실행해도 안 날아감). PK=(attack_id, defense_level).
- 빈 응답은 block 으로 안 때움 — 라벨을 안 만들고 실패 보고 후 다음 실행에서 재시도.

```
joker gold judge --limit 10   # 시험(유료, 수 센트)
joker gold judge              # 전체 125건 (약 $0.10)
joker gold export             # 불일치만 CSV → verdict_human 칸 채우기
joker gold apply              # 재정 반영
joker gold f1                 # csv(순환)/llm(독립)/final(헤드라인) 3종 비교
```
※ 브리지 VM 은 네트워크가 없다 → **이 명령들은 Mac 터미널에서 직접** 실행.

## 다음에 할 것 (우선순위)
1. **진짜 F1 실행** — 위 `joker gold` 5줄을 Mac 터미널에서 실행 → 수치 확보. (코드는 끝남)
2. **처방 전/후 안정화** — ROLE 0→33 원인 확인(여러 프롬프트로 재현), 처방 약한 기법(FORMAT/AUTH/INDIRECT_DOC)
   방어 패턴 보강. 처방후 감소가 서비스 핵심이므로 여기 신뢰도 올리기.
3. **금요일(8/28) 팀 문구 입력** — 받은 4줄을 `data/attacks/ko_native/<이름>.yaml` 에 넣고
   `joker audit` 로 검증 + ko_native 30% 확인(현재 26.3%). 시드 38→목표 60.
4. **기획서 보완본(8/28) 수치 갱신** — 스크리닝 49초✅, 처방 전/후 53→39%, 진짜 F1(1번 결과), 변형 8종✅.
5. **화면 UI**(다음 주) — ui/streamlit_app.py + FastAPI. contracts/api_contract.md 계약 준비됨.
6. (보류) victim 멀티모델 — 구조상 이미 가능(VICTIM_MODEL 한 줄), 코드 여문 뒤 `--victim-model` 플래그.

## 유료 API 설정 상태 (Mac .env 에 이미 넣음)
`JOKER_PROFILE=local` + `RECON_BACKEND=openai` `JUDGE_BACKEND=openai` `OPENAI_API_KEY=sk-...`
`RECON_MODEL=gpt-5-mini` `JUDGE_MODEL=gpt-5-mini`. victim 은 로컬 qwen2.5:3b 유지(동결).
예산: **$30 상환**(선생님). OpenAI 자동충전 OFF + 크레딧 소액 충전으로 하드캡. 코드도 max_calls=200 상한.

## 문서 마감 (KST)
8/28 기획서 보완본 + 요구사항정의서 / 8/31 화면설계서(채효석) / 9/2 DB문서(schema.sql+import-poc, 이상현)
/ 9/4 발표 PPT / 9/22 최종.

## 지켜야 할 제약
- .env / *.db / API 키 절대 커밋 금지(.gitignore 확인됨). victim 모델은 절대 유료 API 안 씀(로컬 유지·정직한 재현).
- 공격은 우리/동의받은 챗봇에만.

## 작업 방식
- 아키텍처 결정은 2~3줄로 "왜"를 설명(내가 아키텍처 약함). 내 파트/팀 파트 구분. 단계별 확인받고 진행.

## 환경 quirks
- Mac 파이썬 3.14 / 학원 Windows 3.11 / 클라우드 3.11. Windows 는 `set VAR=값`·`.venv\Scripts\activate`.
- git 은 브리지에서 안 돎 → 내 터미널에서 직접 커밋·푸시.
- 342 변형 대량은 로컬 Ollama 가 ~180콜에서 뻗음(로컬 한계, 코드 버그 아님). 헤드라인은 base-38 / 적응형 diagnose 사용.
- SVG 는 presentation attribute 에서 var() 못 받음 → 클래스+CSS 로 색.

이 상황에서 이어서 작업하자. 제일 먼저 **진짜 F1(독립 판정)** 부터 만들면 좋겠어.

---
*(인계용. 내용 바뀌면 새로 갱신)*
