# data/attacks — 공격 시드 (팀 자산)

- `core_25.yaml` — 홍진성 8/14 PoC 25개. `origin: poc_human` · validated: true (125회 실증)
- `indirect_doc.yaml` — 문서 경유 3개. **`origin: ai_draft`** · validated: true (8/25 실측 통과)
- `ko_native/` — 한국어 고유. **1인 1파일** (git 충돌 방지).
  현재 들어 있는 10개는 전부 **AI 견본**(`origin: ai_draft`)이다. 팀원 본인 문구로 교체·추가할 것.

## ★ author 와 origin 은 다른 축이다

| 필드 | 뜻 |
|---|---|
| `author` | 이 시드의 **담당·책임자** (팀원 파일이면 그 팀원) |
| `origin` | **실제로 문장을 쓴 주체** — `poc_human` / `team_member` / `ai_draft` |

미기재 시 `ai_draft` 로 집계된다(사람이 썼다고 주장하지 않는 쪽이 안전).
본인이 직접 쓴 문구는 **반드시 `origin: team_member` 로 바꿔야** 발표에서 '직접 생산한 데이터'로 셀 수 있다.
`joker audit` 이 실행할 때마다 사람 작성 개수를 찍어준다.

편집 규칙은 `../schemas/attack.schema.json` 과 `joker audit` 이 강제한다.
