"""호출량·비용 집계 — BudgetProvider 가 세고 있던 숫자를 실제로 읽는 곳.

★ 왜 필요했나 (2026-08-27 구조 점검에서 발견)
`BudgetProvider` 가 calls / prompt_tokens / completion_tokens 를 성실히 세고 있었는데
**그 값을 읽는 코드가 프로젝트 전체에 0건이었다.** 예산 $30 을 관리해야 하는데
"진단 1회에 얼마 썼는지" 알 방법이 없었다. 계약 v0.2 가 약속한 `estimated_calls` 도
여기서 나와야 한다(BYOK 면 그 요금이 **사용자 카드**로 나가므로 시작 전에 고지해야 한다).

정직성 규칙:
- victim 이 로컬(Ollama)이면 비용 0 이다. 로컬 호출을 돈으로 세면 리포트가 거짓말한다.
- 단가는 벤더가 언제든 바꾼다. 여기 표는 **기본값일 뿐**이고 실제 청구액과 다를 수 있다.
  화면·리포트에 쓸 때는 '추정'이라고 밝힌다.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# 1M 토큰당 USD (입력, 출력). ★ 확인 필요 — 벤더 가격 페이지 기준으로 주기적으로 갱신할 것.
#   로컬 모델은 여기 없으면 0 으로 계산된다(그게 맞다).
PRICE_PER_1M: dict[str, tuple[float, float]] = {
    "gpt-5-mini": (0.25, 2.00),
}

# 진단 1회의 대상 모델 호출 수. 실제 호출은 여기에 gray 재검(judge)이 더해진다.
_RECON_CALLS = 1
_ROUNDS = 2


def estimate_calls(n_seeds: int, *, full: bool, screening_size: int = 18) -> dict:
    """진단 시작 전에 '몇 번 부를지' 를 알려준다(계약 v0.2 estimated_calls).

    ★ 적응형(full=False)은 고정값이 아니다. 1단계 스크리닝 뒤 '취약하다'고 본 기법에만
      나머지 시드를 집중 투입하므로, 아무 기법도 안 뚫리면 스크리닝만, 전부 뚫리면 전량이 된다.
      처음에 스크리닝 수만 고지했다가 mock 실행에서 36 예상 / 84 실제가 나왔다 — 전 기법이
      취약해 2단계가 전량을 던진 것이다. **사용자 돈이 걸린 고지를 하한만 말하면 안 된다.**
    judge 는 gray 로 빠진 응답만 부르므로 이것도 사전에 정확히 알 수 없다.
    """
    v_max = n_seeds * _ROUNDS
    v_min = v_max if full else screening_size * _ROUNDS
    return {
        "victim_min": v_min,
        "victim_max": v_max,
        "victim": v_min,              # 하위호환
        "recon": _RECON_CALLS,
        "judge_max": v_max,           # 최악의 경우 전부 gray
        "total_min": v_min + _RECON_CALLS,
        "total_max": v_max + _RECON_CALLS + v_max,
        "note": ("적응형은 취약 기법에만 집중 투입하므로 스크리닝~전량 사이. "
                 "judge 는 gray 응답만 호출한다."),
    }


@dataclass
class RoleUsage:
    role: str
    model: str
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    priced: bool = False   # False = 단가표에 없음(로컬이거나 미등록) → 비용 0 으로 본다


@dataclass
class UsageReport:
    roles: list[RoleUsage] = field(default_factory=list)

    @property
    def total_calls(self) -> int:
        return sum(r.calls for r in self.roles)

    @property
    def total_cost_usd(self) -> float:
        return sum(r.cost_usd for r in self.roles)

    @property
    def has_unpriced_paid_calls(self) -> bool:
        """단가를 모르는 모델을 유료로 불렀을 가능성 — 비용을 0 으로 보고하면 안 되는 경우."""
        return any(r.calls and not r.priced and not _looks_local(r.model) for r in self.roles)

    def lines(self) -> list[str]:
        out = []
        for r in self.roles:
            if not r.calls:
                continue
            money = "무료(로컬)" if _looks_local(r.model) else (
                f"${r.cost_usd:.4f}" if r.priced else "단가 미등록")
            out.append(f"{r.role:6} {r.model:24} {r.calls:4}콜  "
                       f"in {r.prompt_tokens:6} / out {r.completion_tokens:6}  {money}")
        return out


def _is_free(model: str) -> bool:
    """돈이 안 나가는 호출인가. Ollama 태그(':' 포함) 또는 mock.

    ★ mock 을 빠뜨렸다가 "단가 미등록 유료 모델" 경고가 떴다(2026-08-27). 경고가 늑대소년이 되면
      진짜 유료 미등록일 때 아무도 안 본다.
    """
    m = (model or "").lower()
    return ":" in m or m.startswith("mock")


_looks_local = _is_free   # 이름 유지(내부 호출부 호환)


def _price(model: str) -> tuple[float, float] | None:
    m = (model or "").lower().split("/")[-1]
    for key, val in PRICE_PER_1M.items():
        if m.startswith(key):
            return val
    return None


def collect(providers: dict) -> UsageReport:
    """build_providers() 가 만든 dict 를 그대로 넣으면 역할별 사용량을 뽑아준다.

    BudgetProvider 로 감싸이지 않은 provider(mock)는 셀 것이 없으므로 0 으로 둔다.
    """
    rep = UsageReport()
    for role in ("victim", "recon", "judge"):
        p = providers.get(role)
        if p is None:
            continue
        model = getattr(getattr(p, "inner", p), "model", "?")
        u = RoleUsage(role=role, model=model,
                      calls=getattr(p, "calls", 0),
                      prompt_tokens=getattr(p, "prompt_tokens", 0),
                      completion_tokens=getattr(p, "completion_tokens", 0))
        pr = None if _looks_local(model) else _price(model)
        if pr:
            u.priced = True
            u.cost_usd = (u.prompt_tokens / 1_000_000) * pr[0] + (u.completion_tokens / 1_000_000) * pr[1]
        rep.roles.append(u)
    return rep
