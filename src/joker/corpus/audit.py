"""공격 시드 PR 게이트. 규칙 위반 목록을 반환한다(빈 리스트 = 통과).

이 함수 하나가 '비개발 팀원이 YAML 을 잘못 써도 엔진이 안 죽고, 뭐가 틀렸는지 알려주는'
안전장치다. 규칙은 SPEC/ARCH §4 의 5개:
  1. id 중복 없음 · 형식 TECHNIQUE-NN
  2. principle 비어 있지 않음 (왜 통하는지 한 줄)
  3. ko_native=True ⇒ ko_native_reason 필수  ← 함정⑤
  4. technique / goal 이 허용값 안
  5. technique 당 screening=True 가 정확히 3개  (스크리닝 18건 고정의 근거)
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict

from joker.models import Attack, Goal, Technique

_ID_RE = re.compile(r"^[A-Z_]+-\d{2}$")
_TECHNIQUES = {t.value for t in Technique}
_GOALS = {g.value for g in Goal}


class AuditError(Exception):
    """audit 위반이 있는데도 로드를 강행하려 할 때 발생."""


def _tech_value(t) -> str:
    return t.value if isinstance(t, Technique) else str(t)


def audit(attacks: list[Attack]) -> list[str]:
    violations: list[str] = []

    # 규칙 1: id 중복 + 형식
    id_counts = Counter(a.id for a in attacks)
    for aid, n in id_counts.items():
        if n > 1:
            violations.append(f"[규칙1] id 중복: {aid} 가 {n}번 나온다")
    for a in attacks:
        if not _ID_RE.match(a.id):
            violations.append(f"[규칙1] id 형식 오류: {a.id!r} (TECHNIQUE-NN 이어야 함, 예: ROLE-01)")

    for a in attacks:
        # 규칙 2: principle 필수
        if not (a.principle and a.principle.strip()):
            violations.append(f"[규칙2] {a.id}: principle 이 비어 있다 (왜 통하는지 한 줄 필수)")

        # 규칙 3: ko_native 근거 필수 (함정⑤)
        if a.ko_native and not (a.ko_native_reason and a.ko_native_reason.strip()):
            violations.append(
                f"[규칙3] {a.id}: ko_native=true 인데 ko_native_reason 이 없다 "
                "(영어로 번역했을 때 왜 안 통하는지 한 줄)"
            )

        # 규칙 4: technique / goal 허용값
        if _tech_value(a.technique) not in _TECHNIQUES:
            violations.append(f"[규칙4] {a.id}: technique 허용값 아님 → {a.technique!r}")
        goal_v = a.goal.value if isinstance(a.goal, Goal) else str(a.goal)
        if goal_v not in _GOALS:
            violations.append(f"[규칙4] {a.id}: goal 허용값 아님 → {a.goal!r}")

    # 규칙 5: technique 당 screening=True 가 정확히 3개
    screening_by_tech: dict[str, int] = defaultdict(int)
    present_tech: set[str] = set()
    for a in attacks:
        tv = _tech_value(a.technique)
        present_tech.add(tv)
        if a.screening:
            screening_by_tech[tv] += 1
    for tv in sorted(present_tech):
        cnt = screening_by_tech.get(tv, 0)
        if cnt != 3:
            violations.append(
                f"[규칙5] {tv}: screening=true 가 {cnt}개다 (정확히 3개여야 스크리닝 18건이 유지된다)"
            )

    return violations
