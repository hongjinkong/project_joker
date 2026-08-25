"""스크리닝 집합 선정 = 1단계 적응형 샘플링의 앞단.

기법 6종 × 3 = 18건 고정. 팀원이 screening 플래그를 잘못 달면 여기서 로드를 거부한다
(90초 목표와 R1/R2 replay 전제가 개수 하나로 무너지기 때문).
실제 규칙 검증은 audit 이 하고, 여기서는 '선정'과 '순서 안정화'를 담당한다.
"""

from __future__ import annotations

from collections import defaultdict

from joker.models import Attack, Technique


def screening_set(attacks: list[Attack]) -> list[Attack]:
    """screening=True 인 공격만, technique 정렬 → id 정렬로 안정된 순서로 반환.

    technique 하나라도 screening 이 3개가 아니면 ValueError (로드 거부).
    """
    by_tech: dict[Technique, list[Attack]] = defaultdict(list)
    for a in attacks:
        if a.screening:
            by_tech[a.technique].append(a)

    for tech, items in by_tech.items():
        if len(items) != 3:
            raise ValueError(
                f"{tech.value}: screening 이 {len(items)}개다. 정확히 3개여야 스크리닝 18건이 유지된다."
            )

    result: list[Attack] = []
    for tech in sorted(by_tech, key=lambda t: t.value):
        result.extend(sorted(by_tech[tech], key=lambda a: a.id))
    return result


def concentration_set(attacks: list[Attack], techniques: list[Technique]) -> list[Attack]:
    """2단계: 취약 확인된 기법에만 나머지(screening=False 포함 전체) 시드를 집중 투입."""
    targets = set(techniques)
    return sorted(
        [a for a in attacks if a.technique in targets],
        key=lambda a: (a.technique.value, a.id),
    )
