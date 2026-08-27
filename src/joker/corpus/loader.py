"""YAML → Attack[]. 스키마 검증·audit 을 한 번에.

비개발 팀원이 만지는 것은 data/attacks/**.yaml 뿐이다. 이 로더가 그걸 읽어 타입으로 바꾸고,
audit 을 돌려 문제가 있으면 '왜 틀렸는지'와 함께 로드를 거부한다(엔진이 조용히 죽지 않게).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from joker.corpus.audit import AuditError, audit
from joker.models import Attack, DefensePattern, Goal, Origin, Technique


def _to_attack(d: dict, source: str) -> Attack:
    try:
        return Attack(
            id=str(d["id"]),
            technique=Technique(d["technique"]),
            goal=Goal(d.get("goal", "INFO_LEAK")),
            text=str(d["text"]),
            principle=str(d.get("principle", "")),
            screening=bool(d.get("screening", False)),
            ko_native=bool(d.get("ko_native", False)),
            ko_native_reason=(d.get("ko_native_reason") or None),
            author=str(d.get("author", "")),
            # origin 미기재 = AI 초안으로 본다(사람 작성이라고 주장하지 않는 쪽이 안전)
            origin=Origin(d.get("origin", Origin.AI_DRAFT.value)),
            reviewed_by=str(d.get("reviewed_by", "")),
            validated=bool(d.get("validated", False)),
        )
    except KeyError as e:
        raise AuditError(f"{source}: 필수 필드 누락 {e} (id={d.get('id', '?')})") from e
    except ValueError as e:
        raise AuditError(f"{source}: 허용되지 않는 값 ({e}) (id={d.get('id', '?')})") from e


def _read_file(path: Path) -> list[Attack]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise AuditError(f"{path.name}: 최상위가 리스트가 아니다 (- id: ... 형태여야 함)")
    return [_to_attack(d, path.name) for d in raw]


def load_attacks(paths: list[str | Path], *, run_audit: bool = True) -> list[Attack]:
    """여러 YAML 파일/폴더에서 공격을 모아 로드. 폴더면 *.yaml 을 정렬해 읽는다."""
    attacks: list[Attack] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for f in sorted(p.glob("*.yaml")):
                attacks.extend(_read_file(f))
        elif p.exists():
            attacks.extend(_read_file(p))
    if run_audit:
        violations = audit(attacks)
        if violations:
            raise AuditError("공격 시드 검증 실패:\n  - " + "\n  - ".join(violations))
    return attacks


def load_patterns(path: str | Path) -> list[DefensePattern]:
    """방어 패턴 카탈로그(patterns.yaml) 로드."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    patterns: list[DefensePattern] = []
    for d in raw:
        try:
            patterns.append(
                DefensePattern(
                    id=str(d["id"]),
                    name=str(d["name"]),
                    targets=tuple(Technique(t) for t in d.get("targets", [])),
                    template=str(d["template"]),
                    rationale=str(d.get("rationale", "")),
                )
            )
        except (KeyError, ValueError) as e:
            raise AuditError(f"방어 패턴 파싱 실패({d.get('id', '?')}): {e}") from e
    return patterns


def load_default_corpus(data_dir: str | Path = "data/attacks", *, run_audit: bool = True) -> list[Attack]:
    """표준 위치의 코퍼스를 전부 로드: core_25 + indirect_doc + segmented + ko_native/*.

    ★ 파일을 명시 나열하는 이유(글롭으로 안 하는 이유): 코퍼스에 뭐가 들어가는지가 곧 헤드라인
      수치의 분모다. 폴더에 파일을 떨구는 것만으로 수치가 조용히 바뀌면 안 된다.
    """
    base = Path(data_dir)
    paths: list[str | Path] = [
        base / "core_25.yaml",
        base / "indirect_doc.yaml",
        base / "segmented.yaml",   # 2026-08-27 신설 — SEGMENTED 채널 근거 시드
        base / "ko_native",
    ]
    return load_attacks(paths, run_audit=run_audit)
