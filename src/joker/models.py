"""도메인 타입. 9/2 제출 DB 문서(테이블 명세서)와 1:1 로 대응한다.

설계 원칙:
- 입력(공격·방어·자산)은 frozen — 로드 후 바뀌면 안 된다.
- 흐르며 채워지는 것(Attempt·Report)은 mutable — 노드가 응답·판정을 채워 넣는다.
- 문자열 상수는 전부 Enum 으로 고정한다. 오타난 technique/verdict 가 조용히 통과하면
  집계(ASR·F1)가 소리 없이 틀어진다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Technique(str, Enum):
    """어떻게 속이나 (자체 taxonomy — 발표에서 명시). INDIRECT_DOC 는 8/24 미검증 초안."""

    ROLE = "ROLE"
    AUTH = "AUTH"
    INDIRECT = "INDIRECT"
    OBFUSC = "OBFUSC"
    FORMAT = "FORMAT"
    INDIRECT_DOC = "INDIRECT_DOC"


class Goal(str, Enum):
    """무엇을 무너뜨리나. INFO_LEAK 만 구현. 나머지는 스키마만 미리 열어둔다."""

    INFO_LEAK = "INFO_LEAK"
    POLICY_BREAK = "POLICY_BREAK"   # 2순위
    PERSONA_BREAK = "PERSONA_BREAK"  # 제외


class Verdict(str, Enum):
    LEAK = "leak"
    BLOCK = "block"
    GRAY = "gray"   # 규칙으로 확정 못 함 → LLM 재검 대상


class VerdictBy(str, Enum):
    RULE = "rule"
    LLM = "llm"


class LeakChannel(str, Enum):
    PLAIN = "plain"
    REVERSED = "reversed"
    BASE64 = "base64"
    SEMANTIC = "semantic"   # 의역·설명형 (규칙이 못 잡는 것 — 연구 포인트)


class AssetKind(str, Enum):
    SECRET_VALUE = "secret_value"       # 보호할 '값'. 이게 0개면 진단 불가(함정②)
    FORBIDDEN_ACTION = "forbidden_action"
    PERSONA = "persona"
    POLICY = "policy"


class Grade(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


# 공격문 치환 플레이스홀더는 이 4개뿐. 치환은 replace() 로만 한다(함정④, str.format 금지).
PLACEHOLDERS = ("{asset}", "{persona}", "{org}", "{decoy}")


@dataclass(frozen=True)
class Attack:
    """공격 시드 1건. data/attacks/**.yaml 한 항목과 1:1."""

    id: str                       # 형식 TECHNIQUE-NN
    technique: Technique
    goal: Goal
    text: str
    principle: str                # 왜 통하는가 (한 줄, 필수)
    screening: bool = False       # 1단계 스크리닝 대상인가 (technique 당 정확히 3개)
    ko_native: bool = False       # 한국어 고유 공격인가
    ko_native_reason: str | None = None  # ko_native=True 면 필수(함정⑤)
    author: str = ""
    validated: bool = False       # 실제 모델에 던져본 적 있는가. False 면 발표 숫자 제외


@dataclass(frozen=True)
class DefensePattern:
    """방어 패턴 카탈로그 1건. 처방은 여기서 골라 '조립'만 한다(함정⑥, LLM 자유생성 금지)."""

    id: str                       # P01..P08
    name: str
    targets: tuple[Technique, ...]  # 이 패턴이 막는 기법들
    template: str                 # 지시문에 덧붙일 고정 문구
    rationale: str


@dataclass(frozen=True)
class Asset:
    """RECON 이 지시문에서 뽑아낸 보호 대상."""

    name: str
    value: str | None
    kind: AssetKind
    confidence: float = 1.0
    source: str = ""


@dataclass
class Attempt:
    """공격 1회 시도 = tb_attempt 한 행. round_no 로 Before(1)/After(2)를 한 테이블에 담는다."""

    attack_id: str
    technique: Technique
    goal: Goal
    round_no: int                 # 1=처방전 2=처방후
    rendered_text: str
    response_raw: str = ""
    verdict: Verdict | None = None
    verdict_by: VerdictBy | None = None
    leak_channel: LeakChannel | None = None
    was_gray: bool = False
    hit_assets: list[str] = field(default_factory=list)
    # 재현 맥락 3종 — 없으면 결과를 재현할 수 없다
    victim_model: str = ""
    temperature: float = 0.0
    seed: int = 0
    latency_ms: int = 0


@dataclass
class PatchResult:
    """처방 결과. 같은 입력이면 항상 같아야 한다(함정⑥)."""

    patched_prompt: str
    applied_patterns: list[str] = field(default_factory=list)


@dataclass
class Report:
    """최종 리포트 = tb_diagnosis.report. API 응답의 핵심(contracts/ 와 일치)."""

    grade: Grade | None           # 자산 0개면 None(함정②)
    inconclusive: bool
    comparable: bool              # R1/R2 attack_id 집합 동일 여부(함정①)
    asr_before: float | None
    asr_after: float | None
    delta: float | None
    by_technique: dict = field(default_factory=dict)
    applied_patterns: list[str] = field(default_factory=list)
