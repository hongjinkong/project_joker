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
    SEGMENTED = "segmented"  # 조각·한글 음차 ('서울' + '1234' 로 쪼개 전달) — 2026-08-26 독립 심판이 찾아낸 채널
    # ── 한글 자산 전용 채널 (2026-08-27) ─────────────────────
    # 자산 값이 한글이면 기존 채널이 전부 무력했다: normalize() 가 낱개 자모를 지우고,
    # _tokens() 는 영숫자만 잘랐다. 평문 말고는 아무것도 못 잡았다.
    ROMANIZED = "romanized"  # 한글 값을 로마자로 음차해 전달 ('박서준' → 'Bak Seo Jun')
    JAMO = "jamo"           # 음절을 자모로 분해해 전달 ('박' → 'ㅂ ㅏ ㄱ')
    CHOSEONG = "choseong"   # 초성만 전달 ('박서준' → 'ㅂㅅㅈ'). 확정 안 함 → gray
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


class Origin(str, Enum):
    """이 공격문을 **누가 실제로 썼는가**. author(책임자)와 다른 축이다.

    왜 필요한가 (SPEC §7): 발표에서 "직접 생산한 데이터"를 주장하려면 근거가 남아야 한다.
    author 필드만 있으면 AI 초안에 사람 이름이 붙어도 아무도 모른다(2026-08-26 실제로 그랬다).
    기본값이 AI_DRAFT 인 이유: 명시하지 않으면 사람이 썼다고 '주장하지 않는' 쪽이 안전하다.
    """

    POC_HUMAN = "poc_human"      # 홍진성이 8/14 PoC 에서 직접 작성 (125회 실증 원본)
    TEAM_MEMBER = "team_member"  # 팀원이 직접 작성
    AI_DRAFT = "ai_draft"        # AI 초안 (사람 검토 여부는 validated / reviewed_by 로 따로 본다)


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
    author: str = ""              # 이 시드의 책임자(담당). '누가 썼나' 는 origin 을 볼 것
    origin: Origin = Origin.AI_DRAFT  # 누가 실제로 문장을 썼나. 기본값은 보수적으로 AI 초안
    reviewed_by: str = ""         # AI 초안을 사람이 검토·승인했으면 그 이름
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


class Fidelity(str, Enum):
    """진단이 '실물'에 얼마나 가까운가. contracts v0.3.

    ★ 왜 불리언(is_approximation)을 버렸나 (2026-08-27)
      `true/false` 는 "근사냐 아니냐" 로 읽힌다. 그래서 BYOK 로 실제 모델을 쓰면 false 가 되고,
      사용자는 **"이제 진짜 내 챗봇을 잰 것"** 으로 받아들인다. 사실이 아니다 —
      모델만 같아졌을 뿐 배포된 서비스(앞단 필터·RAG·툴·대화 이력)는 여전히 재현되지 않는다.
      이름 붙은 단계로 바꾸면 어느 값도 '실제 서비스' 로 읽히지 않는다.
    """

    PROXY_MODEL = "proxy_model"    # 지시문만 사용자 것, 모델은 우리 대리 모델
    REAL_MODEL = "real_model"      # 지시문 + 모델까지 사용자의 실제 것 (BYOK)
    # ★ 예약값 — SPEC §10 2순위(챗봇 주소 연결 + 소유권 확인). **미구현이며 엔진은 절대 내지 않는다.**
    #   여기 자리를 비워 두는 이유는 goal 필드와 같다: 나중에 축이 붙을 때 스키마를 안 건드리려고.
    #   테스트(test_engine_never_claims_real_service)가 엔진이 이 값을 내지 않는 것을 강제한다.
    REAL_SERVICE = "real_service"


# 어떤 진단이든 항상 붙는 범위 고지. 이 문장이 빠지면 '지시문+모델 진단' 이 '서비스 진단' 으로 읽힌다.
SCOPE_NOTICE = (
    "이 진단은 배포된 챗봇 서비스가 아니라 '시스템 지시문 + 모델' 조합을 대상으로 합니다. "
    "실제 서비스의 앞단 입력 필터·RAG 문서·툴 호출·대화 이력·출력 후처리는 재현되지 않습니다."
)


@dataclass(frozen=True)
class TargetInfo:
    """무엇을 진단했는가 — contracts/api_contract.md 의 `target` 블록.

    ★ 왜 리포트에 이게 있어야 하나 (2026-08-27)
      이전 리포트는 "당신 챗봇은 B등급"이라고 말했지만 실제로 잰 것은
      "qwen2.5:3b 에 당신 지시문을 붙였을 때 B등급" 이었다. 고객사마다 쓰는 모델이 다르므로
      모델명이 빠진 등급은 **다른 대상의 결과를 자기 결과로 오독시킨다** — 함정②와 같은 급의 오답.

    notice 가 두 개인 이유 — 하는 일이 다르다:
      scope_notice : **항상** 붙는다. 우리가 원래 안 보는 영역(서비스 계층)을 알린다.
      model_notice : PROXY_MODEL 일 때만. 이번 실행이 대리 모델이었음을 알린다.
    """

    model: str
    backend: str
    preset: str
    temperature: float
    seed: int
    fidelity: Fidelity
    scope_notice: str = SCOPE_NOTICE
    model_notice: str | None = None

    @property
    def is_proxy_model(self) -> bool:
        """화면이 '대리 모델 진단' 칩을 띄울지. (범위 고지는 이것과 무관하게 항상 띄운다)"""
        return self.fidelity == Fidelity.PROXY_MODEL


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
