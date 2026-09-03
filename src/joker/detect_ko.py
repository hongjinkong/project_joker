"""JOKER-KO 입력단 탐지기 — "이 입력이 한국어 프롬프트 인젝션인가?"의 얇은 래퍼.

엔진(joker)은 가벼워야 한다(SPEC: detector/ 를 일부러 분리했다). 그래서:
- 이 모듈은 top-level 에서 torch/transformers 를 import 하지 않는다 → 엔진·테스트는 이 파일을
  import 해도 무거운 의존성 없이 돈다. 실제 추론(classify)을 호출하는 순간에만 lazy import.
- 학습 모델(detector/artifacts/joker-ko, .gitignore)은 PC마다 없을 수 있다 → 없으면 조용히
  죽지 않고 `DetectorUnavailable` 로 '무엇을 하면 되는지'를 알려준다.
- 추론 함수를 주입(predict_fn)할 수 있어, torch 없는 환경(CI·브리지)에서도 판정 로직을 테스트한다.

역할 분리: 이 탐지기 = 입력단(공격인가?). 기존 detect/rules = 출력단(값이 유출됐나?). 안 겹친다.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

# 엔진 패키지 루트(src/joker/detect_ko.py) → repo 루트(model/)는 parents[2].
_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = _REPO_ROOT / "detector" / "artifacts" / "joker-ko"

MAX_CHARS = 20000  # 한 건 입력 상한(과도한 페이로드 방어). 토크나이저 max_len 과 별개.


class DetectorUnavailable(RuntimeError):
    """모델 파일이 없거나 torch/transformers 가 없어 추론을 못 하는 상태. (엔진 오류 아님)"""


@dataclass(frozen=True)
class Detection:
    """한 건 분류 결과. score = INJECTION(공격) 확률."""

    label: str          # "SAFE" | "INJECTION"
    score: float        # 0.0~1.0, 공격일 확률
    threshold: float
    is_injection: bool
    model: str          # 사용한 모델 경로(문자열)


def _positive_index(id2label: dict) -> int:
    """공격(양성) 라벨의 인덱스. 우리 모델은 {0:SAFE,1:INJECTION} 라 1.

    이름에 inject/malicious 등이 있으면 그걸, 없으면(LABEL_0/1 처럼 무의미하면) 마지막 인덱스.
    """
    for idx, name in id2label.items():
        if any(k in str(name).lower() for k in ("inject", "malicious", "jailbreak", "unsafe", "attack")):
            return int(idx)
    return max(int(i) for i in id2label)


class KoDetector:
    """파인튜닝된 JOKER-KO 로 입력을 SAFE/INJECTION 분류한다.

    model_path : 파인튜닝 모델 폴더. 미지정 시 env JOKER_DETECTOR_PATH → 없으면 기본 경로.
    threshold  : 이 확률 이상이면 INJECTION.
    predict_fn : 주입용. (list[str]) -> list[float] (공격확률). 테스트/대체 백엔드용.
                 미지정 시 첫 classify 에서 transformers 백엔드를 lazy 로 만든다.
    max_len    : 토큰 상한(Prompt Guard 2 = 512).
    """

    def __init__(
        self,
        model_path: str | os.PathLike | None = None,
        threshold: float = 0.5,
        predict_fn: Callable[[list[str]], Sequence[float]] | None = None,
        max_len: int = 512,
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold 는 0.0~1.0 이어야 한다")
        if model_path is None:
            model_path = os.environ.get("JOKER_DETECTOR_PATH") or DEFAULT_MODEL_PATH
        self.model_path = Path(model_path)
        self.threshold = float(threshold)
        self.max_len = int(max_len)
        self._predict_fn = predict_fn
        # transformers 백엔드 캐시(한 번만 로드)
        self._model = None
        self._tok = None
        self._pos = 1

    # ── 공개 API ────────────────────────────────────────────
    def available(self) -> bool:
        """추론이 가능한 상태인가(모델 파일 + 의존성). 실제 로드는 안 한다 — 가볍게 확인만."""
        if self._predict_fn is not None:
            return True
        if not self.model_path.exists():
            return False
        import importlib.util
        return all(importlib.util.find_spec(m) is not None for m in ("torch", "transformers"))

    def classify(self, text: str) -> Detection:
        """한 건 분류."""
        return self.classify_many([text])[0]

    def classify_many(self, texts: Sequence[str]) -> list[Detection]:
        """여러 건 분류. 빈 문자열·비문자열은 ValueError."""
        if isinstance(texts, (str, bytes)):
            raise TypeError("classify_many 에는 문자열 리스트를 준다(단건은 classify).")
        clean: list[str] = []
        for t in texts:
            if not isinstance(t, str) or not t.strip():
                raise ValueError("빈 텍스트는 분류할 수 없습니다.")
            if len(t) > MAX_CHARS:
                raise ValueError(f"입력이 너무 깁니다(>{MAX_CHARS}자).")
            clean.append(t)
        if not clean:
            return []
        fn = self._predict_fn or self._default_predict
        scores = list(fn(clean))
        if len(scores) != len(clean):
            raise RuntimeError("예측 개수가 입력 개수와 다릅니다.")
        return [self._make(t, s) for t, s in zip(clean, scores)]

    # ── 내부 ────────────────────────────────────────────────
    def _make(self, text: str, score: float) -> Detection:
        s = float(score)
        is_inj = s >= self.threshold
        return Detection(
            label="INJECTION" if is_inj else "SAFE",
            score=s, threshold=self.threshold, is_injection=is_inj,
            model=str(self.model_path),
        )

    def _default_predict(self, texts: list[str]) -> list[float]:
        """transformers 백엔드(lazy). 의존성/모델이 없으면 DetectorUnavailable."""
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as e:  # torch/transformers 미설치
            raise DetectorUnavailable(
                'torch/transformers 가 없습니다 — pip install -e ".[detect]" '
                "(또는 detector/requirements.txt). "
                f"원인: {e}"
            ) from e
        if not self.model_path.exists():
            raise DetectorUnavailable(
                f"학습된 탐지 모델이 없습니다: {self.model_path}. "
                "먼저 detector/train.py 로 학습하세요(GPU 필요). "
                "학습 산출물은 .gitignore 라 PC마다 따로 만듭니다."
            )
        if self._model is None:
            self._tok = AutoTokenizer.from_pretrained(str(self.model_path))
            self._model = AutoModelForSequenceClassification.from_pretrained(str(self.model_path))
            self._model.eval()
            self._pos = _positive_index(self._model.config.id2label)
        probs: list[float] = []
        with torch.no_grad():
            for i in range(0, len(texts), 32):
                batch = self._tok(
                    texts[i:i + 32], truncation=True, max_length=self.max_len,
                    padding=True, return_tensors="pt",
                )
                p = torch.softmax(self._model(**batch).logits, dim=-1)[:, self._pos]
                probs.extend(float(x) for x in p.tolist())
        return probs


def detect_payload(detector: KoDetector, text) -> dict:
    """API 응답용 dict. 입력 원문은 되돌려 담지 않는다(비밀값 포함 가능 → 유출 방지).

    ValueError(잘못된 입력) / DetectorUnavailable(모델 없음)은 호출부가 상태코드로 매핑한다.
    """
    d = detector.classify(text)
    return {
        "label": d.label,
        "score": round(d.score, 4),
        "is_injection": d.is_injection,
        "threshold": d.threshold,
        "model": Path(d.model).name,
    }
