"""detector/evaluate.py 의 지표 계산 — sklearn 없이 같은 값이 나오는가.

왜 테스트하나: 평가 지표는 발표에 그대로 인용되는 숫자다. sklearn 의존을 걷어내면서
공식이 어긋나면 지금까지 보고한 F1(0.981 등)과 다른 값이 조용히 나온다.
sklearn 이 설치돼 있으면 그 결과와 직접 대조하고, 없으면 손계산 기대값과 대조한다.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[1] / "detector" / "evaluate.py"
_spec = importlib.util.spec_from_file_location("evaluate", _PATH)
ev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ev)  # type: ignore[union-attr]

CASES = [
    ([1, 1, 1, 1, 0, 0, 0, 0], [1, 1, 0, 1, 0, 1, 0, 0]),
    ([1, 1, 0, 0], [1, 1, 0, 0]),
    ([1, 1, 1], [0, 0, 0]),
    ([0, 0, 0], [0, 0, 0]),
    ([1] * 49, [1] * 39 + [0] * 10),        # OOD 형태(정상 0건)
]


def test_confusion_counts():
    p, r, f, acc, tn, fp, fn, tp = ev._binary_metrics([1, 1, 1, 1, 0, 0, 0, 0],
                                                      [1, 1, 0, 1, 0, 1, 0, 0])
    assert (tp, fp, fn, tn) == (3, 1, 1, 3)
    assert p == r == f == acc == 0.75


def test_no_zero_division_anywhere():
    for y, pred in CASES:
        vals = ev._binary_metrics(y, pred)
        assert all(v == v for v in vals)          # NaN 없음
        assert all(0.0 <= v <= 1.0 for v in vals[:4])


def test_attack_only_set_gives_recall_and_precision_one():
    p, r, f, acc, tn, fp, fn, tp = ev._binary_metrics([1] * 49, [1] * 39 + [0] * 10)
    assert p == 1.0, "정상 표본이 없으면 FP 가 0 이라 정밀도는 1.0 — 성능이 아니라 구조적 결과다"
    assert abs(r - 39 / 49) < 1e-12 and fn == 10


@pytest.mark.parametrize("y,pred", CASES)
def test_matches_sklearn_when_available(y, pred):
    sk = pytest.importorskip("sklearn.metrics", reason="sklearn 은 학습 환경에만 있다")
    p, r, f, acc, *_ = ev._binary_metrics(y, pred)
    sp, sr, sf, _ = sk.precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    assert abs(p - sp) < 1e-12 and abs(r - sr) < 1e-12 and abs(f - sf) < 1e-12
    assert abs(acc - sk.accuracy_score(y, pred)) < 1e-12
