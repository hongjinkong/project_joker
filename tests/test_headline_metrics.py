"""화면에 띄우는 실측 수치의 단일 출처 — data/evidence/headline_metrics.json.

무엇을 지키나:
  · **조건 없는 숫자를 화면에 못 올린다.** 모든 지표는 condition(측정 조건)과 source(근거 문서)를
    가져야 한다. "81.6%"만 크게 띄우고 n 과 조건을 빼면 그 순간 과장이 된다.
  · 한계(limitations)가 비어 있지 않다 — 성능만 있고 한계가 없는 화면은 신뢰를 잃는다.
  · UI 가 이 파일을 실제로 읽을 수 있다(경로·인코딩).
  · 화면(ui/)은 여전히 joker 를 import 하지 않는다 — 파일을 읽는 것과 엔진을 부르는 것은 다르다.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PATH = REPO / "data" / "evidence" / "headline_metrics.json"

REQUIRED = ("key", "label", "value", "detail", "condition", "source")


def _load() -> dict:
    return json.loads(PATH.read_text(encoding="utf-8"))


def test_file_exists_and_parses():
    assert PATH.exists(), "화면이 읽는 수치 파일이 없으면 대시보드가 빈다"
    assert _load()["metrics"], "지표가 비어 있다"


def test_every_metric_has_condition_and_source():
    for m in _load()["metrics"]:
        for field in REQUIRED:
            assert m.get(field), f"{m.get('key')} 에 {field} 가 없다 — 조건·근거 없는 숫자는 화면에 올리지 않는다"
        assert len(m["condition"]) > 10, f"{m['key']} 의 condition 이 너무 짧다(형식적 채움 금지)"


def test_metric_keys_are_unique():
    keys = [m["key"] for m in _load()["metrics"]]
    assert len(keys) == len(set(keys))


def test_limitations_are_present():
    lim = _load().get("limitations") or []
    assert len(lim) >= 3, "한계가 3개 미만이면 '성능만 있는 화면'이 된다"
    assert all(len(x) > 20 for x in lim)


def test_ui_reads_the_same_path():
    src = (REPO / "ui" / "streamlit_app.py").read_text(encoding="utf-8")
    assert "headline_metrics.json" in src, "UI 가 다른 경로를 보면 화면과 근거가 어긋난다"
    assert "import joker" not in src and "from joker" not in src, "화면은 엔진을 import 하지 않는다"
