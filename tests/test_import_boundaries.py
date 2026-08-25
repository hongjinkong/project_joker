"""경계: 의존 방향은 단방향이다. 역방향 import 를 소스에서 정적으로 검출한다.

파일을 실제로 import 하지 않고 '텍스트'로 스캔한다 — 스텁이라도 통과 가능하고,
이 규칙 자체가 팀원에게 주는 문서가 된다. 지금 '통과(초록)'가 정상이다.

의존 방향: data(YAML) → corpus → nodes → pipeline → {store, api} → ui
  - nodes 는 providers 를 직접 import 하지 않는다(호출 객체 주입).
  - ui 는 joker 를 import 하지 않는다(HTTP 만).
  - 하위 공용(models/config/state)은 상위를 import 하지 않는다.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import joker

PKG = Path(joker.__file__).parent          # .../src/joker
REPO = PKG.parent.parent                    # .../model


def _src(rel: str) -> str:
    return (PKG / rel).read_text(encoding="utf-8")


def _imports_any(text: str, module_prefix: str) -> bool:
    pat = rf"^\s*(?:from|import)\s+{re.escape(module_prefix)}"
    return re.search(pat, text, re.MULTILINE) is not None


@pytest.mark.boundary
@pytest.mark.parametrize("node", ["recon", "attack", "judge", "patch", "report"])
def test_nodes_do_not_import_providers(node):
    text = _src(f"nodes/{node}.py")
    assert not _imports_any(text, "joker.providers"), (
        f"nodes/{node}.py 는 providers 를 직접 import 하면 안 된다(deps 로 주입)"
    )


@pytest.mark.boundary
def test_ui_does_not_import_engine():
    ui_dir = REPO / "ui"
    for f in ui_dir.glob("*.py"):
        text = f.read_text(encoding="utf-8")
        assert not _imports_any(text, "joker"), f"{f.name} 은 joker 를 import 하면 안 된다(HTTP 만)"


@pytest.mark.boundary
@pytest.mark.parametrize("lower", ["models.py", "config.py", "state.py"])
def test_shared_layer_does_not_import_upper(lower):
    text = _src(lower)
    for upper in ("joker.corpus", "joker.nodes", "joker.pipeline", "joker.store", "joker.api"):
        assert not _imports_any(text, upper), f"{lower} 이 {upper} 를 import 하면 안 된다(역방향 금지)"


@pytest.mark.boundary
def test_store_does_not_import_nodes_or_pipeline():
    for f in ("store/sqlite.py", "store/import_poc.py"):
        text = _src(f)
        assert not _imports_any(text, "joker.nodes")
        assert not _imports_any(text, "joker.pipeline")
