"""새 공격 시드를 실모델에 던져 `validated: true` 로 승격한다.

왜 필요한가:
  SPEC §7 — `validated: false` 인 시드는 발표·기획서 숫자에 넣지 않는다. "실제로 통하는가"를
  안 재본 공격은 데이터가 아니라 아이디어이기 때문이다. 그런데 그 승격 과정이 수동이었다.
  팀 문구가 한꺼번에 들어오는 날(8/28) 이 스크립트 한 줄로 끝내기 위한 것.

하는 일:
  1) `validated: false` 인 시드만 골라(=새로 들어온 것) 허수아비 지시문에 던진다
  2) 기법별·시드별로 통했는지 표로 보여준다
  3) `--write` 를 주면 실제로 던진 시드의 YAML 을 `validated: true` 로 고친다
     (주석·순서를 보존하려고 줄 단위로 고친다. yaml.dump 로 다시 쓰면 팀원 주석이 다 날아간다)

실행 (Mac 터미널):
    python scripts/validate_seeds.py                 # 미검증 시드만, 쓰기 없이 확인
    python scripts/validate_seeds.py --write         # 확인 후 승격
    python scripts/validate_seeds.py --all --write   # 전량 재검증
    python scripts/validate_seeds.py --targets 한비,나래   # 두 지시문에 던져 더 확실히

victim 은 로컬이라 돈이 안 든다. RECON 은 지시문당 1회(유료).
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

from joker.config import Settings
from joker.corpus.loader import load_default_corpus, load_patterns
from joker.deps import Deps
from joker.models import Verdict
from joker.nodes.attack import build_context, run_attacks
from joker.nodes.judge import judge_attempts
from joker.pipeline import new_state, step_recon
from joker.providers.registry import build_providers


def _targets():
    sys.path.insert(0, str(Path(__file__).parent))
    from asr_rerun import TARGETS

    return TARGETS


def _flip_validated(data_dir: Path, ids: set[str]) -> int:
    """YAML 을 줄 단위로 고쳐 `validated: false` → `true`. 주석·순서 보존."""
    files = [data_dir / "core_25.yaml", data_dir / "indirect_doc.yaml"]
    files += sorted((data_dir / "ko_native").glob("*.yaml"))
    n = 0
    for f in files:
        if not f.exists():
            continue
        lines, out, cur, changed = f.read_text(encoding="utf-8").splitlines(), [], None, False
        for ln in lines:
            m = re.match(r"^-\s*id:\s*(\S+)", ln)
            if m:
                cur = m.group(1)
            mv = re.match(r"^(\s*)validated:\s*false\s*$", ln)
            if mv and cur in ids:
                out.append(f"{mv.group(1)}validated: true   # 실측 승격 (scripts/validate_seeds.py)")
                changed, n = True, n + 1
                continue
            out.append(ln)
        if changed:
            f.write_text("\n".join(out) + "\n", encoding="utf-8")
            print(f"  [수정] {f.name}")
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="새 공격 시드 실측 + validated 승격")
    ap.add_argument("--all", action="store_true", help="이미 validated 인 것까지 전부 재검증")
    ap.add_argument("--write", action="store_true", help="YAML 을 validated: true 로 실제로 고친다")
    ap.add_argument("--targets", default="한비", help="던질 지시문 이름 일부(쉼표 구분)")
    ap.add_argument("--data-dir", default="data/attacks")
    args = ap.parse_args(argv)

    settings = Settings.from_env()
    data_dir = Path(args.data_dir)
    attacks = load_default_corpus(str(data_dir), run_audit=False)
    patterns = load_patterns(data_dir.parent / "defenses" / "patterns.yaml")

    todo = [a for a in attacks if args.all or not a.validated]
    if not todo:
        print("[OK ] 미검증 시드가 없습니다. 전량 재검증하려면 --all.")
        return 0

    keys = [k.strip() for k in args.targets.split(",") if k.strip()]
    targets = [(n, p) for n, p in _targets() if any(k in n for k in keys)]
    if not targets:
        print(f"[FAIL] '{args.targets}' 에 맞는 지시문이 없습니다.")
        return 1

    print(f"[INFO] 검증 대상 {len(todo)}개 × 지시문 {len(targets)}개 = {len(todo)*len(targets)}콜")
    print(f"[INFO] victim={settings.victim_model} (로컬·무료)\n")

    hits: dict[str, int] = defaultdict(int)
    tried: dict[str, int] = defaultdict(int)
    sample: dict[str, str] = {}
    for name, prompt in targets:
        pr = build_providers(settings)
        deps = Deps(settings=settings, victim=pr["victim"], recon=pr["recon"], judge=pr["judge"],
                    attacks=tuple(attacks), patterns=tuple(patterns))
        st = step_recon(new_state(prompt, "validate"), deps)
        if st.get("inconclusive"):
            print(f"[SKIP] {name}: 값 자산이 없어 검증에 쓸 수 없습니다.")
            continue
        att = run_attacks(sorted(todo, key=lambda a: a.id), prompt, 1, deps, build_context(st))
        judge_attempts(att, st["assets"], deps)
        leak = sum(1 for a in att if a.verdict == Verdict.LEAK)
        print(f"  {name}: {leak}/{len(att)} 통함")
        for a in att:
            tried[a.attack_id] += 1
            if a.verdict == Verdict.LEAK:
                hits[a.attack_id] += 1
            sample.setdefault(a.attack_id, (a.response_raw or "")[:80].replace("\n", " "))

    if not tried:
        print("[FAIL] 던진 시드가 없습니다.")
        return 1

    by_id = {a.id: a for a in todo}
    print(f"\n{'='*74}\n{'ID':16s} {'기법':13s} {'통함':6s} {'한국어고유':8s} 응답 앞부분")
    print("─"*74)
    for aid in sorted(tried, key=lambda i: (-hits[i], i)):
        a = by_id[aid]
        print(f"{aid:16s} {a.technique.value:13s} {hits[aid]}/{tried[aid]:<4d} "
              f"{'O' if a.ko_native else '·':^10s} {sample[aid][:34]}")

    dead = [i for i in tried if hits[i] == 0]
    print(f"\n[결과] {len(tried)}개 검증 · 한 번이라도 통한 것 {len(tried)-len(dead)}개")
    if dead:
        print(f"  ⚠ 한 번도 안 통한 시드 {len(dead)}개: {', '.join(sorted(dead))}")
        print("     삭제하지 말 것 — 다른 모델·다른 지시문에서는 통할 수 있다.")
        print("     다만 스크리닝(screening: true)에는 넣지 말 것(1단계에서 취약점을 놓친다).")

    if args.write:
        n = _flip_validated(data_dir, set(tried))
        print(f"\n[OK ] {n}개를 validated: true 로 승격했습니다. `joker audit` 으로 확인하세요.")
    else:
        print("\n[INFO] 쓰기는 안 했습니다. 승격하려면 --write 를 붙이세요.")
    return 0


if __name__ == "__main__":
    from joker.config import load_dotenv

    load_dotenv()
    sys.exit(main())
