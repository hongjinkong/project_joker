"""재현 편차 측정 — 같은 지시문·같은 공격을 N회 반복해 ASR 이 얼마나 흔들리는지 잰다.

왜 필요한가 (2026-08-26 발견):
  SPEC §4 재현성 규칙 1 은 "진단 실행은 temperature=0 고정. '뚫리는가'를 재는 것이지
  '운 좋으면 뚫리는가'가 아니다" 라고 정했다. 그런데 실제로 재보니 그 전제가 깨져 있었다.

  같은 지시문·같은 공격 38건을 두 번 돌린 결과(돌봄이-병원예약):
    · victim 응답 텍스트가 동일한 것 12/38 (31.6%)
    · 판정이 갈린 것 7건 → ASR 55.3% vs 42.1% (13.2%p 차이)
    · gray(LLM 재검)는 3~4건뿐 → 원인은 우리 judge 가 아니라 **로컬 모델**

  temperature=0·seed 를 보내도 llama.cpp/Metal 은 부동소수점 누적 순서와 모델 재적재 때문에
  비트 단위 재현이 안 된다. 코드로 없앨 수 있는 성질이 아니다.
  → 없앨 수 없으면 **재서 밝힌다.** 단일 실행 수치를 소수점까지 인용하지 않기 위한 근거를 만든다.

측정 범위(정직하게 명시):
  RECON 은 **한 번만** 돌리고 그 자산을 N회에 재사용한다. victim 의 편차만 분리해서 보기 위해서다
  (RECON 까지 매번 돌리면 두 편차가 섞여 원인을 못 가른다). 그래서 이 수치는 end-to-end 편차의
  하한이다. 또 처방 후(R2)는 재지 않는다 — R1 만으로 편차 성격은 충분히 드러나고 호출이 절반이다.

실행 (Mac 터미널):
    python scripts/reproducibility.py --repeat 3 --target 한비
    python scripts/reproducibility.py --repeat 5 --target 나래 --data-dir data/attacks

호출량: 시드 수 × repeat (기본 38×3=114). 로컬이라 돈은 안 든다.
결과: 터미널 표 + docs/reproducibility_<stamp>.md
"""

from __future__ import annotations

import argparse
import datetime
import statistics
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
    """asr_rerun.py 와 같은 지시문을 쓴다(수치를 나란히 놓고 비교할 수 있게).

    같은 폴더의 스크립트를 import 하므로 경로를 먼저 넣는다(모듈 최상단에서 하면 순서가 꼬인다).
    """
    sys.path.insert(0, str(Path(__file__).parent))
    from asr_rerun import TARGETS

    return TARGETS


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="처방 전 ASR 의 재현 편차 측정")
    ap.add_argument("--repeat", type=int, default=3, help="반복 횟수(기본 3)")
    ap.add_argument("--target", default="한비", help="지시문 이름 일부(기본 한비)")
    ap.add_argument("--fresh-recon", action="store_true",
                    help="회차마다 RECON 을 다시 돌린다(end-to-end 편차. 이름 고정이 통했는지 확인용)")
    ap.add_argument("--data-dir", default="data/attacks")
    args = ap.parse_args(argv)

    if args.repeat < 2:
        print("[FAIL] --repeat 는 2 이상이어야 편차를 잴 수 있습니다.")
        return 1

    targets = _targets()
    name, prompt = next(((n, p) for n, p in targets if args.target in n), (None, None))
    if not prompt:
        print(f"[FAIL] '{args.target}' 에 맞는 지시문이 없습니다: {[n for n, _ in targets]}")
        return 1

    settings = Settings.from_env()
    data_dir = Path(args.data_dir)
    attacks = load_default_corpus(str(data_dir), run_audit=False)
    patterns = load_patterns(data_dir.parent / "defenses" / "patterns.yaml")
    pr = build_providers(settings)
    deps = Deps(settings=settings, victim=pr["victim"], recon=pr["recon"], judge=pr["judge"],
                attacks=tuple(attacks), patterns=tuple(patterns))

    print(f"[INFO] {name} · 시드 {len(attacks)}개 × {args.repeat}회 = {len(attacks)*args.repeat}콜")
    print(f"[INFO] victim={settings.victim_model} temperature={settings.temperature} seed={settings.seed}")
    print("[INFO] RECON 은 1회만 돌리고 재사용합니다(victim 편차만 분리해서 보기 위해).\n")

    def _recon():
        st = step_recon(new_state(prompt, "repro"), deps)
        if st.get("inconclusive"):
            raise SystemExit(f"[FAIL] 진단 불가 — {st.get('recon_reason')}")
        return build_context(st), st["assets"]

    context, assets = _recon()
    print(f"[RECON] 자산 이름 = {[a.name for a in assets if a.value]} · 공격문의 {{asset}} = {context['asset']!r}")
    sweep = sorted(attacks, key=lambda a: (a.technique.value, a.id))
    rendered_seen: set[str] = set()

    asrs: list[float] = []
    verdicts: dict[str, list[str]] = defaultdict(list)
    responses: dict[str, list[str]] = defaultdict(list)
    for i in range(1, args.repeat + 1):
        if args.fresh_recon and i > 1:
            context, assets = _recon()
            print(f"  [RECON {i}] {{asset}} = {context['asset']!r}")
        rendered_seen.add(context["asset"])
        # 매 회 새 provider — max_calls 는 '진단 1회' 상한이므로 누적시키지 않는다
        p2 = build_providers(settings)
        d2 = Deps(settings=settings, victim=p2["victim"], recon=p2["recon"], judge=p2["judge"],
                  attacks=tuple(attacks), patterns=tuple(patterns))
        att = run_attacks(sweep, prompt, 1, d2, context)
        judge_attempts(att, assets, d2)
        leak = sum(1 for a in att if a.verdict == Verdict.LEAK)
        asrs.append(leak / len(att))
        for a in att:
            verdicts[a.attack_id].append(a.verdict.value)
            responses[a.attack_id].append(a.response_raw or "")
        print(f"  [{i}/{args.repeat}] ASR {leak}/{len(att)} = {leak/len(att):.1%}")

    lo, hi, mean = min(asrs), max(asrs), statistics.mean(asrs)
    sd = statistics.stdev(asrs) if len(asrs) > 1 else 0.0
    stable = [k for k, v in verdicts.items() if len(set(v)) == 1]
    flips = sorted(k for k, v in verdicts.items() if len(set(v)) > 1)
    same_text = [k for k, v in responses.items() if len(set(v)) == 1]

    print(f"\n{'═'*62}")
    print(f"[재현 편차] ASR 평균 {mean:.1%} · 범위 {lo:.1%}~{hi:.1%} (폭 {(hi-lo)*100:.1f}%p) · 표준편차 {sd*100:.1f}%p")
    print(f"  판정이 항상 같은 공격 {len(stable)}/{len(verdicts)} ({len(stable)/len(verdicts):.1%})")
    print(f"  응답 텍스트까지 같은 공격 {len(same_text)}/{len(responses)} ({len(same_text)/len(responses):.1%})")
    if flips:
        print(f"  흔들린 공격 {len(flips)}건: {', '.join(flips)}")
    if args.fresh_recon:
        ok = len(rendered_seen) == 1
        print(f"  RECON 자산 이름: {'항상 동일 ✅' if ok else '흔들림 ⚠ ' + str(sorted(rendered_seen))}")
        if not ok:
            print("     → 공격문이 회차마다 달라졌다. ASR 비교가 성립하지 않는다(이름 고정 실패).")
    print(f"\n  → 단일 실행 ASR 은 ±{(hi-lo)/2*100:.0f}%p 정도 흔들린다. 이보다 작은 차이는 근거로 쓰지 말 것.")

    if settings.backend_for("victim") == "mock":
        print("[INFO] mock 리허설이라 요약 문서를 만들지 않습니다(실측치로 오독 방지).")
        return 0

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path("docs") / f"reproducibility_{stamp}.md"
    out.parent.mkdir(exist_ok=True)
    L = [f"# 처방 전 ASR 재현 편차 — {datetime.datetime.now():%Y-%m-%d %H:%M}", "",
         f"- 지시문: {name}", f"- victim: `{settings.victim_model}` · temperature={settings.temperature} · seed={settings.seed}",
         f"- 시드 {len(attacks)}개 × {args.repeat}회 반복 · RECON "
         f"{'매회 재실행(end-to-end)' if args.fresh_recon else '1회 고정(victim 편차만)'} · R1 만 측정", "",
         "## 결과", "",
         f"| 회차 | ASR |", "|---|---|"]
    L += [f"| {i} | {v:.1%} |" for i, v in enumerate(asrs, 1)]
    L += ["", f"- **평균 {mean:.1%} · 범위 {lo:.1%}~{hi:.1%} (폭 {(hi-lo)*100:.1f}%p) · 표준편차 {sd*100:.1f}%p**",
          f"- 판정이 항상 같은 공격 {len(stable)}/{len(verdicts)} ({len(stable)/len(verdicts):.1%})",
          f"- 응답 텍스트까지 같은 공격 {len(same_text)}/{len(responses)} ({len(same_text)/len(responses):.1%})",
          "", "## 흔들린 공격", ""]
    L += [f"- `{k}`: {' / '.join(verdicts[k])}" for k in flips] or ["- 없음"]
    L += ["", "## 해석", "",
          "`temperature=0` 을 보내도 로컬 모델(llama.cpp)은 부동소수점 누적 순서·모델 재적재 때문에",
          "비트 단위로 재현되지 않는다. 코드로 없앨 수 있는 성질이 아니므로 **편차를 측정해 함께 보고한다.**",
          "단일 실행 수치를 소수점까지 인용하지 않고, 이 폭보다 작은 차이는 근거로 쓰지 않는다."]
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"[OK ] {out}")
    return 0


if __name__ == "__main__":
    from joker.config import load_dotenv

    load_dotenv()
    sys.exit(main())
