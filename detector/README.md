# JOKER-KO — 한국어 프롬프트 인젝션 1차 탐지기

기성 보안 모델 **Llama-Prompt-Guard-2-86M**(multilingual mDeBERTa)을 **우리 한국어 공격 데이터로
파인튜닝**해, 입력이 챗봇에 닿기 전 **1차로 공격을 걸러내는 탐지기**를 만든다.
입력단(공격인가?)을 보는 이 탐지기와, 기존 Judge(출력이 유출됐나?)는 역할이 달라 안 겹친다.

```
사용자 입력 → [JOKER-KO 탐지] → SAFE 통과 / 의심·공격 → 기존 Joker 엔진(정밀 판정·처방·재진단)
```

## 파일
```
detector/
  fetch_benign.py    공개데이터(open-korean-instructions·Chatbot_data)에서 정상 문장 대량 추출
  build_dataset.py   attacks.yaml + 정상 → train/val/test.jsonl (누수 방지 그룹 분할)
  train.py           Prompt Guard 2 → 파인튜닝 → artifacts/joker-ko/
  evaluate.py        baseline(원본) vs JOKER-KO(+ --extra 로 Kakao 벤치마크) F1 비교
  data/
    benign_seed.txt      정상 시드(직접 작성분 68개) — 팀원/공개데이터와 --benign 으로 합침
    benign_public.txt    fetch_benign.py 생성(대량)
    train/val/test.jsonl build_dataset.py 생성
```

## 실행 순서 (GPU 환경 = Colab / 학원 PC)
```bash
pip install -r detector/requirements.txt
huggingface-cli login          # + 모델 페이지에서 라이선스 동의(게이트):
#                                https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M

# 1) 정상 데이터 확보: 공개데이터 대량 + 팀원 수집(.txt) 합치기
python detector/fetch_benign.py --n 2000
python detector/build_dataset.py --benign \
    detector/data/benign_seed.txt detector/data/benign_public.txt 팀원수집.txt

# 2) 학습 → 평가
python detector/train.py --class-weights
python detector/evaluate.py
# 정직성: 변형 제외로도 재측정
python detector/build_dataset.py --no-variants --benign detector/data/benign_seed.txt detector/data/benign_public.txt
python detector/evaluate.py
```

## 데이터가 들어오면 (지금 상태)
- 팀원이 모은 정상 문장 .txt 를 `detector/data/` 에 넣고 위 `--benign` 목록에 파일명만 추가.
- 공개데이터는 `fetch_benign.py` 가 자동으로 뽑는다(둘 다 MIT — 발표/공개 OK).
- 그 뒤 train → evaluate 는 그대로 돌아간다. **코드는 준비됨.**

## 주의
1. **정상 데이터 균형** — 공격:정상이 크게 치우치면 `--class-weights` 로 보정하되, 근본은 정상 수를 늘리는 것.
2. **모델 게이트** — Meta 승인 대기 시 `protectai/deberta-v3-base-prompt-injection-v2`(Apache·게이트없음)로 선행.
3. **변형 과대평가** — mutated 는 규칙 8종이라 분포가 좁다 → `--no-variants` 로도 재서 함께 보고.
4. **Kakao 는 선생❌ 경쟁자⭕** — 라벨러로 쓰면 상한이 Kakao 로 묶이고 순환평가가 된다. evaluate.py `--extra` 로 벤치마크만.

## 엔진 연결(1차 레이어)은 성능 나온 뒤
`src/joker/` 입력단에 탐지 훅(SAFE→통과 / 의심→엔진 / threshold 애매값만 OpenAI 2차).
