"""local(Ollama) / openai 공용 provider. 차이는 base_url·키뿐이라 파일 하나로 둔다.

Ollama 가 OpenAI 호환 엔드포인트(/v1/chat/completions)를 주므로 같은 코드로 둘 다 붙는다.
의존성을 늘리지 않으려고 urllib(표준 라이브러리)만 쓴다.

★ gpt-5 계열 호환: gpt-5-mini 등 신형 모델은 옛 파라미터를 거부한다.
  - `max_tokens` ✕ → `max_completion_tokens` ○
  - `temperature=0` ✕ (기본값 1만 허용) → 아예 안 보낸다
  - `seed` 도 무시/거부 가능 → 안 보낸다
  - 대신 `reasoning_effort` 로 추론 토큰(=비용)을 눌러 준다.
  로컬 qwen(Ollama)은 옛 파라미터를 그대로 쓰므로 모델명으로 분기한다.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from joker.providers.base import CallResult, Usage
# ★ 오류 본문에 키가 섞여 올 수 있다(서버가 요청을 되돌려주는 경우). 마스킹하고 찍는다.
#   safety/masking.py 가 정의만 있고 호출부가 0건이었는데(2026-08-27 구조 점검), 여기가 첫 배선이다.
from joker.safety.masking import mask_secrets

# gpt-5 계열·o-시리즈: 신형 파라미터 규격을 쓰는 모델 접두사
_RESTRICTED_PREFIXES = ("gpt-5", "gpt5", "o1", "o3", "o4")


def _is_restricted(model: str) -> bool:
    """신형(gpt-5/o-시리즈) 파라미터 규격을 써야 하는 모델인가."""
    m = model.lower().split("/")[-1]  # "openai/gpt-5-mini" → "gpt-5-mini"
    return any(m.startswith(p) for p in _RESTRICTED_PREFIXES)


class ProviderError(Exception):
    pass


class OpenAICompatProvider:
    def __init__(self, *, base_url: str, api_key: str, model: str,
                 timeout: float = 120.0, max_tokens: int = 512,
                 reasoning_effort: str = "low") -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.reasoning_effort = reasoning_effort
        self.restricted = _is_restricted(model)

    def _build_body(self, *, system: str, user: str, temperature: float, seed: int) -> dict:
        """요청 본문을 모델 규격에 맞게 조립한다(네트워크 없음 → 단위 테스트 대상)."""
        body: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
        }
        if self.restricted:
            # gpt-5 계열: temperature/seed 미전송, max_completion_tokens 사용.
            # 추론 토큰이 이 한도에 포함되므로 여유를 둬 응답이 잘려-빈문자열 되는 걸 막는다.
            body["max_completion_tokens"] = max(self.max_tokens, 2048)
            body["reasoning_effort"] = self.reasoning_effort
        else:
            # 로컬 qwen 등 고전 규격
            body["temperature"] = temperature
            body["seed"] = seed
            body["max_tokens"] = self.max_tokens
        return body

    def complete(self, *, system: str, user: str, temperature: float, seed: int) -> CallResult:
        url = f"{self.base_url}/chat/completions"
        body = self._build_body(system=system, user=user, temperature=temperature, seed=seed)
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")

        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            # ★ 2026-08-27: 예전엔 base_url 과 "HTTP Error 404" 만 찍었다. 그걸론 원인을 알 수 없다.
            #   실제로 exaone3.5:7.8b 를 받아놓고 victim 호출이 404 났는데, 모델명도 서버 설명도
            #   안 보여서 '엔드포인트 문제인지 모델 문제인지' 를 구분할 수 없었다.
            #   서버는 본문에 이유를 담아 준다(Ollama: {"error":"model 'x' not found"}).
            body = ""
            try:
                body = e.read().decode("utf-8", "replace")[:400]
            except Exception:  # noqa: BLE001 — 본문을 못 읽어도 나머지 정보는 살린다
                pass
            hint = ""
            if e.code == 404:
                hint = (" · 404 는 대개 '그 모델이 서버에 없음' 이다. "
                        "로컬이면 `ollama list` 로 정확한 태그를 확인할 것")
            raise ProviderError(
                f"LLM 호출 실패 [{e.code}] model={self.model!r} url={self.base_url}"
                f"{hint}\n  서버 응답: {mask_secrets(body)}"
            ) from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            # 타임아웃(TimeoutError)은 URLError 가 아니라 OSError 계열 → 함께 잡는다
            raise ProviderError(
                f"LLM 호출 실패 model={self.model!r} url={self.base_url}: {e}"
            ) from e
        latency_ms = int((time.monotonic() - start) * 1000)

        # 신형 모델이 추론에 토큰을 다 쓰면 content 가 None 일 수 있다 → 빈 문자열로 방어
        msg = payload["choices"][0]["message"]
        text = msg.get("content") or ""
        usage_raw = payload.get("usage", {})
        usage = Usage(
            prompt_tokens=usage_raw.get("prompt_tokens", 0),
            completion_tokens=usage_raw.get("completion_tokens", 0),
        )
        return CallResult(text=text, model=self.model, usage=usage, latency_ms=latency_ms)
