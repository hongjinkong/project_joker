"""local(Ollama) / openai 공용 provider. 차이는 base_url·키뿐이라 파일 하나로 둔다.

Ollama 가 OpenAI 호환 엔드포인트(/v1/chat/completions)를 주므로 같은 코드로 둘 다 붙는다.
의존성을 늘리지 않으려고 urllib(표준 라이브러리)만 쓴다.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from joker.providers.base import CallResult, Usage


class ProviderError(Exception):
    pass


class OpenAICompatProvider:
    def __init__(self, *, base_url: str, api_key: str, model: str,
                 timeout: float = 120.0, max_tokens: int = 512) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.max_tokens = max_tokens

    def complete(self, *, system: str, user: str, temperature: float, seed: int) -> CallResult:
        url = f"{self.base_url}/chat/completions"
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "seed": seed,
            "max_tokens": self.max_tokens,  # 응답 길이 상한 → 느린 생성·폭주 방지
            "stream": False,
        }
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")

        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            # 타임아웃(TimeoutError)은 URLError 가 아니라 OSError 계열 → 함께 잡는다
            raise ProviderError(f"LLM 호출 실패({self.base_url}): {e}") from e
        latency_ms = int((time.monotonic() - start) * 1000)

        text = payload["choices"][0]["message"]["content"]
        usage_raw = payload.get("usage", {})
        usage = Usage(
            prompt_tokens=usage_raw.get("prompt_tokens", 0),
            completion_tokens=usage_raw.get("completion_tokens", 0),
        )
        return CallResult(text=text, model=self.model, usage=usage, latency_ms=latency_ms)
