"""인프로세스 잡 레지스트리 + 단일 워커.

정밀 진단이 3~4분 블로킹이라 동기 응답이 불가능하다(계약: 202 running + 폴링).
로컬 victim 은 8GB 라 동시 진단이 물리적으로 불가능하므로 max_workers=1 로 직렬화한다
— 두 번째 요청도 202 를 받고 큐에서 대기하다 앞 진단이 끝나면 시작된다.

레지스트리(메모리)는 인플라이트 전용이고, 완료본의 진실은 DB 다. 그래서 서버가 재시작해도
이력은 DB 에 남고, GET 은 '진행 중이면 레지스트리 · 완료면 DB' 로 이원 조회한다.
"""

from __future__ import annotations

import datetime
import threading
from concurrent.futures import ThreadPoolExecutor

from joker.safety.logging import get_logger

_log = get_logger("joker.api")


class Job:
    def __init__(self, run_id: str, target: dict, estimated: dict) -> None:
        self.run_id = run_id
        self.target = target          # target 블록 dict
        self.estimated = estimated    # estimate_calls() 결과
        self.status = "running"       # running | done | error
        self.error: dict | None = None  # {code, message} — error 일 때만
        self.created_at = datetime.datetime.now().isoformat(timespec="seconds")


class JobRegistry:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="joker-diag")

    def register(self, run_id: str, target: dict, estimated: dict) -> Job:
        job = Job(run_id, target, estimated)
        with self._lock:
            self._jobs[run_id] = job
        return job

    def submit(self, run_id: str, work) -> None:
        """work() = 실제 진단+DB 저장(무인자). 스레드라 예외를 전파 못 하므로 잡 상태로만 남긴다."""
        self._pool.submit(self._run, run_id, work)

    def _run(self, run_id: str, work) -> None:
        try:
            work()
            self._set(run_id, "done")
            _log.info("diagnose done run_id=%s", run_id)
        except Exception as e:  # noqa: BLE001 — 워커 스레드 최상단
            from joker.providers.openai_compat import ProviderError

            if isinstance(e, ProviderError):
                err = {"code": "target_unreachable", "message": "대상 모델 연결에 실패했습니다."}
            else:
                err = {"code": "engine_error", "message": "진단 중 오류가 발생했습니다."}
            self._set(run_id, "error", err)
            # ★ 예외 메시지에 base_url·키가 섞일 수 있어 트레이스백 원문은 안 찍는다. 코드만 남긴다.
            _log.error("diagnose failed run_id=%s code=%s", run_id, err["code"])

    def _set(self, run_id: str, status: str, error: dict | None = None) -> None:
        with self._lock:
            j = self._jobs.get(run_id)
            if j:
                j.status = status
                if error:
                    j.error = error

    def get(self, run_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(run_id)
