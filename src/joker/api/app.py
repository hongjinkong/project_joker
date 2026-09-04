"""FastAPI 앱 — contracts/api_contract.md v0.3 구현. 얇은 라우팅 껍데기.

모든 로직은 fastapi 없이 도는 헬퍼(api/service·serialize·presets·jobs)에 있다.
그래서 엔진·테스트는 fastapi 없이 돌고, 이 파일은 HTTP↔헬퍼 배선만 한다.

구동: 프로젝트 루트(model/)에서
    uvicorn "joker.api.app:create_app" --factory --port 8000
fastapi 는 optional 의존성이라 함수 안에서 import 한다.
"""

import importlib.util


def create_app():
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    from joker.api import presets, serialize, service
    from joker.api.jobs import JobRegistry
    from joker.config import Settings, load_dotenv
    from joker.corpus.loader import load_default_corpus
    from joker.store.sqlite import Repository

    # ★ uvicorn 은 cli.main() 을 안 거치므로 여기서 .env 를 읽는다.
    #   안 하면 JOKER_PROFILE 이 기본값 mock 으로 떨어져 '가짜 응답으로 만든 진짜처럼 보이는 수치'가 나온다.
    load_dotenv()
    settings = Settings.from_env()
    repo = Repository(settings.db_path)
    registry = JobRegistry()
    data_dir = "data/attacks"

    from joker.detect_ko import KoDetector
    detector = KoDetector()  # 모델은 첫 /api/detect 호출에서 lazy 로드(엔진 시작은 안 무겁게)

    # 코퍼스는 시작 시 1회 로드해 health 의 corpus_loaded 로 쓴다(진단마다 다시 읽는 건 prepare 담당).
    try:
        _corpus_n = len(load_default_corpus(data_dir, run_audit=False))
    except Exception:  # noqa: BLE001
        _corpus_n = 0

    app = FastAPI(title="뚫어보기 API", version="0.3")

    def _err_response(prep: dict):
        return JSONResponse(
            status_code=prep["status"],
            content={"error": {"code": prep["code"], "message": prep["message"]}},
        )

    @app.post("/api/diagnose")
    async def diagnose(req: Request):
        try:
            body = await req.json()
        except Exception:  # noqa: BLE001
            return JSONResponse(status_code=400,
                                content={"error": {"code": "bad_json", "message": "요청 본문이 JSON 이 아닙니다."}})
        prep = service.prepare(body, settings, data_dir)
        if not prep.get("ok"):
            return _err_response(prep)
        registry.register(prep["run_id"], prep["target"], prep["estimated"])
        registry.submit(prep["run_id"], service.make_worker(prep, repo))
        est = prep["estimated"]
        # 202: 시작만 알린다. target 은 model+backend 만(전체는 GET 에서). estimated_calls 는 BYOK 요금 고지.
        return JSONResponse(status_code=202, content={
            "run_id": prep["run_id"], "status": "running",
            "estimated_calls": est["victim_max"],
            "target": {"model": prep["target"]["model"], "backend": prep["target"]["backend"]},
        })

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str):
        job = registry.get(run_id)
        if job and job.status == "running":
            return serialize.running_payload(run_id, job.target, job.estimated)
        if job and job.status == "error":
            return serialize.error_payload(run_id, job.target, job.error)
        # 완료본은 DB 가 진실(레지스트리에 없어도 재시작 후 이력으로 조회된다)
        try:
            run = repo.load_run(run_id)
        except KeyError:
            return JSONResponse(status_code=404,
                                content={"error": {"code": "not_found", "message": f"run_id 없음: {run_id}"}})
        return serialize.serialize_run(run)

    @app.get("/api/runs")
    def list_runs():
        try:
            return {"runs": repo.list_runs()}
        except Exception:  # noqa: BLE001 — DB 가 아직 없으면 빈 목록
            return {"runs": []}

    @app.get("/api/models")
    def models():
        return presets.list_models()

    @app.post("/api/detect")
    async def detect(req: Request):
        """입력 문구 1건 → JOKER-KO 공격 탐지. 원문은 응답에 안 담는다(비밀값 유출 방지)."""
        from joker.detect_ko import DetectorUnavailable, detect_payload
        try:
            body = await req.json()
        except Exception:  # noqa: BLE001
            return JSONResponse(status_code=400,
                                content={"error": {"code": "bad_json", "message": "요청 본문이 JSON 이 아닙니다."}})
        try:
            return detect_payload(detector, (body or {}).get("text"))
        except ValueError as e:
            return JSONResponse(status_code=400,
                                content={"error": {"code": "text_required", "message": str(e)}})
        except DetectorUnavailable as e:
            return JSONResponse(status_code=503,
                                content={"error": {"code": "detector_unavailable", "message": str(e)}})

    @app.get("/api/health")
    def health():
        lg = importlib.util.find_spec("langgraph") is not None
        return {
            "status": "ok", "profile": settings.profile.value, "langgraph": lg,
            "corpus_loaded": _corpus_n, "default_preset": presets.DEFAULT_PRESET,
            "detector_ready": detector.available(),
        }

    return app
