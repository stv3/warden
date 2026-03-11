import uuid
import threading
from datetime import datetime, timezone
from fastapi import APIRouter, BackgroundTasks, Depends

from api.routes.auth import get_current_user

router = APIRouter(prefix="/pipeline", tags=["pipeline"])

# In-memory task store — sufficient for on-demand runs in a single-process server.
# For multi-worker deployments, swap this for a Redis/DB-backed store.
_tasks: dict[str, dict] = {}


def _run_in_background(task_id: str, fn):
    """Wrapper that records start/end and captures result or error."""
    _tasks[task_id]["status"] = "running"
    _tasks[task_id]["started_at"] = datetime.now(timezone.utc).isoformat()
    try:
        result = fn()
        _tasks[task_id]["status"] = "completed"
        _tasks[task_id]["result"] = result
    except Exception as e:
        _tasks[task_id]["status"] = "failed"
        _tasks[task_id]["error"] = str(e)
    finally:
        _tasks[task_id]["completed_at"] = datetime.now(timezone.utc).isoformat()


@router.post("/run")
def trigger_full_pipeline(
    background_tasks: BackgroundTasks,
    _: str = Depends(get_current_user),
):
    """Trigger a full ingestion pipeline: fetch scanners → deduplicate → KEV match → score → alert."""
    from orchestrator.pipeline import IngestionPipeline

    task_id = str(uuid.uuid4())
    _tasks[task_id] = {"status": "pending", "started_at": None, "completed_at": None,
                       "result": None, "error": None}

    background_tasks.add_task(
        _run_in_background, task_id, lambda: IngestionPipeline().run()
    )
    return {"status": "queued", "task_id": task_id}


@router.post("/kev-sync")
def trigger_kev_sync(
    background_tasks: BackgroundTasks,
    _: str = Depends(get_current_user),
):
    """Sync the CISA KEV catalog and re-match against existing findings."""
    from orchestrator.pipeline import IngestionPipeline

    task_id = str(uuid.uuid4())
    _tasks[task_id] = {"status": "pending", "started_at": None, "completed_at": None,
                       "result": None, "error": None}

    background_tasks.add_task(
        _run_in_background, task_id, lambda: IngestionPipeline().run_kev_sync_only()
    )
    return {"status": "queued", "task_id": task_id}


@router.get("/task/{task_id}")
def get_task_status(task_id: str, _: str = Depends(get_current_user)):
    """Poll the status of a pipeline task."""
    task = _tasks.get(task_id)
    if not task:
        return {"task_id": task_id, "status": "not_found", "result": None, "error": None}
    return {"task_id": task_id, **task}
