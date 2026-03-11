import logging
from celery import Celery
from celery.schedules import crontab

from config.settings import settings

logger = logging.getLogger(__name__)

celery_app = Celery(
    "vuln_orchestrator",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    beat_schedule={
        # Full ingestion pipeline — runs daily at 2am UTC
        "daily-ingestion": {
            "task": "orchestrator.scheduler.run_ingestion_pipeline",
            "schedule": crontab(hour=2, minute=0),
        },
        # KEV sync — every 6 hours (CISA updates multiple times a day)
        "kev-sync": {
            "task": "orchestrator.scheduler.sync_kev",
            "schedule": crontab(minute=0, hour="*/6"),
        },
        # SLA breach check — daily at 8am UTC (start of business)
        "sla-breach-check": {
            "task": "orchestrator.scheduler.check_sla_breaches",
            "schedule": crontab(hour=8, minute=0),
        },
    },
)


@celery_app.task(name="orchestrator.scheduler.run_ingestion_pipeline", bind=True, max_retries=2)
def run_ingestion_pipeline(self):
    """
    Full pipeline: fetch findings from all enabled scanners → deduplicate → KEV match → score → ticket.
    """
    from orchestrator.pipeline import IngestionPipeline
    try:
        pipeline = IngestionPipeline()
        result = pipeline.run()
        logger.info(f"Ingestion pipeline complete: {result}")
        return result
    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        raise self.retry(exc=e, countdown=300)  # Retry after 5 minutes


@celery_app.task(name="orchestrator.scheduler.sync_kev")
def sync_kev():
    """Syncs KEV catalog to DB and triggers re-matching against existing findings."""
    from orchestrator.pipeline import IngestionPipeline
    pipeline = IngestionPipeline()
    result = pipeline.run_kev_sync_only()
    logger.info(f"KEV sync task complete: {result}")
    return result


@celery_app.task(name="orchestrator.scheduler.check_sla_breaches")
def check_sla_breaches():
    """Checks for findings past their SLA due date and sends alerts."""
    from orchestrator.pipeline import IngestionPipeline
    pipeline = IngestionPipeline()
    result = pipeline.check_sla_breaches()
    logger.info(f"SLA breach check complete: {result}")
    return result
