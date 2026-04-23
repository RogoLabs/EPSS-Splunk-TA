import logging
from datetime import date, datetime, timedelta, timezone
from typing import Optional

try:
    import splunklib.client as client
except ImportError:
    client = None

MINIMUM_SUPPORTED_DATE = "2022-02-07"
CHECKPOINT_KEY = "epss_ingestion_state"
COLLECTION_NAME = "ta_epss_checkpoints"


class CheckpointManager:
    def __init__(
        self,
        service=None,
        app: str = "TA-epss",
        logger: Optional[logging.Logger] = None,
    ):
        self.service = service
        self.app = app
        self.logger = logger or logging.getLogger("ta_epss.checkpoint")
        self._checkpoint = None

    def _default_checkpoint(self) -> dict:
        return {
            "_key": CHECKPOINT_KEY,
            "last_date_ingested": None,
            "total_records_processed": 0,
            "last_successful_run": None,
            "last_error": None,
            "consecutive_errors": 0,
        }

    def get_checkpoint(self) -> dict:
        if self._checkpoint is not None:
            return self._checkpoint

        if self.service is None:
            self._checkpoint = self._default_checkpoint()
            return self._checkpoint

        try:
            collection = self.service.kvstore[COLLECTION_NAME]
            data = collection.data.query_by_id(CHECKPOINT_KEY)
            self._checkpoint = data
        except Exception:
            self._checkpoint = self._default_checkpoint()

        return self._checkpoint

    def save_checkpoint(
        self,
        date_ingested: Optional[str] = None,
        records_processed: int = 0,
        error: Optional[str] = None,
    ) -> None:
        if self._checkpoint is None:
            self._checkpoint = self._default_checkpoint()

        if error:
            self._checkpoint["consecutive_errors"] += 1
            self._checkpoint["last_error"] = error
        else:
            if date_ingested:
                self._checkpoint["last_date_ingested"] = date_ingested
            self._checkpoint["total_records_processed"] += records_processed
            self._checkpoint["last_successful_run"] = datetime.now(timezone.utc).isoformat()
            self._checkpoint["consecutive_errors"] = 0
            self._checkpoint["last_error"] = None

        if self.service is not None:
            try:
                import json

                collection = self.service.kvstore[COLLECTION_NAME]
                body = json.dumps(self._checkpoint)
                try:
                    collection.data.update(CHECKPOINT_KEY, body)
                except Exception:
                    collection.data.insert(body)
            except Exception as e:
                self.logger.error(f"Failed to save checkpoint: {e}")

    def get_dates_to_process(self, lookback_days: int = 30) -> list[str]:
        if self._checkpoint is None:
            self._checkpoint = self._default_checkpoint()

        today = date.today()
        yesterday = today - timedelta(days=1)

        last_ingested = self._checkpoint.get("last_date_ingested")

        if last_ingested:
            start_date = date.fromisoformat(last_ingested) + timedelta(days=1)
        else:
            start_date = today - timedelta(days=lookback_days)

        min_date = date.fromisoformat(MINIMUM_SUPPORTED_DATE)
        if start_date < min_date:
            start_date = min_date

        if start_date > yesterday:
            return []

        dates = []
        current = start_date
        while current <= yesterday:
            dates.append(current.isoformat())
            current += timedelta(days=1)

        return dates
