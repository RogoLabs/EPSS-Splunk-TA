from datetime import date, timedelta
from unittest.mock import MagicMock

from epss_lib.checkpoint import CheckpointManager

MINIMUM_SUPPORTED_DATE = "2022-02-07"


def _make_manager(checkpoint_data=None):
    """Create a CheckpointManager with mocked KV Store."""
    mock_service = MagicMock()
    mgr = CheckpointManager(service=mock_service, logger=MagicMock())
    if checkpoint_data is not None:
        mgr._checkpoint = checkpoint_data
    return mgr


def test_default_checkpoint():
    """Default checkpoint has correct _key, null last_date_ingested, zero records."""
    mgr = _make_manager()
    cp = mgr._default_checkpoint()
    assert cp["_key"] == "epss_ingestion_state"
    assert cp["last_date_ingested"] is None
    assert cp["total_records_processed"] == 0
    assert cp["consecutive_errors"] == 0
    assert cp["last_error"] is None


def test_get_dates_no_checkpoint_30_day_lookback():
    """No checkpoint: returns 30 dates from today-30 to yesterday."""
    mgr = _make_manager()
    # Set internal checkpoint to default (no last_date_ingested)
    mgr._checkpoint = mgr._default_checkpoint()

    today = date.today()
    dates = mgr.get_dates_to_process(lookback_days=30)

    expected_start = today - timedelta(days=30)
    expected_end = today - timedelta(days=1)

    assert len(dates) == 30
    assert dates[0] == expected_start.isoformat()
    assert dates[-1] == expected_end.isoformat()


def test_get_dates_with_existing_checkpoint():
    """With checkpoint: starts from last_date_ingested + 1."""
    mgr = _make_manager()
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    three_days_ago = (date.today() - timedelta(days=3)).isoformat()

    mgr._checkpoint = mgr._default_checkpoint()
    mgr._checkpoint["last_date_ingested"] = three_days_ago

    dates = mgr.get_dates_to_process(lookback_days=30)

    expected_start = (date.today() - timedelta(days=2)).isoformat()
    assert dates[0] == expected_start
    assert dates[-1] == yesterday
    assert len(dates) == 2


def test_get_dates_caps_at_minimum_date():
    """Lookback should never go before 2022-02-07."""
    mgr = _make_manager()
    mgr._checkpoint = mgr._default_checkpoint()

    # Use a huge lookback that would go before minimum date
    dates = mgr.get_dates_to_process(lookback_days=99999)

    assert dates[0] == MINIMUM_SUPPORTED_DATE


def test_get_dates_already_current_returns_empty():
    """If last_date_ingested is yesterday, return empty list."""
    mgr = _make_manager()
    yesterday = (date.today() - timedelta(days=1)).isoformat()

    mgr._checkpoint = mgr._default_checkpoint()
    mgr._checkpoint["last_date_ingested"] = yesterday

    dates = mgr.get_dates_to_process(lookback_days=30)
    assert dates == []


def test_save_checkpoint_accumulates_records():
    """records_processed adds to total_records_processed."""
    mgr = _make_manager()
    mgr._checkpoint = mgr._default_checkpoint()
    mgr._checkpoint["total_records_processed"] = 100

    mgr.save_checkpoint(date_ingested="2026-04-23", records_processed=500)

    assert mgr._checkpoint["total_records_processed"] == 600
    assert mgr._checkpoint["last_date_ingested"] == "2026-04-23"
    assert mgr._checkpoint["consecutive_errors"] == 0
    assert mgr._checkpoint["last_error"] is None


def test_save_checkpoint_error_tracking():
    """consecutive_errors increments on error, resets on success."""
    mgr = _make_manager()
    mgr._checkpoint = mgr._default_checkpoint()

    # Record an error
    mgr.save_checkpoint(error="Download failed")
    assert mgr._checkpoint["consecutive_errors"] == 1
    assert mgr._checkpoint["last_error"] == "Download failed"

    # Record another error
    mgr.save_checkpoint(error="Timeout")
    assert mgr._checkpoint["consecutive_errors"] == 2
    assert mgr._checkpoint["last_error"] == "Timeout"

    # Record success — should reset
    mgr.save_checkpoint(date_ingested="2026-04-23", records_processed=100)
    assert mgr._checkpoint["consecutive_errors"] == 0
    assert mgr._checkpoint["last_error"] is None
