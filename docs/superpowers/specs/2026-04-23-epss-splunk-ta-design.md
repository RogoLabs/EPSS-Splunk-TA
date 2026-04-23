# EPSS-Splunk-TA Design Spec

**Date:** 2026-04-23
**Author:** Jerry Gamblin
**Status:** Draft

## Overview

A Splunk Technology Add-on that ingests daily EPSS (Exploit Prediction Scoring System) scores from FIRST's published CSV files. Modeled after the CVE-Splunk-TA architecture with simplifications appropriate to the EPSS data source.

EPSS provides a daily probability score (0.0-1.0) for every CVE, predicting the likelihood of exploitation in the next 30 days. The TA downloads the daily compressed CSV (~5MB), parses ~250K rows, and writes one Splunk event per CVE per day.

## Data Source

**URL pattern:** `https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz`

**CSV format:**

```
#model_version:v2025.03.14,score_date:2026-04-23T00:00:00+0000
cve,epss,percentile
CVE-2014-0160,0.97565,0.99996
CVE-2024-1234,0.00043,0.14832
...
```

- Line 1: Comment with model version and score date
- Line 2: Column headers
- Lines 3+: One row per CVE (~250K rows)
- No authentication required
- Published daily, typically available by 00:30 UTC

## Architecture

```
TA-epss/
├── bin/
│   ├── epss.py                    # Modular input entry point
│   ├── epss_lib/
│   │   ├── __init__.py
│   │   ├── epss_client.py         # EPSS CSV download client
│   │   ├── csv_processor.py       # CSV parsing -> event dicts
│   │   ├── checkpoint.py          # KV Store checkpoint manager
│   │   ├── credential.py          # Proxy credential storage (if needed)
│   │   └── logging_config.py      # Logging to TA-epss.log
│   └── lib/                       # Vendored: splunklib, requests, urllib3, certifi, etc.
├── default/
│   ├── app.conf
│   ├── inputs.conf
│   ├── props.conf
│   ├── transforms.conf
│   ├── collections.conf
│   ├── macros.conf
│   ├── savedsearches.conf
│   └── data/ui/views/
│       ├── epss_overview.json     # Dashboard Studio (JSON)
│       └── epss_health.json       # Dashboard Studio (JSON)
├── lookups/
│   ├── epss_current.csv           # Latest day's EPSS scores
│   └── epss_daily_summary.csv     # Daily aggregate stats
├── metadata/
│   ├── default.meta
│   └── local.meta
├── static/
│   └── appIcon.png
├── README/
├── tests/
│   ├── conftest.py
│   ├── test_csv_processor.py
│   ├── test_checkpoint.py
│   ├── test_epss_client.py
│   └── test_epss_input.py
├── scripts/
│   ├── build.sh                   # Package TA for distribution
│   └── vendor.sh                  # Install vendored dependencies
├── .github/
│   └── workflows/
│       ├── ci.yml                 # Lint + unit tests on push/PR
│       ├── appinspect.yml         # Splunk AppInspect validation
│       └── integration.yml        # Docker-based integration tests
├── docker-compose.test.yml
├── app.manifest
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Module Design

### epss.py (Modular Input Entry Point)

- **`--scheme` early exit:** Check `sys.argv` for `--scheme` before any imports, print XML schema definition, flush stdout, exit. This avoids splunklib import issues in some environments.
- **`sys.path` setup:** Insert `bin/` and `bin/lib/` into `sys.path` before importing vendored dependencies.
- **`stream_events()`:** Main entry point called by Splunk scheduler.
- **`_process_input()`:** Orchestrates download/parse/write loop:
  1. Read checkpoint to get last ingested date
  2. Calculate dates to process (backfill or catch-up)
  3. For each date: download CSV, parse, write events in batches, update checkpoint
- **`_write_batch()`:** Converts processed rows to Splunk events with `sourcetype=epss:score`.
- **`_write_audit_event()`:** Writes operational events with `sourcetype=epss:audit`.

### epss_client.py (HTTP Client)

- **`download_scores(date: str) -> bytes`:** Downloads `epss_scores-{date}.csv.gz` via HTTP GET. Returns decompressed CSV content.
- **`check_availability(date: str) -> bool`:** HEAD request to check if a date's file exists (for backfill boundary detection).
- Supports optional proxy configuration via Splunk's proxy settings.
- Retries with exponential backoff (3 attempts) for transient HTTP errors (502/503/504, timeouts).
- Raises specific exceptions for 404 (date not available) vs. other failures.

### csv_processor.py (CSV Parser)

- **`parse_csv(csv_content: str, score_date: str) -> Iterator[dict]`:** Yields one dict per row.
- Parses comment line to extract `model_version` and `score_date`.
- Each yielded dict:
  ```python
  {
      "cve_id": "CVE-2024-1234",
      "epss_score": 0.00043,
      "percentile": 0.14832,
      "score_date": "2026-04-23",
      "model_version": "v2025.03.14",
      "epss_risk_tier": "Low"
  }
  ```
- **Risk tier calculation:**
  - Critical: epss_score > 0.7
  - High: epss_score > 0.3
  - Medium: epss_score > 0.1
  - Low: epss_score <= 0.1
- Validates CVE ID format (`CVE-\d{4}-\d{4,}`), skips malformed rows with warning.
- Tracks stats: total parsed, skipped, errors.

### checkpoint.py (KV Store Checkpoint)

- **Collection:** `ta_epss_checkpoints`
- **Tracked state:**
  - `last_date_ingested`: Most recent score_date successfully processed (YYYY-MM-DD)
  - `total_records_processed`: Cumulative event count
  - `last_successful_run`: ISO 8601 timestamp of last completion
  - `last_error`: Most recent error message (null on success)
  - `consecutive_errors`: Error counter (resets on success)
- **Methods:**
  - `get_checkpoint()`: Read with retry logic (handles KV Store init delays)
  - `save_checkpoint()`: Atomic update
  - `get_dates_to_process(lookback_days: int) -> list[str]`: Returns list of dates from `last_date_ingested + 1` through today (or from `today - lookback_days` if no checkpoint exists)

### credential.py (Credential Manager)

- Stores optional proxy credentials via Splunk's `storage/passwords` API.
- Realm: `TA-epss`
- Gracefully handles missing credentials (no proxy = direct connection).

### logging_config.py

- Output: `$SPLUNK_HOME/var/log/splunk/TA-epss.log`
- Format: `%(asctime)s %(levelname)s [%(name)s] %(message)s`
- Rotation: 10MB files, 5 backups
- Fallback: stderr

## Data Flow

### First Run (Backfill)

1. Modular input fires (interval = 86400, once daily)
2. Checkpoint is empty -> calculate start date as `today - lookback_days` (default: 30)
3. For each date from start through today:
   a. Download `epss_scores-{date}.csv.gz`
   b. Decompress, parse CSV (~250K rows)
   c. Write events in batches of 500 with `sourcetype=epss:score`
   d. Write audit event: `{"action": "ingest_complete", "score_date": "...", "records": 250000}`
   e. Update checkpoint with this date
4. If download fails for a date (404 = not published yet, or weekend gap), skip and continue

### Daily Operation

1. Checkpoint shows `last_date_ingested = 2026-04-22`
2. Calculate: need to process 2026-04-23
3. Download, parse, write, update checkpoint
4. Done until next scheduled run

### Catch-Up After Downtime

- TA disabled for 5 days -> checkpoint is 5 days old
- Next run processes all 5 missed days sequentially
- No data gaps

## Event Schema

### sourcetype=epss:score

One event per CVE per day. Flat JSON, compatible with `KV_MODE=json`.

```json
{
  "cve_id": "CVE-2024-1234",
  "epss_score": 0.00043,
  "percentile": 0.14832,
  "score_date": "2026-04-23",
  "model_version": "v2025.03.14",
  "epss_risk_tier": "Low"
}
```

### sourcetype=epss:audit

Operational lifecycle events.

```json
{
  "timestamp": "2026-04-23T01:15:32.123Z",
  "action": "ingest_complete",
  "score_date": "2026-04-23",
  "records_ingested": 249847,
  "duration_seconds": 45.2,
  "http_status": 200,
  "file_size_bytes": 5242880
}
```

Actions: `input_started`, `download_started`, `download_complete`, `ingest_complete`, `input_complete`, `error`.

## Splunk Configuration

### app.conf

```ini
[install]
build = 1
is_configured = false

[ui]
is_visible = true
label = EPSS Scores for Splunk

[launcher]
author = Jerry Gamblin
description = Ingests daily EPSS (Exploit Prediction Scoring System) scores from FIRST
version = 1.0.0

[package]
id = TA-epss
check_for_updates = false
```

**CRITICAL: `install.splunk_version_requirement` must NOT be set or must be `*`.** Setting a specific version (e.g., `>=10.0`) causes SLIM/AppInspect validation failures. This was learned from both the CVE-Splunk-TA and CVEICU-TA. Enforce version compatibility through documentation only.

### inputs.conf

```ini
[epss]
python.version = python3
python.required = 3.13

[epss://default]
index = main
lookback_days = 30
batch_size = 500
interval = 86400
disabled = 0
```

- `python.required = 3.13` (not deprecated `python.version` alone -- required for Splunk 10.2+)
- `disabled = 0` so input is enabled by default (avoids "no events" support issues)

### props.conf

```ini
[epss:score]
KV_MODE = json
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_FORMAT = %Y-%m-%d
TIME_PREFIX = "score_date"\s*:\s*"
MAX_TIMESTAMP_LOOKAHEAD = 10
TRUNCATE = 0

FIELDALIAS-vulnerability_id = cve_id AS vulnerability_id
FIELDALIAS-severity_score = epss_score AS severity_score
FIELDALIAS-dest = cve_id AS dest
FIELDALIAS-signature = cve_id AS signature

[epss:audit]
KV_MODE = json
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%Z
TIME_PREFIX = "timestamp"\s*:\s*"
TRUNCATE = 0
```

### transforms.conf

```ini
[epss_current_lookup]
external_type = kvstore
collection = epss_current_lookup
fields_list = _key, cve_id, epss_score, percentile, epss_risk_tier, score_date, model_version
```

### collections.conf

```ini
[ta_epss_checkpoints]
enforceTypes = false
replicate = false

[epss_current_lookup]
enforceTypes = false
replicate = true
```

- `ta_epss_checkpoints`: No replication (local to each search head)
- `epss_current_lookup`: Replicated (used for cross-TA correlation on search head clusters)

### macros.conf

```ini
[epss_index]
definition = index=main
iseval = 0
```

All dashboards and saved searches reference the `epss_index` macro so users can redirect to a custom index via `local/macros.conf`.

### savedsearches.conf

```ini
[EPSS Current Lookup Refresh]
search = `epss_index` sourcetype=epss:score earliest=-2d@d latest=now \
  | stats latest(epss_score) as epss_score latest(percentile) as percentile \
    latest(epss_risk_tier) as epss_risk_tier latest(score_date) as score_date \
    latest(model_version) as model_version by cve_id \
  | outputlookup epss_current_lookup
cron_schedule = 30 2 * * *
enableSched = 1
dispatch.earliest_time = -2d@d
dispatch.latest_time = now
description = Refreshes the EPSS current scores KV Store lookup with the most recent day's scores

[EPSS Daily Summary Refresh]
search = `epss_index` sourcetype=epss:score earliest=-2d@d latest=now \
  | stats latest(score_date) as score_date count as total_cves \
    avg(epss_score) as mean_score median(epss_score) as median_score \
    max(epss_score) as max_score \
    sum(if(epss_score>0.7,1,0)) as critical_count \
    sum(if(epss_score>0.3 AND epss_score<=0.7,1,0)) as high_count \
    sum(if(epss_score>0.1 AND epss_score<=0.3,1,0)) as medium_count \
    sum(if(epss_score<=0.1,1,0)) as low_count \
  | outputlookup epss_daily_summary.csv
cron_schedule = 35 2 * * *
enableSched = 1
dispatch.earliest_time = -2d@d
dispatch.latest_time = now
description = Refreshes the daily EPSS summary stats lookup
```

Saved searches run at 02:30 and 02:35 UTC daily -- after EPSS data is published (~00:30 UTC) and after the TA has had time to ingest.

### metadata/default.meta

```ini
[]
access = read : [ * ], write : [ admin ]
export = system
```

Required for AppInspect validation.

## Dashboards (Dashboard Studio v2, JSON)

Both dashboards use Dashboard Studio JSON format targeting Splunk 10.x. Stored as `.json` files in `default/data/ui/views/`.

### epss_overview.json

- **Score Distribution** -- histogram of today's EPSS scores across all CVEs (log-scale bins)
- **Risk Tier Breakdown** -- bar chart: Critical/High/Medium/Low counts
- **Top 50 Highest EPSS** -- table: CVE ID, score, percentile, risk tier (sortable)
- **Biggest Daily Movers** -- table: CVEs with largest absolute score change vs. previous day (requires 2+ days of data)
- **CVE Trend Lookup** -- line chart of EPSS score over time for a user-entered CVE ID (text input token)
- **Coverage Stats** -- single value panels: total CVEs scored, mean score, count above 0.5, model version

### epss_health.json

Mirrors the CVE-TA operational_health dashboard:

- **Last Successful Ingest** -- single value from `epss:audit` where `action=ingest_complete`
- **Records Ingested Today / Total** -- single value panels
- **Days Ingested Timeline** -- bar chart: record count per `score_date`
- **Backfill Progress** -- single value: days ingested vs. lookback target
- **Error Log** -- table of `epss:audit` events where `action=error`, sorted by time
- **Index Volume** -- chart of daily event count over time
- **Checkpoint Status** -- table showing current KV Store checkpoint state
- **Source Availability** -- single value: last HTTP status code and response time
- **Model Version History** -- table showing when model_version changed over time

## Vendored Dependencies

Pure Python only (no `.so`, no binary wheels, no `.dist-info`):

- `splunklib` (Splunk Python SDK)
- `requests`
- `urllib3`
- `certifi`
- `charset_normalizer`
- `idna`

Packaging: `COPYFILE_DISABLE=1 tar czf TA-epss-1.0.0.tar.gz ...` excluding `__pycache__`, `*.pyc`, `local/`, `metadata/local.meta`, `.DS_Store`.

## CI/CD (GitHub Actions)

### ci.yml -- Lint + Unit Tests

Triggers on push and PR to `main`.

**Jobs:**

1. **lint** -- `ruff check .` and `mypy` type checking
2. **unit-tests** -- `pytest tests/ -v --cov` excluding integration-marked tests
3. **build** -- Run `scripts/build.sh`, upload `TA-epss-*.tar.gz` as artifact

### appinspect.yml -- Splunk AppInspect Validation

Triggers after CI passes (needs: [unit-tests]).

**Jobs:**

1. **appinspect** -- Install `splunk-appinspect`, run `splunk-appinspect inspect TA-epss-*.tar.gz --mode precert`
2. Fail the workflow if any `failure` results (warnings are acceptable)

### integration.yml -- Docker Integration Tests

Triggers on PR to `main` (needs: [unit-tests, appinspect]).

**Jobs:**

1. **integration** -- `docker compose -f docker-compose.test.yml up -d`
2. Wait for Splunk container health check (30-60s)
3. Install TA package into running Splunk
4. Restart Splunk, wait for health
5. Run `pytest tests/ -v -m integration` which verifies:
   - Modular input registers (`--scheme` returns valid XML)
   - Events appear in the index with correct sourcetype
   - Field extraction works (cve_id, epss_score, percentile all present)
   - Audit events are written
   - Checkpoint is created in KV Store
6. Collect screenshots of dashboards for PR review
7. Tear down containers

## Local Development & Testing

### Prerequisites

```bash
pip install -e ".[dev]"
```

### Running Tests Locally

```bash
# Unit tests
pytest tests/ -v --cov -m "not integration"

# Lint
ruff check .

# Type check
mypy TA-epss/bin/ --ignore-missing-imports
```

### Local Docker Integration Test

```bash
# Build the TA package
./scripts/build.sh

# Start Splunk + install TA
docker compose -f docker-compose.test.yml up -d

# Wait for Splunk to be ready, then run integration tests
pytest tests/ -v -m integration

# Tear down
docker compose -f docker-compose.test.yml down -v
```

### Manual Testing in Splunk

1. Build package: `./scripts/build.sh`
2. Install in local Splunk: copy `TA-epss/` to `$SPLUNK_HOME/etc/apps/`
3. Restart Splunk
4. Verify: `index=main sourcetype=epss:score | head 10`
5. Check health: `index=_internal source=*TA-epss.log`

## Screenshots

Dashboard screenshots are captured during integration tests and stored as CI artifacts for PR review. Screenshots to capture:

1. **EPSS Overview dashboard** -- full page showing score distribution, top CVEs, risk tiers
2. **EPSS Health dashboard** -- full page showing ingest status, timeline, errors
3. **Search results** -- `sourcetype=epss:score` showing field extraction working correctly
4. **KV Store lookup** -- `| inputlookup epss_current_lookup | head 10` showing correlation data

Screenshots are captured using Splunk's built-in PDF/screenshot capability or a headless browser (Playwright) in CI.

## Lessons Learned (Applied)

These are specific gotchas from the CVE-Splunk-TA and CVEICU-TA that are baked into this design:

1. **`splunk_version_requirement = *`** -- Never set a specific version; causes SLIM/AppInspect failures.
2. **`--scheme` early exit** -- Must happen before `import splunklib` to avoid import errors in some environments.
3. **`python.required = 3.13`** -- Use this instead of deprecated `python.version` for Splunk 10.2+ compatibility.
4. **Flatten JSON for KV_MODE** -- Write pre-flattened dicts as event body; raw nested JSON breaks field extraction even with `KV_MODE=json`.
5. **AppInspect metadata** -- `default.meta` must have `access = read : [ * ], write : [ admin ]` and `export = system`.
6. **Input enabled by default** -- `disabled = 0` prevents "no events" confusion when no setup page exists.
7. **Macro-based index** -- All searches use the `epss_index` macro so users can override via local config.
8. **Pure Python vendored deps** -- No `.so` files, no `dist-info` directories.
9. **macOS packaging** -- `COPYFILE_DISABLE=1` to prevent `.DS_Store` and `._*` files in tarball.

## Testing Strategy

- **Unit tests:** pytest for csv_processor (valid CSV, malformed rows, empty file, missing columns), checkpoint (get/save/dates_to_process), epss_client (mock HTTP responses, 404 handling, retry logic).
- **Integration tests:** `@pytest.mark.integration` -- download a real EPSS CSV, parse it, verify field values are in expected ranges. Docker-based tests verify end-to-end Splunk ingestion.
- **AppInspect:** Run `splunk-appinspect inspect` in CI before Docker tests.
- **Docker:** `docker-compose.test.yml` with Splunk container to verify modular input registers, events are indexed, and field extraction works.

## Out of Scope

- Real-time API queries for individual CVEs (use the `epss_current_lookup` KV Store instead)
- EPSS model retraining or custom scoring
- Direct integration with CVE-Splunk-TA (they share `cve_id` as a join key; correlation is done at search time)
