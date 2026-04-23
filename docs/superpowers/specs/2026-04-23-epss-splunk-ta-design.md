# EPSS-Splunk-TA Design Spec

**Date:** 2026-04-23
**Author:** Jerry Gamblin
**Status:** Draft (v2 -- revised after Splunk + EPSS expert review)

## Overview

A Splunk Technology Add-on that ingests daily EPSS (Exploit Prediction Scoring System) scores from FIRST's published CSV files. Modeled after the CVE-Splunk-TA architecture with simplifications appropriate to the EPSS data source.

EPSS provides a daily probability score (0.0-1.0) for every CVE, predicting the likelihood of exploitation in the next 30 days. The TA downloads the daily compressed CSV (~2MB gzipped, ~10MB uncompressed), parses ~330K rows, and writes one Splunk event per CVE per day.

## Data Source

**Primary URL pattern:** `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz`

**Legacy URL (301 redirect):** `https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz` -- redirects to the primary domain. The `requests` library follows redirects by default, but the primary domain should be used to avoid the extra round-trip.

**Latest file shortcut:** `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` -- always returns the most recent published file. Used as a fallback to discover the latest available date.

**CSV format (current, 2022-02-07 onward):**

```
#model_version:v2025.03.14,score_date:2026-04-23T12:55:00Z
cve,epss,percentile
CVE-2014-0160,0.94464,0.99921
CVE-2024-1234,0.00043,0.14832
CVE-2021-40438,5e-05,0.02318
...
```

- Line 1: Comment with model version and score date
- Line 2: Column headers
- Lines 3+: One row per CVE (~330K rows as of April 2026, growing ~30K/year)
- No authentication required
- Published daily (7 days/week, no weekend gaps), typically available by **~14:00 UTC**
- Scores may use scientific notation (e.g., `5e-05`, `7e-05`) for ~1% of rows

**Historical CSV format variations:**

| Date Range                | Comment Line | Columns                           | Notes             |
| ------------------------- | ------------ | --------------------------------- | ----------------- |
| 2021-04-14 to ~2021-08-31 | None         | `cve,epss` (2 columns)            | No percentile     |
| ~2021-09-01 to 2022-02-06 | None         | `cve,epss,percentile` (3 columns) | No comment header |
| 2022-02-07 onward         | Present      | `cve,epss,percentile` (3 columns) | Current format    |

**Minimum supported date:** 2022-02-07 (when comment line and 3-column format stabilized). The `lookback_days` parameter is capped to not reach before this date. This avoids parser complexity for legacy formats that provide incomplete data (no percentile, no model version).

**Comment line timestamp formats:** The parser must handle both `+0000` suffix (older model) and `Z` suffix (current model), and varying times of day (not always midnight).

**Row count growth:**

| Date       | Approximate Rows |
| ---------- | ---------------- |
| 2022-01-01 | ~79,500          |
| 2023-01-01 | ~192,000         |
| 2024-01-01 | ~220,900         |
| 2025-01-01 | ~271,700         |
| 2026-04-22 | ~328,400         |

**Model version transitions:** EPSS periodically updates its model (e.g., `v2023.03.01` to `v2025.03.14` on 2025-03-17). Model transitions cause score discontinuities -- the same CVE's score may change dramatically overnight due to the model change, not a change in threat. The TA tracks `model_version` per event to enable filtering by model era.

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
│   ├── eventtypes.conf
│   ├── tags.conf
│   ├── collections.conf
│   ├── macros.conf
│   ├── savedsearches.conf
│   └── data/ui/views/
│       ├── epss_overview.json     # Dashboard Studio (JSON, UDF v2)
│       └── epss_health.json       # Dashboard Studio (JSON, UDF v2)
├── lookups/
│   └── epss_daily_summary.csv     # Daily aggregate stats (header-only seed)
├── metadata/
│   ├── default.meta
│   └── local.meta
├── static/
│   └── appIcon.png
├── README/
│   └── inputs.conf.spec           # Documents custom input parameters
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

**`--scheme` early exit:** Check `sys.argv` for `--scheme` before any imports, print XML schema definition, flush stdout, `sys.exit(0)`. This avoids splunklib import issues in some environments.

The `--scheme` output must be:

```xml
<scheme>
    <title>epss</title>
    <description>Ingests daily EPSS scores from FIRST</description>
    <use_external_validation>false</use_external_validation>
    <use_single_instance>false</use_single_instance>
    <streaming_mode>xml</streaming_mode>
    <endpoint>
        <args>
            <arg name="index">
                <title>Index</title>
                <description>Splunk index for EPSS events</description>
                <required_on_create>false</required_on_create>
                <data_type>string</data_type>
            </arg>
            <arg name="lookback_days">
                <title>Lookback Days</title>
                <description>Days of historical data to backfill on first run (max 1500)</description>
                <required_on_create>false</required_on_create>
                <data_type>number</data_type>
            </arg>
            <arg name="batch_size">
                <title>Batch Size</title>
                <description>Number of events per write batch</description>
                <required_on_create>false</required_on_create>
                <data_type>number</data_type>
            </arg>
            <arg name="epss_base_url">
                <title>EPSS Base URL</title>
                <description>Base URL for EPSS CSV downloads</description>
                <required_on_create>false</required_on_create>
                <data_type>string</data_type>
            </arg>
        </args>
    </endpoint>
</scheme>
```

**CRITICAL:** The `<title>` element must be exactly `epss` to match the `[epss://default]` stanza in `inputs.conf`. If these do not match, the input silently never fires.

**Class structure:** The script defines a class extending `splunklib.modularinput.Script` and overrides:

- `get_scheme(self)`: Returns the Scheme object (only reached if `--scheme` early exit is bypassed)
- `validate_input(self, validation_definition)`: Validates input parameters (stub, returns True)
- `stream_events(self, inputs, ew)`: Main entry point called by Splunk scheduler

**`sys.path` setup:** Insert `bin/` and `bin/lib/` into `sys.path` before importing vendored dependencies.

**`_process_input()`:** Orchestrates download/parse/write loop:

1. Read checkpoint to get last ingested date
2. Calculate dates to process (backfill or catch-up)
3. For each date: download CSV, parse, write events in batches, update checkpoint

**`_write_batch()`:** Converts processed rows to Splunk events with `sourcetype=epss:score`. Must explicitly set `sourcetype`, `source`, and `index` on every `Event` object -- never rely on `inputs.conf` for these.

**`_write_audit_event()`:** Writes operational events with `sourcetype=epss:audit`.

**`source` field:** Set to `epss` on all events for clean SPL filtering.

### epss_client.py (HTTP Client)

- **`download_scores(date: str) -> bytes`:** Downloads `{base_url}/epss_scores-{date}.csv.gz` via HTTP GET. Returns decompressed CSV content.
- **`download_current() -> tuple[str, bytes]`:** Downloads `{base_url}/epss_scores-current.csv.gz`. Returns `(score_date, csv_content)`. Used as fallback to discover latest available date.
- **`check_availability(date: str) -> bool`:** HEAD request to check if a date's file exists (for backfill boundary detection).
- **`base_url`:** Defaults to `https://epss.empiricalsecurity.com`, configurable via `epss_base_url` input parameter.
- Supports optional proxy configuration via Splunk's proxy settings.
- Retries with exponential backoff (3 attempts) for transient HTTP errors (502/503/504, timeouts).
- Raises specific exceptions for 404 (date not available) vs. other failures.
- **Politeness delay:** 1-second delay between sequential downloads during backfill to be a good citizen to FIRST's servers.

### csv_processor.py (CSV Parser)

- **`parse_csv(csv_content: str) -> Iterator[dict]`:** Yields one dict per row.
- Parses comment line (if present) to extract `model_version` and `score_date`. Handles both `+0000` and `Z` timezone suffixes, and varying times of day. Extracts only the date portion (`YYYY-MM-DD`) for `score_date`.
- If no comment line is present, falls back to date from filename (passed as parameter).
- **Scientific notation handling:** Uses Python's `float()` which handles `5e-05` natively. No regex-based float validation.
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
- **Risk tier calculation (percentile-based):**
  - Critical: percentile >= 0.99 (top 1%)
  - High: percentile >= 0.95 (top 5%)
  - Medium: percentile >= 0.90 (top 10%)
  - Low: percentile < 0.90

  These thresholds are based on percentile rather than raw score, which produces a more useful distribution and aligns with how FIRST recommends interpreting EPSS (via percentile rank). Approximate distribution: Critical ~1%, High ~4%, Medium ~5%, Low ~90%. These are not FIRST-endorsed tiers -- they are TA defaults for user convenience and are documented as such.

- Validates CVE ID format (`CVE-\d{4}-\d{4,}`), skips malformed rows with warning.
- **Data integrity checks:** Validates `epss_score` and `percentile` are between 0.0 and 1.0. Logs warnings for out-of-range values.
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
  - `get_dates_to_process(lookback_days: int) -> list[str]`: Returns list of dates from `last_date_ingested + 1` through yesterday (or from `today - lookback_days` if no checkpoint exists). Uses yesterday as the upper bound since today's file may not be published yet. Caps lookback to not go before 2022-02-07 (minimum supported date).

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

1. Modular input fires (cron: `0 18 * * *`, daily at 18:00 UTC)
2. Checkpoint is empty -> calculate start date as `today - lookback_days` (default: 30, capped at 2022-02-07)
3. For each date from start through **yesterday**:
   a. Download `epss_scores-{date}.csv.gz` (1-second delay between downloads)
   b. Decompress, parse CSV (~330K rows)
   c. Write events in batches of 5000 with `sourcetype=epss:score`
   d. Write audit event: `{"action": "ingest_complete", "score_date": "...", "records": 328400}`
   e. Update checkpoint with this date
4. Then attempt today's file:
   a. Try date-specific URL first
   b. If 404, try `epss_scores-current.csv.gz` as fallback
   c. If still unavailable (too early), skip -- will be picked up tomorrow
5. If download fails for a date with 404, skip and continue to next date

### Daily Operation

1. Checkpoint shows `last_date_ingested = 2026-04-22`
2. Input fires at 18:00 UTC (well after ~14:00 UTC publish time)
3. Download 2026-04-23, parse, write, update checkpoint
4. Done until next scheduled run

### Catch-Up After Downtime

- TA disabled for 5 days -> checkpoint is 5 days old
- Next run processes all 5 missed days sequentially (with 1s delay between downloads)
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
  "timestamp": "2026-04-23T18:15:32.123Z",
  "action": "ingest_complete",
  "score_date": "2026-04-23",
  "records_ingested": 328362,
  "duration_seconds": 45.2,
  "http_status": 200,
  "file_size_bytes": 2188618
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

### app.manifest

```json
{
  "schemaVersion": "2.0.0",
  "info": {
    "title": "EPSS Scores for Splunk",
    "id": {
      "group": null,
      "name": "TA-epss",
      "version": "1.0.0"
    },
    "author": [
      {
        "name": "Jerry Gamblin"
      }
    ],
    "releaseDate": null,
    "description": "Ingests daily EPSS (Exploit Prediction Scoring System) scores from FIRST",
    "classification": {
      "intendedAudience": "Security",
      "categories": ["Security, Fraud & Compliance"],
      "developmentStatus": "Production/Stable"
    },
    "commonInformationModels": {
      "Vulnerabilities": ">=5.0.0"
    },
    "license": {
      "name": "MIT",
      "text": "LICENSE",
      "uri": null
    },
    "privacyPolicy": {
      "name": null,
      "text": null,
      "uri": null
    },
    "releaseNotes": {
      "name": "README",
      "text": "README.md",
      "uri": null
    }
  },
  "dependencies": null,
  "tasks": null,
  "inputGroups": null,
  "incompatibleApps": null,
  "platformRequirements": null,
  "supportedDeployments": [
    "_standalone",
    "_distributed",
    "_search_head_clustering"
  ],
  "targetWorkloads": ["_search_heads"]
}
```

### inputs.conf

```ini
[epss]
python.version = python3
python.required = 3.9

[epss://default]
index = main
lookback_days = 30
batch_size = 5000
epss_base_url = https://epss.empiricalsecurity.com
interval = 0 18 * * *
disabled = 0
```

- `python.version = python3` retained for backward compatibility with Splunk 9.x
- `python.required = 3.9` for Splunk 10.2+ (not pinned to 3.13 to support broader installs)
- `disabled = 0` so input is enabled by default (documented in AppInspect response notes)
- `interval = 0 18 * * *` uses cron syntax to fire daily at 18:00 UTC, well after the ~14:00 UTC EPSS publish time
- `batch_size = 5000` for better throughput (330K rows / 5000 = 66 batch writes vs. 660 at batch_size=500)
- `epss_base_url` configurable so users can update if the domain changes

### README/inputs.conf.spec

```ini
[epss://default]
index = <string>
* Splunk index for EPSS events
* Default: main

lookback_days = <integer>
* Number of days of historical data to backfill on first run
* Maximum effective lookback is to 2022-02-07 (earliest supported CSV format)
* Default: 30

batch_size = <integer>
* Number of events per write batch
* Higher values improve throughput but use more memory
* Default: 5000

epss_base_url = <string>
* Base URL for EPSS CSV file downloads
* Default: https://epss.empiricalsecurity.com

interval = <cron expression or seconds>
* How often to run the input
* Recommended: cron expression targeting late afternoon UTC (after ~14:00 UTC publish time)
* Default: 0 18 * * *
```

### props.conf

```ini
[epss:score]
KV_MODE = json
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_FORMAT = %Y-%m-%d
TIME_PREFIX = "score_date"\s*:\s*"
MAX_TIMESTAMP_LOOKAHEAD = 10
TRUNCATE = 10000

FIELDALIAS-vulnerability_id = cve_id AS vulnerability_id
FIELDALIAS-severity_score = epss_score AS severity_score
FIELDALIAS-signature = cve_id AS signature
FIELDALIAS-signature_id = cve_id AS signature_id

[epss:audit]
KV_MODE = json
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%f
TIME_PREFIX = "timestamp"\s*:\s*"
TRUNCATE = 10000
```

- Removed `FIELDALIAS-dest`: in CIM, `dest` is the affected host/asset, not the CVE ID. EPSS data has no host information.
- `TRUNCATE = 10000` instead of 0 (unlimited) to catch malformed oversized events.
- Audit `TIME_FORMAT` uses `%f` (microseconds) which is portable across Splunk versions. Audit events emit timestamps with `Z` suffix which Splunk recognizes.

### eventtypes.conf

```ini
[epss_score]
search = sourcetype=epss:score
```

### tags.conf

```ini
[eventtype=epss_score]
vulnerability = enabled
report = enabled
```

Required for CIM Vulnerabilities data model compliance. Without these, Splunk ES and CIM-aware apps will not discover EPSS data.

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
field.cve_id = string
field.epss_score = number
field.percentile = number
field.epss_risk_tier = string
field.score_date = string
field.model_version = string
accelerated_fields.cve_id = {"cve_id": 1}
enforceTypes = true
replicate = true
```

- `ta_epss_checkpoints`: No replication, no type enforcement (local to each search head)
- `epss_current_lookup`: Typed fields, accelerated index on `cve_id` for fast lookups on ~330K rows, replicated for search head clusters

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
search = `epss_index` sourcetype=epss:score earliest=-1d@d latest=now \
  | stats latest(epss_score) as epss_score latest(percentile) as percentile \
    latest(epss_risk_tier) as epss_risk_tier latest(score_date) as score_date \
    latest(model_version) as model_version by cve_id \
  | outputlookup epss_current_lookup
cron_schedule = 0 20 * * *
enableSched = 1
dispatch.earliest_time = -1d@d
dispatch.latest_time = now
dispatch.max_time = 900
dispatch.auto_cancel = 1800
description = Refreshes the EPSS current scores KV Store lookup with the most recent day's scores

[EPSS Daily Summary Refresh]
search = `epss_index` sourcetype=epss:score earliest=-1d@d latest=now \
  | stats count as total_cves \
    avg(epss_score) as mean_score median(epss_score) as median_score \
    max(epss_score) as max_score \
    sum(if(percentile>=0.99,1,0)) as critical_count \
    sum(if(percentile>=0.95 AND percentile<0.99,1,0)) as high_count \
    sum(if(percentile>=0.90 AND percentile<0.95,1,0)) as medium_count \
    sum(if(percentile<0.90,1,0)) as low_count \
    by score_date \
  | sort -score_date \
  | head 1 \
  | outputlookup epss_daily_summary.csv
cron_schedule = 5 20 * * *
enableSched = 1
dispatch.earliest_time = -1d@d
dispatch.latest_time = now
dispatch.max_time = 900
dispatch.auto_cancel = 1800
description = Refreshes the daily EPSS summary stats lookup for the most recent day
```

- Saved searches run at 20:00 and 20:05 UTC -- 2 hours after the 18:00 UTC input run
- `EPSS Daily Summary Refresh` now correctly groups `by score_date` and takes only the most recent day (`sort -score_date | head 1`)
- Both searches have `dispatch.max_time = 900` (15 min) and `dispatch.auto_cancel = 1800` (30 min) to prevent runaway searches
- Time range `earliest=-1d@d` to cover yesterday and today

### metadata/default.meta

```ini
[]
access = read : [ * ], write : [ admin ]
export = system
```

Required for AppInspect validation.

### lookups/epss_daily_summary.csv (seed file, header only)

```csv
score_date,total_cves,mean_score,median_score,max_score,critical_count,high_count,medium_count,low_count
```

Shipped with headers only so `| inputlookup epss_daily_summary.csv` does not error before the first saved search run.

Note: The KV Store `epss_current_lookup` is created automatically by `collections.conf` and does not need a seed file. No CSV file for current scores -- the KV Store is the single mechanism for current EPSS lookups, avoiding the confusion of having both a CSV and KV Store with similar names.

## Dashboards (Dashboard Studio, UDF v2 JSON)

Both dashboards use Unified Dashboard Framework (UDF) v2 JSON format for Splunk 10.x Dashboard Studio. Stored as `.json` files in `default/data/ui/views/`.

UDF v2 structure:

```json
{
  "visualizations": { ... },
  "dataSources": { ... },
  "defaults": { ... },
  "inputs": { ... },
  "layout": {
    "type": "grid",
    ...
  }
}
```

### epss_overview.json

- **Score Distribution** -- histogram of today's EPSS scores across all CVEs (log-scale bins)
- **Risk Tier Breakdown** -- bar chart: Critical/High/Medium/Low counts (percentile-based tiers)
- **Top 50 Highest EPSS** -- table: CVE ID, score, percentile, risk tier (sortable)
- **Biggest Daily Movers** -- table: CVEs with largest absolute score change vs. previous day, **filtered to same model_version only** to avoid false positives from model transitions
- **CVE Trend Lookup** -- line chart of EPSS score over time for a user-entered CVE ID (text input token), with **model version transitions annotated** as vertical markers
- **Coverage Stats** -- single value panels: total CVEs scored, mean score, count in Critical tier, model version

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
2. Wait for Splunk container health check (loop with 10s intervals, 60s timeout)
3. Install TA package into running Splunk
4. Restart Splunk, wait for health check again (modular inputs need restart to register)
5. Run `pytest tests/ -v -m integration` which verifies:
   - Modular input registers (`--scheme` returns valid XML with `<title>epss</title>`)
   - Events appear in the index with correct sourcetype
   - Field extraction works (cve_id, epss_score, percentile all present and typed correctly)
   - Scientific notation scores are parsed correctly
   - Audit events are written
   - Checkpoint is created in KV Store
6. **Capture screenshots** using Playwright (headless Chromium):
   - EPSS Overview dashboard -- full page
   - EPSS Health dashboard -- full page
   - Search results for `sourcetype=epss:score | head 20`
   - KV Store lookup: `| inputlookup epss_current_lookup | head 10`
7. Upload screenshots as CI artifacts for PR review
8. Tear down containers

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
5. Check field extraction: `index=main sourcetype=epss:score | table cve_id epss_score percentile score_date model_version epss_risk_tier`
6. Check health: `index=_internal source=*TA-epss.log`

## Screenshots

Dashboard screenshots are captured during integration tests via Playwright and stored as CI artifacts for PR review. Screenshots to capture:

1. **EPSS Overview dashboard** -- full page showing score distribution, top CVEs, risk tiers
2. **EPSS Health dashboard** -- full page showing ingest status, timeline, errors
3. **Search results** -- `sourcetype=epss:score` showing field extraction working correctly
4. **KV Store lookup** -- `| inputlookup epss_current_lookup | head 10` showing correlation data

## Lessons Learned (Applied)

These are specific gotchas from the CVE-Splunk-TA and CVEICU-TA that are baked into this design:

1. **`splunk_version_requirement = *`** -- Never set a specific version; causes SLIM/AppInspect failures.
2. **`--scheme` early exit** -- Must happen before `import splunklib` to avoid import errors in some environments. The `<title>` must match the input stanza name exactly.
3. **`python.version` + `python.required`** -- Keep both for compatibility. `python.version = python3` for 9.x, `python.required = 3.9` for 10.2+.
4. **Flatten JSON for KV_MODE** -- Write pre-flattened dicts as event body; raw nested JSON breaks field extraction even with `KV_MODE=json`.
5. **AppInspect metadata** -- `default.meta` must have `access = read : [ * ], write : [ admin ]` and `export = system`.
6. **AppInspect manifest** -- `app.manifest` must be present with valid schema or AppInspect fails.
7. **Input enabled by default** -- `disabled = 0` prevents "no events" confusion when no setup page exists.
8. **Macro-based index** -- All searches use the `epss_index` macro so users can override via local config.
9. **Pure Python vendored deps** -- No `.so` files, no `dist-info` directories.
10. **macOS packaging** -- `COPYFILE_DISABLE=1` to prevent `.DS_Store` and `._*` files in tarball.
11. **Set sourcetype explicitly on Event objects** -- Never rely on inputs.conf for sourcetype in modular inputs.
12. **README/inputs.conf.spec** -- Required to document custom input parameters for AppInspect.

## Testing Strategy

- **Unit tests:** pytest for csv_processor (valid CSV, malformed rows, empty file, missing columns, scientific notation scores, both comment line timestamp formats, data integrity validation), checkpoint (get/save/dates_to_process, 2022-02-07 floor), epss_client (mock HTTP responses, 404 handling, retry logic, redirect following, current URL fallback).
- **Integration tests:** `@pytest.mark.integration` -- download a real EPSS CSV, parse it, verify field values are in expected ranges. Docker-based tests verify end-to-end Splunk ingestion, field extraction, and KV Store population.
- **AppInspect:** Run `splunk-appinspect inspect` in CI before Docker tests.
- **Docker:** `docker-compose.test.yml` with Splunk container to verify modular input registers, events are indexed, and field extraction works. Includes Playwright for dashboard screenshots.

## Out of Scope

- Real-time API queries for individual CVEs (use the `epss_current_lookup` KV Store instead)
- EPSS model retraining or custom scoring
- Direct integration with CVE-Splunk-TA (they share `cve_id` as a join key; correlation is done at search time)
- Historical CSV formats prior to 2022-02-07 (2-column and no-comment-line eras)
- Automatic lookup enrichment of other sourcetypes (users can manually add `| lookup epss_current_lookup cve_id` to their searches)
