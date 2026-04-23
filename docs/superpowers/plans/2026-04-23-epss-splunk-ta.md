# EPSS-Splunk-TA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Splunk Technology Add-on that ingests daily EPSS scores from FIRST's published CSV files into Splunk events.

**Architecture:** Modular input TA modeled after CVE-Splunk-TA. Downloads daily gzipped CSV from `epss.empiricalsecurity.com`, parses ~330K rows per file, writes one Splunk event per CVE per day. KV Store checkpoint tracks last ingested date. Dashboard Studio dashboards for analytics and health monitoring.

**Tech Stack:** Python 3.9+, splunklib (Splunk SDK), requests, pytest, ruff, GitHub Actions, Docker, Playwright

**Spec:** `docs/superpowers/specs/2026-04-23-epss-splunk-ta-design.md`

**Reference TA:** `~/Documents/Github/CVE-Splunk-TA/` (working Splunk modular input)

---

## File Map

| File                                              | Responsibility                                                    |
| ------------------------------------------------- | ----------------------------------------------------------------- |
| `TA-epss/bin/epss.py`                             | Modular input entry point: --scheme, stream_events, batch writing |
| `TA-epss/bin/epss_lib/__init__.py`                | Package marker                                                    |
| `TA-epss/bin/epss_lib/epss_client.py`             | HTTP client: download gzipped CSV, retry, politeness delay        |
| `TA-epss/bin/epss_lib/csv_processor.py`           | Parse CSV: comment line, rows, risk tiers, validation             |
| `TA-epss/bin/epss_lib/checkpoint.py`              | KV Store checkpoint: dates to process, save/load state            |
| `TA-epss/bin/epss_lib/credential.py`              | Proxy credential retrieval from Splunk secure storage             |
| `TA-epss/bin/epss_lib/logging_config.py`          | Rotating file logger for TA-epss.log                              |
| `TA-epss/default/app.conf`                        | App metadata                                                      |
| `TA-epss/default/inputs.conf`                     | Modular input definition + default instance                       |
| `TA-epss/default/props.conf`                      | Sourcetype definitions, field aliases                             |
| `TA-epss/default/transforms.conf`                 | KV Store lookup definition                                        |
| `TA-epss/default/collections.conf`                | KV Store collections with typed fields                            |
| `TA-epss/default/eventtypes.conf`                 | CIM event type mapping                                            |
| `TA-epss/default/tags.conf`                       | CIM vulnerability tags                                            |
| `TA-epss/default/macros.conf`                     | Index macro                                                       |
| `TA-epss/default/savedsearches.conf`              | Lookup refresh searches                                           |
| `TA-epss/default/data/ui/views/epss_overview.xml` | Overview dashboard (UDF v2 JSON in XML CDATA)                     |
| `TA-epss/default/data/ui/views/epss_health.xml`   | Health dashboard (UDF v2 JSON in XML CDATA)                       |
| `TA-epss/default/data/ui/nav/default.xml`         | Navigation menu                                                   |
| `TA-epss/lookups/epss_daily_summary.csv`          | Seed CSV with headers only                                        |
| `TA-epss/metadata/default.meta`                   | AppInspect required metadata                                      |
| `TA-epss/metadata/local.meta`                     | Empty local metadata                                              |
| `TA-epss/README/inputs.conf.spec`                 | Custom input parameter documentation                              |
| `TA-epss/static/appIcon.png`                      | App icon                                                          |
| `TA-epss/app.manifest`                            | AppInspect manifest                                               |
| `tests/conftest.py`                               | Test fixtures and path setup                                      |
| `tests/unit/test_csv_processor.py`                | CSV parser unit tests                                             |
| `tests/unit/test_checkpoint.py`                   | Checkpoint manager unit tests                                     |
| `tests/unit/test_epss_client.py`                  | HTTP client unit tests                                            |
| `tests/unit/test_epss_input.py`                   | Modular input --scheme test                                       |
| `tests/fixtures/epss_sample.csv`                  | Sample EPSS CSV test fixture                                      |
| `tests/fixtures/epss_sample_old_tz.csv`           | Old timezone format fixture                                       |
| `.github/workflows/ci.yml`                        | Lint + unit tests + appinspect + docker integration               |
| `docker-compose.test.yml`                         | Docker Splunk test container                                      |
| `scripts/build.sh`                                | Package build script                                              |
| `scripts/vendor.sh`                               | Dependency vendoring script                                       |
| `pyproject.toml`                                  | Project config: dependencies, ruff, pytest                        |
| `requirements.txt`                                | Pinned runtime deps for vendoring                                 |

---

## Task 1: Project Scaffolding and Splunk Configuration

**Files:**

- Create: `pyproject.toml`, `requirements.txt`
- Create: `TA-epss/bin/epss_lib/__init__.py`
- Create: All files under `TA-epss/default/`, `TA-epss/metadata/`, `TA-epss/README/`, `TA-epss/lookups/`
- Create: `TA-epss/app.manifest`

- [ ] **Step 1: Create pyproject.toml**

Create `pyproject.toml` with contents:

```toml
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.build_meta"

[project]
name = "TA-epss"
version = "1.0.0"
description = "Splunk Technology Add-on for EPSS score ingestion"
requires-python = ">=3.9"
license = {text = "MIT"}
authors = [{name = "Jerry Gamblin"}]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-cov>=4.0",
    "pytest-mock>=3.10",
    "ruff>=0.4.0",
    "mypy>=1.8",
    "requests-mock>=1.11",
]

[tool.ruff]
target-version = "py39"
line-length = 100

[tool.ruff.lint]
select = ["E", "F", "I", "N", "W", "UP"]

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
    "integration: marks tests requiring Docker Splunk (deselect with '-m not integration')",
]
```

- [ ] **Step 2: Create requirements.txt**

```
requests>=2.31.0,<3.0.0
urllib3>=2.0.0,<3.0.0
certifi>=2023.7.22
charset-normalizer>=3.0.0,<4.0.0
idna>=3.4,<4.0.0
splunk-sdk>=2.0.0
```

- [ ] **Step 3: Create TA-epss/bin/epss_lib/**init**.py (empty file)**

- [ ] **Step 4: Create all Splunk config files**

See spec for exact contents of each file. Create these files exactly as specified in the design spec (section "Splunk Configuration"):

- `TA-epss/default/app.conf`
- `TA-epss/default/inputs.conf`
- `TA-epss/default/props.conf`
- `TA-epss/default/transforms.conf`
- `TA-epss/default/collections.conf`
- `TA-epss/default/eventtypes.conf`
- `TA-epss/default/tags.conf`
- `TA-epss/default/macros.conf`
- `TA-epss/default/savedsearches.conf`
- `TA-epss/metadata/default.meta`
- `TA-epss/metadata/local.meta` (empty)
- `TA-epss/README/inputs.conf.spec`
- `TA-epss/lookups/epss_daily_summary.csv` (header row only)
- `TA-epss/app.manifest`

- [ ] **Step 5: Commit scaffolding**

```bash
git add pyproject.toml requirements.txt TA-epss/
git commit -m "feat: scaffold TA-epss with Splunk config files and project setup"
```

---

## Task 2: Logging and Credential Modules

**Files:**

- Create: `TA-epss/bin/epss_lib/logging_config.py`
- Create: `TA-epss/bin/epss_lib/credential.py`

- [ ] **Step 1: Create logging_config.py**

Adapted from `~/Documents/Github/CVE-Splunk-TA/TA-cvelist/bin/cvelist_lib/logging_config.py`. Change all `ta_cvelist`/`TA-cvelist` references to `ta_epss`/`TA-epss`.

```python
import logging
import logging.handlers
import os
from typing import Optional


def setup_logging(
    log_level: str = "INFO",
    log_name: str = "ta_epss",
    splunk_home: Optional[str] = None,
) -> logging.Logger:
    if splunk_home is None:
        splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")

    log_dir = os.path.join(splunk_home, "var", "log", "splunk")
    log_file = os.path.join(log_dir, "TA-epss.log")

    try:
        os.makedirs(log_dir, exist_ok=True)
    except OSError:
        log_file = "TA-epss.log"

    logger = logging.getLogger(log_name)
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S %z",
    )

    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(numeric_level)
        logger.addHandler(file_handler)
    except (OSError, IOError):
        pass

    stderr_handler = logging.StreamHandler()
    stderr_handler.setFormatter(formatter)
    stderr_handler.setLevel(numeric_level)
    logger.addHandler(stderr_handler)

    logger.propagate = False
    return logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"ta_epss.{name}")
```

- [ ] **Step 2: Create credential.py**

Adapted from CVE-TA. Changed realm to `TA-epss`, returns proxy config instead of GitHub token.

```python
import logging
from typing import Optional

try:
    import splunklib.client as client
except ImportError:
    client = None


class CredentialManager:
    REALM = "TA-epss"

    def __init__(
        self,
        session_key: str,
        splunk_uri: str = "https://localhost:8089",
        app: str = "TA-epss",
        logger: Optional[logging.Logger] = None,
    ):
        self.session_key = session_key
        self.splunk_uri = splunk_uri
        self.app = app
        self.logger = logger or logging.getLogger("ta_epss.credential")
        self._service = None

    @property
    def service(self):
        if self._service is None:
            if client is None:
                raise ImportError("splunklib is required for credential management")
            from urllib.parse import urlparse

            parsed = urlparse(self.splunk_uri)
            self._service = client.connect(
                token=self.session_key,
                host=parsed.hostname or "localhost",
                port=parsed.port or 8089,
                app=self.app,
                autologin=True,
            )
        return self._service

    def get_proxy_config(self) -> Optional[dict]:
        try:
            for credential in self.service.storage_passwords:
                if credential.realm == self.REALM:
                    self.logger.debug("Proxy config retrieved from secure storage")
                    return {"https": credential.clear_password}
            self.logger.info("No proxy configured - using direct connection")
            return None
        except Exception as e:
            self.logger.warning(f"Could not retrieve proxy config: {e}")
            return None
```

- [ ] **Step 3: Commit**

```bash
git add TA-epss/bin/epss_lib/logging_config.py TA-epss/bin/epss_lib/credential.py
git commit -m "feat: add logging and credential modules"
```

---

## Task 3: CSV Processor with TDD

**Files:**

- Create: `tests/conftest.py`, `tests/fixtures/epss_sample.csv`, `tests/fixtures/epss_sample_old_tz.csv`
- Create: `tests/unit/test_csv_processor.py`
- Create: `TA-epss/bin/epss_lib/csv_processor.py`

- [ ] **Step 1: Create test fixtures**

`tests/conftest.py`:

```python
import os
import sys

BIN_DIR = os.path.join(os.path.dirname(__file__), "..", "TA-epss", "bin")
LIB_DIR = os.path.join(BIN_DIR, "lib")
sys.path.insert(0, BIN_DIR)
sys.path.insert(0, LIB_DIR)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
```

`tests/fixtures/epss_sample.csv` -- 7 rows covering all risk tiers and scientific notation:

```
#model_version:v2025.03.14,score_date:2026-04-23T12:55:00Z
cve,epss,percentile
CVE-2014-0160,0.94464,0.99921
CVE-2024-1234,0.00043,0.14832
CVE-2021-40438,5e-05,0.02318
CVE-2023-23752,0.94520,0.99940
CVE-2020-1472,0.50123,0.97500
CVE-2021-44228,0.93000,0.99800
CVE-2019-0708,0.70100,0.98900
```

`tests/fixtures/epss_sample_old_tz.csv` -- old `+0000` timestamp format:

```
#model_version:v2023.03.01,score_date:2024-01-15T00:00:00+0000
cve,epss,percentile
CVE-2014-0160,0.97565,0.99996
CVE-2024-1234,0.00043,0.14832
```

- [ ] **Step 2: Write failing tests**

`tests/unit/test_csv_processor.py` -- 12 test cases covering: standard parsing, old timezone, scientific notation, all 4 risk tiers, malformed CVE IDs, out-of-range scores, empty input, fallback date, stats tracking. (See full test code in spec section "csv_processor.py".)

Key tests:

- `test_parses_standard_csv`: 7 rows, checks all fields on first row
- `test_handles_old_timezone_format`: verifies `+0000` suffix parses to correct date
- `test_handles_scientific_notation`: `5e-05` parses as float 0.00005
- `test_risk_tier_critical/high/medium/low`: percentile-based tier assignment
- `test_skips_malformed_cve_id`: `NOT-A-CVE` filtered out
- `test_skips_out_of_range_scores`: epss > 1.0 filtered out
- `test_empty_csv_returns_empty`: no crash on empty string
- `test_fallback_date_when_no_comment`: uses `fallback_date` param
- `test_stats_tracking`: parsed and skipped counts

- [ ] **Step 3: Run tests to verify they fail**

Run: `PYTHONPATH=TA-epss/bin pytest tests/unit/test_csv_processor.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'epss_lib'`

- [ ] **Step 4: Implement csv_processor.py**

Module-level functions (not a class): `parse_csv(content, fallback_date=None)`, `get_stats()`, `reset_stats()`, `_calculate_risk_tier(percentile)`, `_parse_comment_line(line)`.

Key implementation details:

- Uses `csv.DictReader` on remaining content after comment line
- `float()` for parsing (handles scientific notation natively)
- CVE ID validated with regex `^CVE-\d{4}-\d{4,}$`
- Score range validation: 0.0 <= score <= 1.0
- Percentile-based tiers: Critical >= 0.99, High >= 0.95, Medium >= 0.90, Low < 0.90

- [ ] **Step 5: Run tests to verify they pass**

Run: `PYTHONPATH=TA-epss/bin pytest tests/unit/test_csv_processor.py -v`
Expected: All 12 tests PASS

- [ ] **Step 6: Commit**

```bash
git add tests/ TA-epss/bin/epss_lib/csv_processor.py
git commit -m "feat: add CSV processor with TDD tests"
```

---

## Task 4: EPSS HTTP Client with TDD

**Files:**

- Create: `tests/unit/test_epss_client.py`
- Create: `TA-epss/bin/epss_lib/epss_client.py`

- [ ] **Step 1: Write failing tests**

7 test cases using `requests_mock` fixture:

- `test_download_scores_success`: gzip-compressed CSV, decompresses correctly
- `test_download_scores_404_raises`: raises `EPSSNotAvailable`
- `test_download_scores_server_error_retries`: 502, 503, then success
- `test_download_current`: parses date from comment line
- `test_custom_base_url`: configurable base URL
- `test_check_availability_true/false`: HEAD request returns 200/404

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=TA-epss/bin pytest tests/unit/test_epss_client.py -v`
Expected: FAIL

- [ ] **Step 3: Implement epss_client.py**

Classes: `EPSSClient`, `EPSSNotAvailable(Exception)`, `EPSSDownloadError(Exception)`.

Key methods:

- `download_scores(date) -> str`: GET + gzip decompress
- `download_current() -> tuple[str, str]`: downloads current.csv.gz, extracts date
- `check_availability(date) -> bool`: HEAD request
- `_get_with_retry(url)`: exponential backoff, 3 attempts, distinguishes 404 from 5xx

- [ ] **Step 4: Run tests to verify they pass**

Run: `pip install requests-mock && PYTHONPATH=TA-epss/bin pytest tests/unit/test_epss_client.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_epss_client.py TA-epss/bin/epss_lib/epss_client.py
git commit -m "feat: add EPSS HTTP client with retry logic and TDD tests"
```

---

## Task 5: Checkpoint Manager with TDD

**Files:**

- Create: `tests/unit/test_checkpoint.py`
- Create: `TA-epss/bin/epss_lib/checkpoint.py`

- [ ] **Step 1: Write failing tests**

7 test cases:

- `test_default_checkpoint`: correct \_key, null last_date_ingested, zero records
- `test_get_dates_no_checkpoint_30_day_lookback`: 30 dates from today-30 to yesterday
- `test_get_dates_with_existing_checkpoint`: starts from last_date_ingested + 1
- `test_get_dates_caps_at_minimum_date`: never goes before 2022-02-07
- `test_get_dates_already_current_returns_empty`: returns [] when up to date
- `test_save_checkpoint_accumulates_records`: records_processed adds to total
- `test_save_checkpoint_error_tracking`: consecutive_errors increments, resets on success

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=TA-epss/bin pytest tests/unit/test_checkpoint.py -v`
Expected: FAIL

- [ ] **Step 3: Implement checkpoint.py**

Adapted from CVE-TA's `checkpoint.py`. Key differences:

- `COLLECTION_NAME = "ta_epss_checkpoints"`, app = `"TA-epss"`
- Tracks `last_date_ingested` instead of `last_release_tag`
- `get_dates_to_process(lookback_days)` method calculates date range
- `MINIMUM_SUPPORTED_DATE = "2022-02-07"` constant for lookback cap
- No `is_initial_load_needed()` or `should_process_cve()` (simpler than CVE-TA)

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=TA-epss/bin pytest tests/unit/test_checkpoint.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_checkpoint.py TA-epss/bin/epss_lib/checkpoint.py
git commit -m "feat: add checkpoint manager with date calculation and TDD tests"
```

---

## Task 6: Modular Input Entry Point

**Files:**

- Create: `tests/unit/test_epss_input.py`
- Create: `TA-epss/bin/epss.py`

- [ ] **Step 1: Write failing tests for --scheme output**

3 tests:

- `test_scheme_returns_valid_xml`: subprocess runs `epss.py --scheme`, parses XML, exit code 0
- `test_scheme_title_matches_input_stanza`: `<title>` text is exactly `epss`
- `test_scheme_has_required_args`: contains `index`, `lookback_days`, `batch_size`, `epss_base_url`

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_epss_input.py -v`
Expected: FAIL (epss.py does not exist)

- [ ] **Step 3: Implement epss.py**

Structure follows CVE-TA's `cvelist.py` pattern:

- Lines 1-38: `--scheme` early exit (hardcoded XML, flush, exit)
- Lines 40+: imports after early exit
- `EPSSInput(Script)` class with:
  - `get_scheme()`, `validate_input()`, `stream_events()`
  - `_process_input()`: reads config, creates client/checkpoint/processor, loops over dates
  - `_write_events_batched()`: chunks records into batches
  - `_write_batch()`: creates Event objects with explicit sourcetype/source/index/host
  - `_write_audit_event()`: operational events with action, timestamps, kwargs
- 1-second sleep between date downloads (politeness)
- `source = "epss"` on all events
- `host = "epss"` on all events

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/test_epss_input.py -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Run all unit tests together**

Run: `PYTHONPATH=TA-epss/bin pytest tests/unit/ -v`
Expected: All 29 tests PASS

- [ ] **Step 6: Commit**

```bash
git add TA-epss/bin/epss.py tests/unit/test_epss_input.py
git commit -m "feat: add modular input entry point with --scheme and stream_events"
```

---

## Task 7: Vendor Dependencies and Build Scripts

**Files:**

- Create: `scripts/vendor.sh`
- Create: `scripts/build.sh`

- [ ] **Step 1: Create scripts/vendor.sh**

Installs pure-Python deps into `TA-epss/bin/lib/`, strips `.dist-info`, `__pycache__`, `.so` files.

- [ ] **Step 2: Create scripts/build.sh**

Builds `TA-epss-{version}.tar.gz` with `COPYFILE_DISABLE=1`, excludes dotfiles, `__pycache__`, `*.pyc`, `local/`, `metadata/local.meta`.

- [ ] **Step 3: Make executable and vendor**

```bash
chmod +x scripts/vendor.sh scripts/build.sh
./scripts/vendor.sh
```

- [ ] **Step 4: Build and verify package**

Run: `./scripts/build.sh && tar tzf TA-epss-1.0.0.tar.gz | head -30`
Expected: Package builds, lists files under `TA-epss/`

- [ ] **Step 5: Commit**

```bash
git add scripts/ TA-epss/bin/lib/
git commit -m "feat: add vendor and build scripts with vendored dependencies"
```

---

## Task 8: Dashboard Studio Dashboards

**Files:**

- Create: `TA-epss/default/data/ui/views/epss_overview.xml`
- Create: `TA-epss/default/data/ui/views/epss_health.xml`
- Create: `TA-epss/default/data/ui/nav/default.xml`

- [ ] **Step 1: Create epss_overview.xml**

Dashboard v2 format with UDF JSON inside `<definition><![CDATA[...]]></definition>`. Uses `<dashboard version="2">` wrapper.

Data sources:

- `ds_coverage_stats`: single-value stats (total CVEs, mean score, model version, critical count)
- `ds_risk_tiers`: bar chart of tier distribution
- `ds_top50`: table of top 50 by epss_score
- `ds_movers`: score delta vs previous day, filtered to same model_version
- `ds_trend`: line chart for user-entered CVE ID

Input: `input_cve` (text input, token `cve_lookup`, default `CVE-2021-44228`)

Layout: grid, 1440px wide. 4 single-value cards across top, charts and tables below.

- [ ] **Step 2: Create epss_health.xml**

Same dashboard v2 format. Mirrors CVE-TA `operational_health.xml` structure.

Data sources:

- `ds_last_ingest`, `ds_records_today`, `ds_records_total`, `ds_error_count`: single values
- `ds_daily_timeline`: column chart of records per day (30 days)
- `ds_audit_events`: recent audit events table
- `ds_errors_table`: error events table
- `ds_model_versions`: model version history table

- [ ] **Step 3: Create default.xml navigation**

```xml
<nav>
    <view name="epss_overview" default="true" />
    <view name="epss_health" />
</nav>
```

- [ ] **Step 4: Commit**

```bash
git add TA-epss/default/data/
git commit -m "feat: add Dashboard Studio dashboards for overview and health"
```

---

## Task 9: GitHub Actions CI/CD and Docker

**Files:**

- Create: `.github/workflows/ci.yml`
- Create: `docker-compose.test.yml`

- [ ] **Step 1: Create .github/workflows/ci.yml**

Three jobs:

1. `unit-tests`: matrix Python 3.11/3.12/3.13, PYTHONPATH set, `pytest tests/unit/ -v`
2. `appinspect`: builds tar.gz, runs `splunk-appinspect inspect --mode precert`, uploads artifact
3. `docker-integration` (needs: unit-tests, appinspect): starts Splunk container, installs TA, verifies --scheme, restarts, checks modular input registration, runs integration tests, captures logs on failure

Follows exact pattern from CVE-TA's `ci.yml` with `TA-cvelist` replaced by `TA-epss` and `cvelist` replaced by `epss`.

- [ ] **Step 2: Create docker-compose.test.yml**

```yaml
services:
  splunk:
    image: splunk/splunk:latest
    platform: linux/amd64
    environment:
      SPLUNK_START_ARGS: "--accept-license"
      SPLUNK_GENERAL_TERMS: "--accept-sgt-current-at-splunk-com"
      SPLUNK_PASSWORD: "TestPassword123!"
    ports:
      - "18089:8089"
      - "18000:8000"
    volumes:
      - ./TA-epss:/opt/splunk/etc/apps/TA-epss
    healthcheck:
      test:
        [
          "CMD",
          "curl",
          "-k",
          "-s",
          "https://localhost:8089/services/server/health",
        ]
      interval: 10s
      timeout: 5s
      retries: 30
      start_period: 60s
```

- [ ] **Step 3: Commit**

```bash
git add .github/ docker-compose.test.yml
git commit -m "feat: add GitHub Actions CI and Docker integration test config"
```

---

## Task 10: Static Assets and App Icon

**Files:**

- Create: `TA-epss/static/appIcon.png`
- Create: `TA-epss/static/appIcon_2x.png`

- [ ] **Step 1: Generate placeholder app icons**

Use Python to generate minimal 36x36 and 72x72 PNG files (solid blue color).

- [ ] **Step 2: Commit**

```bash
git add TA-epss/static/
git commit -m "feat: add placeholder app icons"
```

---

## Task 11: Lint and Final Verification

- [ ] **Step 1: Install dev dependencies**

```bash
pip install -e ".[dev]"
```

- [ ] **Step 2: Run ruff linter and fix issues**

Run: `ruff check TA-epss/bin/ tests/`
Expected: No errors (fix any that appear).

- [ ] **Step 3: Run all unit tests with coverage**

Run: `PYTHONPATH=TA-epss/bin pytest tests/unit/ -v --cov=epss_lib --cov-report=term-missing`
Expected: All 29 tests PASS, >80% coverage on core modules.

- [ ] **Step 4: Verify build**

Run: `./scripts/build.sh`
Expected: Creates `TA-epss-1.0.0.tar.gz`

- [ ] **Step 5: Verify --scheme output**

Run: `python3 TA-epss/bin/epss.py --scheme`
Expected: Valid XML with `<title>epss</title>`

- [ ] **Step 6: Commit any fixes**

```bash
git add -A
git commit -m "chore: lint fixes and final verification"
```

---

## Task 12: Update README.md

**Files:**

- Modify: `README.md`

- [ ] **Step 1: Write README with sections for: overview, features, installation, configuration, sourcetypes, dashboards, development, license**

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add project README"
```
