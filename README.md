# EPSS Scores for Splunk (TA-epss)

A Splunk Technology Add-on that ingests daily EPSS (Exploit Prediction Scoring System) scores from FIRST. Downloads the daily compressed CSV (~330K CVEs), parses each row, and writes one Splunk event per CVE per day.

## Features

- **Daily automated ingestion** via Splunk modular input (cron: `0 18 * * *`)
- **Historical backfill** with configurable lookback (default 30 days, back to 2022-02-07)
- **Catch-up after downtime** — automatically processes missed days
- **Risk tier classification** — Critical (>=99th pct), High (>=95th), Medium (>=90th), Low (<90th)
- **KV Store lookups** — current scores lookup for correlation with other data
- **CIM Vulnerabilities compliance** — field aliases, eventtypes, and tags for Splunk ES
- **Dashboard Studio dashboards** — EPSS Overview and Operational Health
- **Saved searches** — automatic lookup refresh at 20:00 UTC daily

## Installation

1. Download or build `TA-epss-1.0.0.tar.gz`
2. Install via Splunk Web: **Apps > Install app from file**
3. Or copy `TA-epss/` to `$SPLUNK_HOME/etc/apps/`
4. Restart Splunk

The input is enabled by default and runs daily at 18:00 UTC.

## Configuration

Edit `local/inputs.conf` to customize:

```ini
[epss://default]
index = epss
lookback_days = 90
batch_size = 5000
epss_base_url = https://epss.empiricalsecurity.com
interval = 0 18 * * *
```

| Parameter       | Default                              | Description                          |
| --------------- | ------------------------------------ | ------------------------------------ |
| `index`         | `main`                               | Target Splunk index                  |
| `lookback_days` | `30`                                 | Days of historical data on first run |
| `batch_size`    | `5000`                               | Events per write batch               |
| `epss_base_url` | `https://epss.empiricalsecurity.com` | EPSS CSV download base URL           |
| `interval`      | `0 18 * * *`                         | Cron schedule (daily at 18:00 UTC)   |

Override the index macro in `local/macros.conf`:

```ini
[epss_index]
definition = index=epss
```

## Sourcetypes

### `epss:score`

One event per CVE per day:

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

### `epss:audit`

Operational lifecycle events:

```json
{
  "timestamp": "2026-04-23T18:15:32.123Z",
  "action": "ingest_complete",
  "score_date": "2026-04-23",
  "records_ingested": 328362
}
```

## Dashboards

- **EPSS Overview** — score distribution, risk tier breakdown, top 50 CVEs, daily movers, CVE trend lookup
- **EPSS Health** — last ingest time, daily volume, error log, model version history, checkpoint status

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run unit tests
PYTHONPATH=TA-epss/bin pytest tests/unit/ -v

# Lint
ruff check TA-epss/bin/ tests/

# Vendor dependencies
./scripts/vendor.sh

# Build package
./scripts/build.sh

# Local Splunk testing
docker compose -f docker-compose.test.yml up -d
```

## Data Source

EPSS data is published daily by [FIRST](https://www.first.org/epss/) and is freely available without authentication. Scores are typically published by ~14:00 UTC. The TA downloads from `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz`.

## License

MIT
