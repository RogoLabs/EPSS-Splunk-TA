import os

import pytest
from conftest import FIXTURES_DIR
from epss_lib.csv_processor import (
    _calculate_risk_tier,
    get_stats,
    parse_csv,
    reset_stats,
)


def test_parses_standard_csv():
    """Load epss_sample.csv and verify 7 rows with correct structure."""
    fixture_path = os.path.join(FIXTURES_DIR, "epss_sample.csv")
    with open(fixture_path) as f:
        content = f.read()

    results = parse_csv(content)

    assert len(results) == 7

    first_row = results[0]
    assert first_row["cve_id"] == "CVE-2014-0160"
    assert first_row["epss_score"] == 0.94464
    assert first_row["percentile"] == 0.99921
    assert first_row["score_date"] == "2026-04-23"
    assert first_row["model_version"] == "v2025.03.14"
    assert first_row["epss_risk_tier"] == "Critical"


def test_handles_old_timezone_format():
    """Load epss_sample_old_tz.csv and verify date/version parsing."""
    fixture_path = os.path.join(FIXTURES_DIR, "epss_sample_old_tz.csv")
    with open(fixture_path) as f:
        content = f.read()

    results = parse_csv(content)

    assert len(results) == 2
    assert results[0]["score_date"] == "2024-01-15"
    assert results[0]["model_version"] == "v2023.03.01"


def test_handles_scientific_notation():
    """Parse CSV with scientific notation (5e-05) as EPSS score."""
    csv_content = """#model_version:v2025.03.14,score_date:2026-04-23T12:55:00Z
cve,epss,percentile
CVE-2021-40438,5e-05,0.02318
"""
    results = parse_csv(csv_content)

    assert len(results) == 1
    assert results[0]["epss_score"] == pytest.approx(0.00005)


def test_risk_tier_critical():
    """Percentile >= 0.99 should return Critical."""
    assert _calculate_risk_tier(0.99) == "Critical"
    assert _calculate_risk_tier(0.999) == "Critical"
    assert _calculate_risk_tier(1.0) == "Critical"


def test_risk_tier_high():
    """Percentile >= 0.95 and < 0.99 should return High."""
    assert _calculate_risk_tier(0.95) == "High"
    assert _calculate_risk_tier(0.97) == "High"
    assert _calculate_risk_tier(0.9899) == "High"


def test_risk_tier_medium():
    """Percentile >= 0.90 and < 0.95 should return Medium."""
    assert _calculate_risk_tier(0.90) == "Medium"
    assert _calculate_risk_tier(0.92) == "Medium"
    assert _calculate_risk_tier(0.9499) == "Medium"


def test_risk_tier_low():
    """Percentile < 0.90 should return Low."""
    assert _calculate_risk_tier(0.89) == "Low"
    assert _calculate_risk_tier(0.5) == "Low"
    assert _calculate_risk_tier(0.0) == "Low"


def test_skips_malformed_cve_id():
    """CSV row with invalid CVE ID should be filtered out."""
    csv_content = """cve,epss,percentile
NOT-A-CVE,0.5,0.5
CVE-2024-1234,0.1,0.2
CVE-INVALID,0.3,0.4
CVE-2023-5678,0.6,0.7
"""
    results = parse_csv(csv_content)

    assert len(results) == 2
    assert results[0]["cve_id"] == "CVE-2024-1234"
    assert results[1]["cve_id"] == "CVE-2023-5678"


def test_skips_out_of_range_scores():
    """CSV row with EPSS score > 1.0 should be filtered out."""
    csv_content = """cve,epss,percentile
CVE-2024-9999,1.5,0.5
CVE-2024-1234,0.5,0.5
CVE-2024-5678,0.5,1.5
CVE-2023-1111,0.3,0.3
"""
    results = parse_csv(csv_content)

    assert len(results) == 2
    assert results[0]["cve_id"] == "CVE-2024-1234"
    assert results[1]["cve_id"] == "CVE-2023-1111"


def test_empty_csv_returns_empty():
    """parse_csv with empty string should return empty list."""
    assert parse_csv("") == []
    assert parse_csv("   ") == []
    assert parse_csv("\n\n") == []


def test_fallback_date_when_no_comment():
    """CSV without comment line should use fallback_date."""
    csv_content = """cve,epss,percentile
CVE-2024-1234,0.5,0.5
"""
    results = parse_csv(csv_content, fallback_date="2026-01-01")

    assert len(results) == 1
    assert results[0]["score_date"] == "2026-01-01"
    assert results[0]["model_version"] is None


def test_stats_tracking():
    """Verify parsed and skipped counts are tracked correctly."""
    csv_content = """cve,epss,percentile
CVE-2024-1234,0.5,0.5
NOT-A-CVE,0.3,0.3
CVE-2024-5678,0.7,0.7
CVE-2024-9999,1.5,0.5
"""
    parse_csv(csv_content)

    stats = get_stats()
    assert stats["parsed"] == 2
    assert stats["skipped"] == 2

    reset_stats()
    stats = get_stats()
    assert stats["parsed"] == 0
    assert stats["skipped"] == 0
    assert stats["errors"] == 0
