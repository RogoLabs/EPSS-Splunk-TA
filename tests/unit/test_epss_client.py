import gzip

import pytest
from epss_lib.epss_client import EPSSClient, EPSSNotAvailable

SAMPLE_CSV = """#model_version:v2025.03.14,score_date:2026-04-23T12:55:00Z
cve,epss,percentile
CVE-2014-0160,0.94464,0.99921
"""


def _gzip_content(text: str) -> bytes:
    return gzip.compress(text.encode("utf-8"))


def test_download_scores_success(requests_mock):
    """Download gzipped CSV and decompress correctly."""
    requests_mock.get(
        "https://epss.empiricalsecurity.com/epss_scores-2026-04-23.csv.gz",
        content=_gzip_content(SAMPLE_CSV),
    )
    client = EPSSClient()
    result = client.download_scores("2026-04-23")
    assert "CVE-2014-0160" in result
    assert "0.94464" in result


def test_download_scores_404_raises(requests_mock):
    """404 response should raise EPSSNotAvailable."""
    requests_mock.get(
        "https://epss.empiricalsecurity.com/epss_scores-2026-04-23.csv.gz",
        status_code=404,
    )
    client = EPSSClient()
    with pytest.raises(EPSSNotAvailable):
        client.download_scores("2026-04-23")


def test_download_scores_server_error_retries(requests_mock):
    """502/503 errors should retry, then succeed."""
    requests_mock.get(
        "https://epss.empiricalsecurity.com/epss_scores-2026-04-23.csv.gz",
        [
            {"status_code": 502},
            {"status_code": 503},
            {"content": _gzip_content(SAMPLE_CSV)},
        ],
    )
    client = EPSSClient(retry_delay=0)
    result = client.download_scores("2026-04-23")
    assert "CVE-2014-0160" in result


def test_download_current(requests_mock):
    """Download current.csv.gz and extract date from content."""
    requests_mock.get(
        "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        content=_gzip_content(SAMPLE_CSV),
    )
    client = EPSSClient()
    date, content = client.download_current()
    assert date == "2026-04-23"
    assert "CVE-2014-0160" in content


def test_custom_base_url(requests_mock):
    """Client should use custom base URL."""
    requests_mock.get(
        "https://custom.example.com/epss_scores-2026-04-23.csv.gz",
        content=_gzip_content(SAMPLE_CSV),
    )
    client = EPSSClient(base_url="https://custom.example.com")
    result = client.download_scores("2026-04-23")
    assert "CVE-2014-0160" in result


def test_check_availability_true(requests_mock):
    """HEAD request returning 200 means date is available."""
    requests_mock.head(
        "https://epss.empiricalsecurity.com/epss_scores-2026-04-23.csv.gz",
        status_code=200,
    )
    client = EPSSClient()
    assert client.check_availability("2026-04-23") is True


def test_check_availability_false(requests_mock):
    """HEAD request returning 404 means date is not available."""
    requests_mock.head(
        "https://epss.empiricalsecurity.com/epss_scores-2026-04-23.csv.gz",
        status_code=404,
    )
    client = EPSSClient()
    assert client.check_availability("2026-04-23") is False
