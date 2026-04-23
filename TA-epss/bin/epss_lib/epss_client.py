import gzip
import logging
import time
from typing import Optional

import requests

logger = logging.getLogger("ta_epss.epss_client")

DEFAULT_BASE_URL = "https://epss.empiricalsecurity.com"
DEFAULT_TIMEOUT = 60
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 2


class EPSSNotAvailable(Exception):  # noqa: N818
    pass


class EPSSDownloadError(Exception):
    pass


class EPSSClient:
    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_delay: float = DEFAULT_RETRY_DELAY,
        proxies: Optional[dict] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.proxies = proxies
        self.session = requests.Session()
        if proxies:
            self.session.proxies.update(proxies)

    def download_scores(self, date: str) -> str:
        url = f"{self.base_url}/epss_scores-{date}.csv.gz"
        response = self._get_with_retry(url)
        return gzip.decompress(response.content).decode("utf-8")

    def download_current(self) -> tuple[str, str]:
        url = f"{self.base_url}/epss_scores-current.csv.gz"
        response = self._get_with_retry(url)
        content = gzip.decompress(response.content).decode("utf-8")
        score_date = self._extract_date(content)
        return score_date, content

    def check_availability(self, date: str) -> bool:
        url = f"{self.base_url}/epss_scores-{date}.csv.gz"
        try:
            response = self.session.head(url, timeout=self.timeout)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def _get_with_retry(self, url: str) -> requests.Response:
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 404:
                    raise EPSSNotAvailable(f"EPSS data not available: {url}")
                if response.status_code in (502, 503, 504):
                    logger.warning(
                        f"Server error {response.status_code} on attempt "
                        f"{attempt + 1}/{self.max_retries}: {url}"
                    )
                    if attempt < self.max_retries - 1:
                        time.sleep(self.retry_delay * (2**attempt))
                    last_exception = EPSSDownloadError(f"HTTP {response.status_code}: {url}")
                    continue
                response.raise_for_status()
                return response
            except EPSSNotAvailable:
                raise
            except requests.RequestException as e:
                logger.warning(f"Request error on attempt {attempt + 1}/{self.max_retries}: {e}")
                last_exception = EPSSDownloadError(str(e))
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (2**attempt))

        raise last_exception or EPSSDownloadError(f"Failed after {self.max_retries} retries: {url}")

    @staticmethod
    def _extract_date(content: str) -> str:
        first_line = content.split("\n", 1)[0]
        if first_line.startswith("#"):
            for part in first_line[1:].split(","):
                part = part.strip()
                if part.startswith("score_date:"):
                    return part.split(":", 1)[1][:10]
        raise EPSSDownloadError("Could not extract score_date from CSV content")
