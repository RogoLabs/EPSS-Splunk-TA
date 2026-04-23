import csv
import io
import logging
import re
from typing import Optional

logger = logging.getLogger("ta_epss.csv_processor")

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

_stats = {"parsed": 0, "skipped": 0, "errors": 0}


def reset_stats() -> None:
    """Reset parsing statistics counters."""
    global _stats
    _stats = {"parsed": 0, "skipped": 0, "errors": 0}


def get_stats() -> dict:
    """Return a copy of current parsing statistics."""
    return dict(_stats)


def _calculate_risk_tier(percentile: float) -> str:
    """
    Calculate risk tier based on EPSS percentile.

    Args:
        percentile: EPSS percentile value (0.0 to 1.0)

    Returns:
        Risk tier: "Critical", "High", "Medium", or "Low"
    """
    if percentile >= 0.99:
        return "Critical"
    if percentile >= 0.95:
        return "High"
    if percentile >= 0.90:
        return "Medium"
    return "Low"


def _parse_comment_line(line: str) -> tuple[Optional[str], Optional[str]]:
    """
    Extract model_version and score_date from CSV comment line.

    Args:
        line: Comment line starting with '#'

    Returns:
        Tuple of (model_version, score_date) where score_date is YYYY-MM-DD format
    """
    model_version = None
    score_date = None
    if not line.startswith("#"):
        return model_version, score_date
    content = line[1:]
    for part in content.split(","):
        part = part.strip()
        if part.startswith("model_version:"):
            model_version = part.split(":", 1)[1]
        elif part.startswith("score_date:"):
            date_str = part.split(":", 1)[1]
            # Extract just YYYY-MM-DD from ISO timestamp
            # Handles both Z and +0000 suffixes
            score_date = date_str[:10]
    return model_version, score_date


def parse_csv(content: str, fallback_date: Optional[str] = None) -> list[dict]:
    """
    Parse EPSS CSV content into structured records.

    Args:
        content: CSV content string with optional comment line
        fallback_date: Date to use if no score_date found in comment line

    Returns:
        List of dictionaries containing parsed EPSS records
    """
    if not content or not content.strip():
        return []

    reset_stats()
    lines = content.strip().split("\n")

    model_version = None
    score_date = fallback_date
    start_idx = 0

    if lines[0].startswith("#"):
        model_version, parsed_date = _parse_comment_line(lines[0])
        if parsed_date:
            score_date = parsed_date
        start_idx = 1

    remaining = "\n".join(lines[start_idx:])
    reader = csv.DictReader(io.StringIO(remaining))

    results = []
    for row in reader:
        cve_id = row.get("cve", "").strip()
        if not CVE_PATTERN.match(cve_id):
            logger.warning(f"Skipping malformed CVE ID: {cve_id!r}")
            _stats["skipped"] += 1
            continue

        try:
            epss_score = float(row.get("epss", "0"))
            percentile = float(row.get("percentile", "0"))
        except (ValueError, TypeError) as e:
            logger.warning(f"Skipping {cve_id}: invalid numeric value: {e}")
            _stats["errors"] += 1
            continue

        if not (0.0 <= epss_score <= 1.0):
            logger.warning(f"Skipping {cve_id}: epss_score {epss_score} out of range [0,1]")
            _stats["skipped"] += 1
            continue

        if not (0.0 <= percentile <= 1.0):
            logger.warning(f"Skipping {cve_id}: percentile {percentile} out of range [0,1]")
            _stats["skipped"] += 1
            continue

        results.append(
            {
                "cve_id": cve_id,
                "epss_score": epss_score,
                "percentile": percentile,
                "score_date": score_date,
                "model_version": model_version,
                "epss_risk_tier": _calculate_risk_tier(percentile),
            }
        )
        _stats["parsed"] += 1

    return results
