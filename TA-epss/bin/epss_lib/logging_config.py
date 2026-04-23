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
    except OSError:
        pass

    stderr_handler = logging.StreamHandler()
    stderr_handler.setFormatter(formatter)
    stderr_handler.setLevel(numeric_level)
    logger.addHandler(stderr_handler)

    logger.propagate = False
    return logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"ta_epss.{name}")
