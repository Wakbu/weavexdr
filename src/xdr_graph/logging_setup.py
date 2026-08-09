from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_rotating_logging(
    log_dir: str | Path,
    *,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
) -> logging.Logger:
    if max_bytes < 1 or backup_count < 1:
        raise ValueError("log rotation limits must be positive")
    target_dir = Path(log_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("weavexdr")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for handler in tuple(logger.handlers):
        handler.close()
        logger.removeHandler(handler)
    handler = RotatingFileHandler(
        target_dir / "weavexdr.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    return logger
