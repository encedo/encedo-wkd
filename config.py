#!/usr/bin/env python3
"""
Encedo WKD Server — configuration loader.
"""

import json
import logging
import os
import sys

logger = logging.getLogger(__name__)

CONFIG_PATH = os.environ.get("WKD_CONFIG", "/opt/encedo-wkd/config.json")

REQUIRED_FIELDS = ["port", "cache_dir"]


def load_config() -> dict:
    """Load and validate config.json. Exits on missing file or required fields."""
    logger.info("Loading config from %s", CONFIG_PATH)
    try:
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        logger.error("Config file not found: %s", CONFIG_PATH)
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error("Config JSON parse error: %s", e)
        sys.exit(1)

    missing = [f for f in REQUIRED_FIELDS if f not in config]
    if missing:
        logger.error("Missing required config fields: %s", ", ".join(missing))
        sys.exit(1)

    logger.info("Config loaded OK (port=%s cache_dir=%s)", config["port"], config["cache_dir"])
    return config
