from __future__ import annotations

import os


def default_config() -> dict[str, object]:
    return {
        "MYSQL_HOST": os.getenv("MYSQL_HOST", "127.0.0.1"),
        "MYSQL_PORT": int(os.getenv("MYSQL_PORT", "3306")),
        "MYSQL_DATABASE": os.getenv("MYSQL_DATABASE", "sast_engine"),
        "MYSQL_USER": os.getenv("MYSQL_USER", "sast_app"),
        "MYSQL_PASSWORD": os.getenv("MYSQL_PASSWORD", ""),
        "MAX_CONTENT_LENGTH": int(os.getenv("MAX_CONTENT_LENGTH", str(3 * 1024 * 1024))),
        "CWE_LIST_NAME": "SAST Python Rule Starter Set",
        "CWE_LIST_EDITION": 1,
    }
