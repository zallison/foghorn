"""Shared lazy-import helpers for SQL backend drivers.

Inputs:
  - Backend modules call these helpers with optional driver preference and
    fallback settings.

Outputs:
  - Imported DB-API driver modules and normalized placeholder/param-style
    metadata used by SQL backends.
"""

from __future__ import annotations

from typing import Optional


def import_mqtt_driver() -> object:
    """Brief: Import and return a paho-mqtt style client module.

    Inputs:
      - None.

    Outputs:
      - Module exposing a Client class compatible with paho-mqtt.

    Raises:
      - RuntimeError: When no supported MQTT driver is available.
    """

    import sys

    injected = sys.modules.get("paho.mqtt.client")
    if injected is not None:
        return injected

    try:
        import paho.mqtt.client as mqtt  # type: ignore[import]

        return mqtt
    except Exception as exc:  # pragma: no cover - environment specific
        raise RuntimeError(
            "No supported MQTT client library found; install 'paho-mqtt' to "
            "use the MqttLogging"
        ) from exc


def import_mongo_driver() -> object:
    """Brief: Import and return a MongoDB driver module exposing MongoClient.

    Inputs:
      - None.

    Outputs:
      - pymongo-like module exposing a ``MongoClient`` callable.

    Raises:
      - RuntimeError: When no supported MongoDB driver is available.
    """

    try:  # pragma: no cover - import-path dependent
        import pymongo  # type: ignore[import]

        return pymongo
    except Exception as exc:  # pragma: no cover - environment specific
        raise RuntimeError(
            "No supported MongoDB driver found; install 'pymongo' to use the "
            "MongoStatsStore"
        ) from exc


def import_postgres_driver(*, consumer_name: str) -> object:
    """Brief: Import and return a DB-API compatible PostgreSQL driver module.

    Inputs:
      - consumer_name: Backend name used in RuntimeError text.

    Outputs:
      - object: Driver module exposing a ``connect`` callable.

    Raises:
      - RuntimeError: When no supported PostgreSQL driver is available.
    """

    try:  # pragma: no cover - import-path dependent
        import psycopg as driver  # type: ignore[import]

        return driver
    except Exception:  # pragma: no cover - environment specific
        try:
            import psycopg2 as driver  # type: ignore[import]

            return driver
        except Exception as exc:  # pragma: no cover - environment specific
            raise RuntimeError(
                "No supported PostgreSQL driver found; install either "
                f"'psycopg' or 'psycopg2' to use the {consumer_name}"
            ) from exc


def normalize_mysql_driver_name(raw: object) -> str | None:
    """Brief: Normalize a MySQL driver name from configuration.

    Inputs:
      - raw: Candidate value (string-like) from backend config.

    Outputs:
      - str | None: Canonical driver key ('mariadb' or
        'mysql-connector-python'), or None when raw is empty/auto/default.
    """

    if raw is None:
        return None
    if not isinstance(raw, str):
        return None

    value = raw.strip().lower().replace("_", "-").replace(" ", "")
    if not value or value in {"auto", "default"}:
        return None

    if value in {"mariadb", "maria-db"}:
        return "mariadb"
    if value in {
        "mysql",
        "mysql-connector-python",
        "mysql.connector",
        "mysql-connector",
        "mysqlconnector",
        "mysql-connector/py",
        "connector",
    }:
        return "mysql-connector-python"

    raise ValueError(
        "mysql driver must be one of 'auto', 'mariadb', 'mysql', or "
        "'mysql-connector-python'"
    )


def normalize_mysql_driver_fallbacks(raw: object) -> list[str] | None:
    """Brief: Normalize MySQL driver fallback configuration.

    Inputs:
      - raw: Fallback config from YAML (string or list of strings).

    Outputs:
      - list[str] | None:
        - None for default behavior (auto fallback)
        - [] for explicit no-fallback
        - list of canonical driver keys
    """

    if raw is None:
        return None

    if isinstance(raw, str):
        v = raw.strip().lower().replace("_", "-").replace(" ", "")
        if not v or v in {"auto", "default"}:
            return None
        if v in {"none", "no", "false", "off"}:
            return []
        return [normalize_mysql_driver_name(raw)]  # type: ignore[list-item]

    if isinstance(raw, list):
        out: list[str] = []
        for item in raw:
            if item is None:
                continue
            name = normalize_mysql_driver_name(item)
            if name is None:
                continue
            out.append(name)
        return out

    return None


def mysql_driver_order_from_config(
    *,
    driver: object = None,
    driver_fallback: object = None,
) -> list[str]:
    """Brief: Compute MySQL driver import order from config.

    Inputs:
      - driver: Preferred driver name.
      - driver_fallback: Fallback policy.

    Outputs:
      - list[str]: Ordered canonical driver keys to try.
    """

    preferred = normalize_mysql_driver_name(driver)
    fallbacks = normalize_mysql_driver_fallbacks(driver_fallback)
    default_order = ["mariadb", "mysql-connector-python"]

    if preferred is None:
        if fallbacks == []:
            return [default_order[0]]
        return default_order

    if fallbacks is None:
        fallbacks = [d for d in default_order if d != preferred]

    order = [preferred] + list(fallbacks or [])
    seen: set[str] = set()
    out: list[str] = []
    for item in order:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def import_mysql_driver(
    *,
    driver: object = None,
    driver_fallback: object = None,
    consumer_name: str,
) -> tuple[object, str]:
    """Brief: Import and return a DB-API compatible MySQL/MariaDB driver.

    Inputs:
      - driver: Preferred driver selector.
      - driver_fallback: Fallback driver policy.
      - consumer_name: Backend name used in RuntimeError text.

    Outputs:
      - tuple[object, str]:
        - object: Imported driver module.
        - str: Param style ('qmark' for '?', 'format' for '%s').
    """

    order = mysql_driver_order_from_config(
        driver=driver,
        driver_fallback=driver_fallback,
    )

    last_exc: Optional[Exception] = None
    for choice in order:
        try:
            if choice == "mariadb":
                import mariadb as driver_mod  # type: ignore[import]

                return driver_mod, "qmark"
            if choice == "mysql-connector-python":
                import mysql.connector as driver_mod  # type: ignore[import]

                return driver_mod, "format"
        except ImportError as exc:  # pragma: no cover - import-path dependent
            last_exc = exc
            continue

    raise RuntimeError(
        "No supported MySQL/MariaDB driver found; install either 'mariadb' "
        f"or 'mysql-connector-python' to use the {consumer_name}"
    ) from last_exc
