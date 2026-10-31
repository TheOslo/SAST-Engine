from __future__ import annotations

import json
from typing import Any


class DatabaseUnavailable(RuntimeError):
    """Raised when the configured MySQL service cannot complete an operation."""


class MySQLRepository:
    def __init__(self, config: Any) -> None:
        self.config = config

    def _connect(self):
        try:
            import mysql.connector
        except ImportError as exc:
            raise DatabaseUnavailable("MySQL Connector/Python is not installed") from exc

        try:
            return mysql.connector.connect(
                host=self.config["MYSQL_HOST"],
                port=self.config["MYSQL_PORT"],
                database=self.config["MYSQL_DATABASE"],
                user=self.config["MYSQL_USER"],
                password=self.config["MYSQL_PASSWORD"],
                connection_timeout=3,
            )
        except mysql.connector.Error as exc:
            raise DatabaseUnavailable("Could not connect to MySQL") from exc

    def list_cwes(self) -> list[dict[str, object]]:
        connection = self._connect()
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute(
                """SELECT c.cwe_id, c.name, c.description
                   FROM cwe_list_member AS member
                   JOIN cwe_list AS catalog ON catalog.list_id = member.list_id
                   JOIN cwe AS c ON c.cwe_id = member.cwe_id
                   WHERE catalog.list_name = %s AND catalog.edition = %s
                     AND c.cwe_id IN (78, 79, 89, 352, 787, 862, 918)
                   ORDER BY member.rank_position""",
                (self.config["CWE_LIST_NAME"], self.config["CWE_LIST_EDITION"]),
            )
            rows = [dict(row) for row in cursor.fetchall()]
            expected_ids = {78, 79, 89, 352, 787, 862, 918}
            if {int(row["cwe_id"]) for row in rows} != expected_ids:
                raise DatabaseUnavailable("Configured CWE catalog is incomplete")
            return rows
        except Exception as exc:
            if isinstance(exc, DatabaseUnavailable):
                raise
            raise DatabaseUnavailable("Could not read the CWE catalog") from exc
        finally:
            if cursor is not None:
                cursor.close()
            connection.close()

    def record_scan(
        self,
        *,
        selected_cwe_ids: tuple[int, ...],
        duration_ms: int,
        source_count: int,
        finding_count: int,
        custom_finding_count: int,
        custom_observation_count: int,
    ) -> None:
        connection = self._connect()
        cursor = None
        try:
            cursor = connection.cursor()
            cursor.execute(
                """INSERT INTO scan_telemetry
                   (selected_cwe_ids, duration_ms, source_count, finding_count,
                    custom_finding_count, custom_observation_count)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (
                    json.dumps(selected_cwe_ids),
                    duration_ms,
                    source_count,
                    finding_count,
                    custom_finding_count,
                    custom_observation_count,
                ),
            )
            connection.commit()
        except Exception as exc:
            connection.rollback()
            raise DatabaseUnavailable("Could not write scan telemetry") from exc
        finally:
            if cursor is not None:
                cursor.close()
            connection.close()
