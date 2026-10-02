"""The notebook: where runs and findings are recorded.

There is one Storage interface and two backends behind it:

- SQLiteStorage  - a single file, zero setup. The default, and what the tests
  and the CLI use out of the box.
- PostgresStorage - the real backend for the service. psycopg is imported
  lazily so nothing but this backend depends on it.

Pick a backend with env (no credentials in code):
    HARNESS_DB_BACKEND=postgres  + DATABASE_URL=postgresql://user:pw@host/db
Anything else falls back to SQLite at the given path. Both backends return the
exact same row shape, so the coordinator, CLI and API never know which is live.
"""
from __future__ import annotations

import abc
import json
import os
import sqlite3
import threading
from pathlib import Path

from .models import Finding

DEFAULT_DB = "harness.db"

# One column set, shared by both backends. created_at is TEXT (ISO string, as
# the Finding produces) and evidence is a JSON string we parse on read, so the
# two backends are byte-for-byte interchangeable from the caller's side.
_COLUMNS = ("id", "target", "scenario", "verdict", "detail", "evidence", "created_at")


class Storage(abc.ABC):
    """Interface every backend implements. Methods: save, recent, get, close."""

    @abc.abstractmethod
    def save(self, finding: Finding) -> int:
        """Persist a finding, return its new id."""

    @abc.abstractmethod
    def recent(
        self, limit: int = 50, target: str | None = None, verdict: str | None = None
    ) -> list[dict]:
        """Most recent findings first, optionally filtered by target/verdict."""

    @abc.abstractmethod
    def get(self, finding_id: int) -> dict | None:
        """One finding by id with full evidence, or None if absent."""

    def close(self) -> None:  # pragma: no cover - trivial
        """Release resources. Safe to override; default is a no-op."""


def _row_to_dict(row: dict) -> dict:
    """Normalize a raw DB row: parse the evidence JSON blob into a dict."""
    d = dict(row)
    ev = d.get("evidence")
    d["evidence"] = json.loads(ev) if ev else {}
    return d


class SQLiteStorage(Storage):
    """File-backed SQLite store. Zero setup; the default backend."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS findings (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        target     TEXT NOT NULL,
        scenario   TEXT NOT NULL,
        verdict    TEXT NOT NULL,
        detail     TEXT,
        evidence   TEXT,              -- JSON blob of captured proof
        created_at TEXT NOT NULL
    );
    """

    def __init__(self, path: str = DEFAULT_DB):
        self.path = Path(path)
        # check_same_thread=False + a lock lets the API touch one store from
        # request threads AND background scan tasks; the lock serializes access.
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(self._SCHEMA)
            self._conn.commit()

    def save(self, finding: Finding) -> int:
        row = finding.to_row()
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO findings
                   (target, scenario, verdict, detail, evidence, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    row["target"],
                    row["scenario"],
                    row["verdict"],
                    row["detail"],
                    json.dumps(row["evidence"]),
                    row["created_at"],
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def recent(
        self, limit: int = 50, target: str | None = None, verdict: str | None = None
    ) -> list[dict]:
        clauses, params = [], []
        if target:
            clauses.append("target = ?")
            params.append(target)
        if verdict:
            clauses.append("verdict = ?")
            params.append(verdict)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with self._lock:
            cur = self._conn.execute(
                f"SELECT * FROM findings{where} ORDER BY id DESC LIMIT ?", params
            )
            return [_row_to_dict(r) for r in cur.fetchall()]

    def get(self, finding_id: int) -> dict | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM findings WHERE id = ?", (finding_id,)
            )
            r = cur.fetchone()
        return _row_to_dict(r) if r is not None else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class PostgresStorage(Storage):
    """Postgres store via psycopg (v3). psycopg is imported lazily so the rest
    of the project never has to have it installed."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS findings (
        id         BIGSERIAL PRIMARY KEY,
        target     TEXT NOT NULL,
        scenario   TEXT NOT NULL,
        verdict    TEXT NOT NULL,
        detail     TEXT,
        evidence   TEXT,
        created_at TEXT NOT NULL
    );
    """

    def __init__(self, dsn: str | None = None):
        try:
            import psycopg  # noqa: PLC0415 - optional dependency, lazy on purpose
        except ModuleNotFoundError as e:  # pragma: no cover - env-dependent
            raise RuntimeError(
                "PostgresStorage needs psycopg: pip install 'mcp-harness[postgres]'"
            ) from e

        self._dsn = dsn or os.environ.get("DATABASE_URL")
        if not self._dsn:
            raise RuntimeError("Postgres backend requires DATABASE_URL (or a dsn)")
        self._conn = psycopg.connect(self._dsn, autocommit=True)
        self._lock = threading.Lock()
        with self._lock, self._conn.cursor() as cur:
            cur.execute(self._SCHEMA)

    def save(self, finding: Finding) -> int:
        row = finding.to_row()
        with self._lock, self._conn.cursor() as cur:
            cur.execute(
                """INSERT INTO findings
                   (target, scenario, verdict, detail, evidence, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                (
                    row["target"],
                    row["scenario"],
                    row["verdict"],
                    row["detail"],
                    json.dumps(row["evidence"]),
                    row["created_at"],
                ),
            )
            return int(cur.fetchone()[0])

    def recent(
        self, limit: int = 50, target: str | None = None, verdict: str | None = None
    ) -> list[dict]:
        clauses, params = [], []
        if target:
            clauses.append("target = %s")
            params.append(target)
        if verdict:
            clauses.append("verdict = %s")
            params.append(verdict)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with self._lock, self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM findings{where} "
                "ORDER BY id DESC LIMIT %s",
                params,
            )
            return [_row_to_dict(dict(zip(_COLUMNS, r))) for r in cur.fetchall()]

    def get(self, finding_id: int) -> dict | None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM findings WHERE id = %s",
                (finding_id,),
            )
            r = cur.fetchone()
        return _row_to_dict(dict(zip(_COLUMNS, r))) if r is not None else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def open_storage(sqlite_path: str = DEFAULT_DB) -> Storage:
    """Build the storage backend selected by the environment.

    HARNESS_DB_BACKEND=postgres (or a DATABASE_URL that looks like Postgres)
    selects Postgres; otherwise SQLite at sqlite_path. Credentials live only in
    DATABASE_URL (the environment), never in this file.
    """
    backend = os.environ.get("HARNESS_DB_BACKEND", "").strip().lower()
    url = os.environ.get("DATABASE_URL", "")
    looks_pg = url.startswith(("postgres://", "postgresql://"))
    if backend == "postgres" or (not backend and looks_pg):
        return PostgresStorage(url)
    return SQLiteStorage(sqlite_path)
