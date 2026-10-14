import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def test_migrations_reach_single_head(tmp_path):
    database_path = tmp_path / "schema.sqlite"
    environment = os.environ.copy()
    environment["DATABASE_URL"] = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    root = Path(__file__).resolve().parent.parent

    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )

    with sqlite3.connect(database_path) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {"batches", "iocs", "lookup_results", "ioc_feedback"} <= tables
        ioc_columns = {row[1]: row for row in connection.execute("PRAGMA table_info(iocs)")}
        feedback_columns = {row[1]: row for row in connection.execute("PRAGMA table_info(ioc_feedback)")}
        lookup_columns = {row[1] for row in connection.execute("PRAGMA table_info(lookup_results)")}
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(lookup_results)")}
        unique_index_exists = any(row[2] for row in connection.execute("PRAGMA index_list(lookup_results)"))

    assert "VARCHAR(2048)" in ioc_columns["value"][2]
    assert "VARCHAR(2048)" in feedback_columns["ioc_value"][2]
    assert "batch_id" in lookup_columns
    assert "ix_lookup_results_batch_id" in indexes
    assert unique_index_exists


def test_migration_deduplicates_legacy_task_rows(tmp_path):
    database_path = tmp_path / "legacy.sqlite"
    environment = os.environ.copy()
    environment["DATABASE_URL"] = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    root = Path(__file__).resolve().parent.parent

    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "a1f96ea838ee"],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    with sqlite3.connect(database_path) as connection:
        connection.execute("INSERT INTO iocs (value, ioc_type) VALUES ('legacy.example', 'domain')")
        ioc_id = connection.execute("SELECT id FROM iocs WHERE value = 'legacy.example'").fetchone()[0]
        connection.executemany(
            "INSERT INTO lookup_results (ioc_id, task_id, composite_score, composite_verdict, composite_confidence, source_count) VALUES (?, ?, ?, ?, ?, ?)",
            [(ioc_id, "legacy-task", 10.0, "clean", "low", 0), (ioc_id, "legacy-task", 90.0, "malicious", "high", 1)],
        )
        connection.commit()

    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    with sqlite3.connect(database_path) as connection:
        rows = connection.execute(
            "SELECT composite_verdict FROM lookup_results WHERE task_id = 'legacy-task'"
        ).fetchall()
    assert rows == [("malicious",)]


def test_init_adopts_unversioned_legacy_sqlite(tmp_path):
    database_path = tmp_path / "unversioned.sqlite"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE investigations (
                id INTEGER PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE iocs (
                id INTEGER PRIMARY KEY,
                value VARCHAR(512) NOT NULL,
                ioc_type VARCHAR(50) NOT NULL,
                first_seen DATETIME,
                last_seen DATETIME,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE investigation_iocs (
                id INTEGER PRIMARY KEY,
                investigation_id INTEGER NOT NULL,
                ioc_id INTEGER NOT NULL,
                notes TEXT,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (investigation_id) REFERENCES investigations(id),
                FOREIGN KEY (ioc_id) REFERENCES iocs(id)
            );
            CREATE TABLE lookup_results (
                id INTEGER PRIMARY KEY,
                ioc_id INTEGER NOT NULL,
                task_id VARCHAR(32) NOT NULL,
                composite_score FLOAT NOT NULL DEFAULT 0.0,
                composite_verdict VARCHAR(20) NOT NULL DEFAULT 'unknown',
                composite_confidence VARCHAR(10) NOT NULL DEFAULT 'low',
                full_response TEXT,
                source_count INTEGER NOT NULL DEFAULT 0,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ioc_id) REFERENCES iocs(id)
            );
            """
        )
        connection.execute("INSERT INTO investigations (id, name) VALUES (1, 'legacy')")
        connection.execute(
            "INSERT INTO iocs (id, value, ioc_type, first_seen, last_seen) "
            "VALUES (1, 'duplicate.example', 'unknown', '2020-01-01', '2021-01-01')"
        )
        connection.execute(
            "INSERT INTO iocs (id, value, ioc_type, first_seen, last_seen) "
            "VALUES (2, 'duplicate.example', 'domain', '2022-01-01', '2023-01-01')"
        )
        connection.execute("INSERT INTO lookup_results (ioc_id, task_id) VALUES (1, 'legacy-task-1')")
        connection.execute("INSERT INTO lookup_results (ioc_id, task_id) VALUES (2, 'legacy-task-2')")
        connection.execute("INSERT INTO investigation_iocs (investigation_id, ioc_id, notes) VALUES (1, 1, 'first note')")
        connection.execute("INSERT INTO investigation_iocs (investigation_id, ioc_id, notes) VALUES (1, 2, 'second note')")
        connection.execute("CREATE UNIQUE INDEX uq_investigation_ioc_legacy ON investigation_iocs (investigation_id, ioc_id)")
        connection.commit()

    environment = os.environ.copy()
    environment["DATABASE_URL"] = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    root = Path(__file__).resolve().parent.parent
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import asyncio; from app.backend.database import init_db; asyncio.run(init_db())",
        ],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    check = subprocess.run(
        [sys.executable, "-m", "alembic", "check"],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stderr or check.stdout

    with sqlite3.connect(database_path) as connection:
        version = connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        lookup_columns = {row[1] for row in connection.execute("PRAGMA table_info(lookup_results)")}
        foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
        ioc_count = connection.execute("SELECT COUNT(*) FROM iocs WHERE value = 'duplicate.example'").fetchone()[0]
        ioc_row = connection.execute(
            "SELECT ioc_type, first_seen, last_seen FROM iocs WHERE value = 'duplicate.example'"
        ).fetchone()
        link_count = connection.execute("SELECT COUNT(*) FROM investigation_iocs WHERE investigation_id = 1").fetchone()[0]
        link_notes = connection.execute("SELECT notes FROM investigation_iocs WHERE investigation_id = 1").fetchone()[0]

    assert version == "f2c8d4e6b1a9"
    assert {"batches", "ioc_feedback", "webhooks"} <= tables
    assert "batch_id" in lookup_columns
    assert foreign_key_errors == []
    assert ioc_count == 1
    assert ioc_row == ("domain", "2020-01-01", "2023-01-01")
    assert link_count == 1
    assert "first note" in link_notes and "second note" in link_notes


def test_init_refuses_unrelated_database_with_generic_table_names(tmp_path):
    database_path = tmp_path / "unrelated.sqlite"
    with sqlite3.connect(database_path) as connection:
        connection.execute("CREATE TABLE investigations (id INTEGER PRIMARY KEY, name TEXT)")
        connection.execute("INSERT INTO investigations (name) VALUES ('unrelated app')")
        connection.commit()

    environment = os.environ.copy()
    environment["DATABASE_URL"] = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    with sqlite3.connect(database_path) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "iocs" not in tables
    assert "lookup_results" not in tables
    assert "batches" not in tables


def test_init_refuses_incompatible_unversioned_sqlite(tmp_path):
    database_path = tmp_path / "incompatible.sqlite"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE investigations (
                id INTEGER PRIMARY KEY,
                name VARCHAR(255) NOT NULL
            );
            CREATE TABLE iocs (
                id INTEGER PRIMARY KEY,
                value VARCHAR(2048) NOT NULL
            );
            CREATE TABLE investigation_iocs (
                id INTEGER PRIMARY KEY,
                investigation_id INTEGER NOT NULL,
                ioc_id INTEGER NOT NULL
            );
            CREATE TABLE lookup_results (
                id INTEGER PRIMARY KEY,
                ioc_id INTEGER NOT NULL,
                task_id VARCHAR(32) NOT NULL
            );
            """
        )
        connection.execute("INSERT INTO iocs (value) VALUES ('legacy.example')")
        connection.execute("INSERT INTO lookup_results (ioc_id, task_id) VALUES (1, 'legacy-task')")
        connection.commit()

    environment = os.environ.copy()
    environment["DATABASE_URL"] = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import asyncio; from app.backend.database import init_db; asyncio.run(init_db())",
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "Refusing to adopt unversioned SQLite database" in (result.stderr + result.stdout)
    with sqlite3.connect(database_path) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "alembic_version" not in tables
    assert "batches" not in tables
    assert "webhooks" not in tables


def test_downgrade_refuses_to_drop_persisted_batch_associations(tmp_path):
    database_path = tmp_path / "downgrade.sqlite"
    environment = os.environ.copy()
    environment["DATABASE_URL"] = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    root = Path(__file__).resolve().parent.parent

    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    with sqlite3.connect(database_path) as connection:
        connection.execute("INSERT INTO iocs (value, ioc_type) VALUES ('batch.example', 'domain')")
        ioc_id = connection.execute("SELECT id FROM iocs WHERE value = 'batch.example'").fetchone()[0]
        connection.execute("INSERT INTO batches (id, status, total, completed) VALUES ('b1', 'completed', 1, 1)")
        connection.execute(
            "INSERT INTO lookup_results (ioc_id, task_id, batch_id) VALUES (?, 'task-b1', 'b1')",
            (ioc_id,),
        )
        connection.commit()

    result = subprocess.run(
        [sys.executable, "-m", "alembic", "downgrade", "a1f96ea838ee"],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "Refusing to downgrade" in (result.stderr + result.stdout)
    with sqlite3.connect(database_path) as connection:
        version = connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
        batch_rows = connection.execute("SELECT COUNT(*) FROM batches").fetchone()[0]
    assert version == "f2c8d4e6b1a9"
    assert batch_rows == 1


def test_downgrade_succeeds_on_empty_batch_schema(tmp_path):
    database_path = tmp_path / "downgrade_empty.sqlite"
    environment = os.environ.copy()
    environment["DATABASE_URL"] = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    root = Path(__file__).resolve().parent.parent

    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [sys.executable, "-m", "alembic", "downgrade", "a1f96ea838ee"],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    with sqlite3.connect(database_path) as connection:
        version = connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert version == "a1f96ea838ee"
    assert "batches" not in tables
