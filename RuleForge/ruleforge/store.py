"""Rule history, on SQLite.

The history tab is not a convenience. Tuning a detection is iterative -- widen
a condition, re-run it against samples, narrow it again -- and the question an
engineer actually asks is "what did this rule look like before I touched it,
and why did I change it?". A store that overwrites answers neither.

So this is APPEND-ONLY. Saving a tuned rule writes a NEW row that points at the
one it came from, and nothing is ever updated in place. The lineage that falls
out of `parent_id` is the audit trail: you can walk a rule from the version
pasted in off a blog post, through four tuning passes, to the one deployed.

`origin` records which of the three authoring paths produced a row, because
they carry very different trust:

    authored      built in the GUI from the IR outward
    imported      pasted in as vendor text and parsed
    synthesized   generated from a log sample

A rule synthesized from one log line is a hypothesis; a rule an engineer
authored deliberately is a decision. Flattening that distinction is how a
history tab becomes a list nobody trusts.

Rules are stored as codec JSON rather than as vendor text, because vendor text
is lossy in both directions -- `kql.py` cannot render annotations at all -- and
because a stored rule has to be re-openable in the builder, which needs the IR.
The original text is kept ALONGSIDE it, verbatim, so an imported rule can still
be shown exactly as the analyst pasted it.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from .codec import SCHEMA_VERSION, rule_from_json, rule_to_json
from .ir import Rule
from .values import Refusal

__all__ = [
    "ORIGINS",
    "Entry",
    "RuleStore",
    "default_store_path",
]

#: How a row came to exist. A closed set, because the UI shows it as a badge
#: and an unrecognised origin would render as a blank.
ORIGINS: Final[frozenset[str]] = frozenset({"authored", "imported", "synthesized"})

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS entries (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     TEXT    NOT NULL,
    rule_id        TEXT    NOT NULL,
    title          TEXT    NOT NULL DEFAULT '',
    dialect        TEXT    NOT NULL,
    origin         TEXT    NOT NULL,
    parent_id      INTEGER REFERENCES entries(id),
    note           TEXT    NOT NULL DEFAULT '',
    source_text    TEXT    NOT NULL DEFAULT '',
    rule_json      TEXT    NOT NULL,
    schema_version INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS entries_created ON entries(created_at DESC);
CREATE INDEX IF NOT EXISTS entries_rule_id ON entries(rule_id);
CREATE INDEX IF NOT EXISTS entries_parent  ON entries(parent_id);
"""


def default_store_path() -> Path:
    """`data/history.sqlite3` beside the package, honouring an override.

    The `data/` directory already exists in the repository and is empty, which
    is where this was always meant to go.
    """
    override = os.environ.get("RULEFORGE_HOME")
    root = Path(override) if override else Path(__file__).resolve().parent.parent / "data"
    return root / "history.sqlite3"


@dataclass(frozen=True, slots=True)
class Entry:
    """One stored version of a rule.

    `rule_json` is kept as text rather than decoded eagerly: listing a hundred
    history rows should not decode and validate a hundred rules. Call
    `RuleStore.rule(entry_id)` for the Rule itself.
    """

    id: int
    created_at: str
    rule_id: str
    title: str
    dialect: str
    origin: str
    parent_id: int | None
    note: str
    source_text: str
    rule_json: str
    schema_version: int

    def as_dict(self, *, include_rule: bool = False) -> dict[str, Any]:
        """The shape the API hands a history list."""
        body: dict[str, Any] = {
            "id": self.id,
            "created_at": self.created_at,
            "rule_id": self.rule_id,
            "title": self.title,
            "dialect": self.dialect,
            "origin": self.origin,
            "parent_id": self.parent_id,
            "note": self.note,
            "has_source": bool(self.source_text),
        }
        if include_rule:
            body["source_text"] = self.source_text
            body["rule"] = json.loads(self.rule_json)
        return body


class RuleStore:
    """Append-only rule history.

    A short-lived connection per call rather than one long-lived handle. The
    API server is threaded, and a shared sqlite3 connection across threads is
    either a crash or a lock held across a request -- neither of which is worth
    saving a few microseconds on a local tool.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path) if path is not None else default_store_path()
        self._in_memory = str(self.path) == ":memory:"
        self._memory: sqlite3.Connection | None = None
        if self._in_memory:
            # An in-memory database exists exactly as long as its connection,
            # so this one handle is kept open for the store's lifetime.
            self._memory = sqlite3.connect(":memory:", check_same_thread=False)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    # -- plumbing ---------------------------------------------------------

    def _connect(self) -> "_Session":
        if self._memory is not None:
            return _Session(self._memory, close=False)
        conn = sqlite3.connect(str(self.path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return _Session(conn, close=True)

    @staticmethod
    def _row_to_entry(row: Any) -> Entry:
        return Entry(
            id=row["id"],
            created_at=row["created_at"],
            rule_id=row["rule_id"],
            title=row["title"],
            dialect=row["dialect"],
            origin=row["origin"],
            parent_id=row["parent_id"],
            note=row["note"],
            source_text=row["source_text"],
            rule_json=row["rule_json"],
            schema_version=row["schema_version"],
        )

    # -- writing ----------------------------------------------------------

    def save(
        self,
        rule: Rule,
        *,
        origin: str,
        source_text: str = "",
        note: str = "",
        parent_id: int | None = None,
        title: str | None = None,
    ) -> Entry:
        """Append a version. Never updates; never overwrites.

        `parent_id` is what makes a tuning session legible later: each save
        during a tuning pass points at the version it was derived from.
        """
        if not isinstance(rule, Rule):
            raise Refusal(
                "STORE_NOT_A_RULE",
                f"`{type(rule).__name__}` is not a Rule.",
                "store",
            )
        if origin not in ORIGINS:
            raise Refusal(
                "STORE_ORIGIN_UNKNOWN",
                f"`{origin}` is not how a rule can come to exist. Use one of: "
                f"{', '.join(sorted(ORIGINS))}. The origin is shown to the "
                f"analyst, because a rule generated from one log line is a "
                f"hypothesis and an authored rule is a decision.",
                "store",
            )

        # Encoded before the row is opened, so a rule the codec refuses never
        # leaves a half-written history behind.
        rule_json = rule_to_json(rule, indent=None)
        dialect = rule.metadata.get("dialect", "")
        resolved_title = (
            title if title is not None else (rule.annotations.title or "")
        )

        with self._connect() as conn:
            if parent_id is not None:
                found = conn.execute(
                    "SELECT id FROM entries WHERE id = ?", (parent_id,)
                ).fetchone()
                if found is None:
                    raise Refusal(
                        "STORE_PARENT_UNKNOWN",
                        f"entry {parent_id} is not in this history, so a rule "
                        f"cannot be recorded as derived from it.",
                        "store",
                    )
            cursor = conn.execute(
                "INSERT INTO entries (created_at, rule_id, title, dialect, "
                "origin, parent_id, note, source_text, rule_json, "
                "schema_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    rule.rule_id,
                    resolved_title,
                    dialect,
                    origin,
                    parent_id,
                    note,
                    source_text,
                    rule_json,
                    SCHEMA_VERSION,
                ),
            )
            new_id = int(cursor.lastrowid or 0)
            row = conn.execute(
                "SELECT * FROM entries WHERE id = ?", (new_id,)
            ).fetchone()
        return self._row_to_entry(row)

    def forget(self, entry_id: int) -> None:
        """Remove one version.

        Deliberately narrow: it refuses to orphan a lineage. Deleting the
        version a later one was tuned from would leave a history that reads as
        if the rule appeared fully formed.
        """
        with self._connect() as conn:
            children = conn.execute(
                "SELECT id FROM entries WHERE parent_id = ? LIMIT 1", (entry_id,)
            ).fetchone()
            if children is not None:
                raise Refusal(
                    "STORE_ENTRY_HAS_CHILDREN",
                    f"entry {entry_id} is the version later ones were tuned "
                    f"from. Deleting it would leave a lineage whose history "
                    f"starts in the middle.",
                    "store",
                )
            cursor = conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
            if cursor.rowcount == 0:
                raise Refusal(
                    "STORE_ENTRY_UNKNOWN",
                    f"entry {entry_id} is not in this history.",
                    "store",
                )

    # -- reading ----------------------------------------------------------

    def entry(self, entry_id: int) -> Entry:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM entries WHERE id = ?", (entry_id,)
            ).fetchone()
        if row is None:
            raise Refusal(
                "STORE_ENTRY_UNKNOWN",
                f"entry {entry_id} is not in this history.",
                "store",
            )
        return self._row_to_entry(row)

    def rule(self, entry_id: int) -> Rule:
        """The stored Rule, decoded and re-validated on the way out."""
        return rule_from_json(self.entry(entry_id).rule_json)

    def history(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        dialect: str = "",
        origin: str = "",
        query: str = "",
    ) -> list[Entry]:
        """Newest first. Every filter is a bound parameter, never interpolated."""
        if limit < 1 or limit > 500:
            raise Refusal(
                "STORE_LIMIT_INVALID",
                f"`{limit}` is not a page size between 1 and 500.",
                "store",
            )
        if offset < 0:
            raise Refusal(
                "STORE_OFFSET_INVALID", f"`{offset}` is a negative offset.", "store"
            )

        clauses: list[str] = []
        params: list[Any] = []
        if dialect:
            clauses.append("dialect = ?")
            params.append(dialect)
        if origin:
            if origin not in ORIGINS:
                raise Refusal(
                    "STORE_ORIGIN_UNKNOWN",
                    f"`{origin}` is not an origin. Use one of: "
                    f"{', '.join(sorted(ORIGINS))}.",
                    "store",
                )
            clauses.append("origin = ?")
            params.append(origin)
        if query:
            # LIKE with an escaped pattern, so a rule titled "100% CPU" is
            # searchable rather than matching everything.
            pattern = f"%{_escape_like(query)}%"
            clauses.append(
                "(title LIKE ? ESCAPE '\\' OR rule_id LIKE ? ESCAPE '\\' "
                "OR note LIKE ? ESCAPE '\\' OR source_text LIKE ? ESCAPE '\\')"
            )
            params.extend([pattern] * 4)

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM entries{where} "
                f"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def lineage(self, entry_id: int) -> list[Entry]:
        """The chain from the earliest ancestor down to `entry_id`.

        Oldest first, because that is the order the tuning happened in and the
        order an analyst reads it.
        """
        chain: list[Entry] = []
        seen: set[int] = set()
        current: int | None = entry_id
        while current is not None:
            if current in seen:
                # parent_id is set by this module and should never cycle, but a
                # hand-edited database must not spin forever.
                raise Refusal(
                    "STORE_LINEAGE_CYCLE",
                    f"entry {current} is its own ancestor, so this history has "
                    f"been edited outside the tool.",
                    "store",
                )
            seen.add(current)
            found = self.entry(current)
            chain.append(found)
            current = found.parent_id
        return list(reversed(chain))

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM entries").fetchone()
        return int(row["n"])

    def close(self) -> None:
        """Release the in-memory handle.

        File-backed stores close their connection after every call, so this is
        a no-op for them. It matters for `:memory:`, whose one handle is held
        open for the store's lifetime.
        """
        if self._memory is not None:
            self._memory.close()
            self._memory = None


def _escape_like(text: str) -> str:
    """Escape LIKE wildcards so a search for `%` searches for `%`."""
    return (
        text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )


class _Session:
    """A connection scoped to one operation.

    `with sqlite3.connect(...) as conn` commits the transaction and does NOT
    close the connection -- a genuine sqlite3 trap. Left as-is, every call here
    leaked a handle, and on Windows the leaked handle holds a lock on the
    database file, so the next open fails with a permission error that looks
    like a filesystem problem rather than a bug in this module.
    """

    __slots__ = ("conn", "_close")

    def __init__(self, conn: sqlite3.Connection, *, close: bool) -> None:
        self.conn = conn
        self.conn.row_factory = sqlite3.Row
        self._close = close

    def __enter__(self) -> sqlite3.Connection:
        return self.conn

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        try:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
        finally:
            if self._close:
                self.conn.close()

    def close(self) -> None:
        """Release the in-memory handle. File sessions close themselves."""
        self.conn.close()
