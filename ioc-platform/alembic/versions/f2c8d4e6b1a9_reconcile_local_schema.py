"""reconcile local persistence schema"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f2c8d4e6b1a9"
down_revision: Union[str, Sequence[str], None] = "a1f96ea838ee"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_names(bind) -> set[str]:
    return set(sa.inspect(bind).get_table_names())


def _column_names(bind, table_name: str) -> set[str]:
    return {column["name"] for column in sa.inspect(bind).get_columns(table_name)}


def _index_names(bind, table_name: str) -> set[str]:
    return {index["name"] for index in sa.inspect(bind).get_indexes(table_name)}


def _unique_constraint_names(bind, table_name: str) -> set[str]:
    return {
        constraint["name"]
        for constraint in sa.inspect(bind).get_unique_constraints(table_name)
        if constraint.get("name")
    }


def _drop_equivalent_unique_indexes(bind, table_name: str, column_names: list[str]) -> None:
    for index in sa.inspect(bind).get_indexes(table_name):
        if index.get("unique") and index.get("column_names") == column_names:
            op.drop_index(index["name"], table_name=table_name)


def upgrade() -> None:
    bind = op.get_bind()
    tables = _table_names(bind)

    if "batches" not in tables:
        op.create_table(
            "batches",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
            sa.Column("total", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("completed", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("summary_json", sa.Text(), nullable=True, server_default="{}"),
            sa.Column("result_json", sa.Text(), nullable=True, server_default="{}"),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
    else:
        batch_columns = _column_names(bind, "batches")
        additions = {
            "status": sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
            "total": sa.Column("total", sa.Integer(), nullable=False, server_default="0"),
            "completed": sa.Column("completed", sa.Integer(), nullable=False, server_default="0"),
            "summary_json": sa.Column("summary_json", sa.Text(), nullable=True, server_default="{}"),
            "result_json": sa.Column("result_json", sa.Text(), nullable=True, server_default="{}"),
            "error": sa.Column("error", sa.Text(), nullable=True),
        }
        for name, column in additions.items():
            if name not in batch_columns:
                op.add_column("batches", column)

    batch_indexes = _index_names(bind, "batches")
    if "ix_batches_created_at" not in batch_indexes:
        op.create_index("ix_batches_created_at", "batches", ["created_at"])
    if "ix_batches_status_created" not in batch_indexes:
        op.create_index("ix_batches_status_created", "batches", ["status", "created_at"])

    sqlite_fk_disabled = False
    if bind.dialect.name == "sqlite":
        bind.exec_driver_sql("PRAGMA foreign_keys=OFF")
        sqlite_fk_disabled = True
    try:
        with op.batch_alter_table("iocs") as batch_op:
            batch_op.alter_column("value", existing_type=sa.String(length=512), type_=sa.String(length=2048), existing_nullable=False)

        with op.batch_alter_table("ioc_feedback") as batch_op:
            batch_op.alter_column("ioc_value", existing_type=sa.String(length=512), type_=sa.String(length=2048), existing_nullable=False)

        ioc_duplicates = bind.execute(
            sa.text("SELECT value, COUNT(*) FROM iocs GROUP BY value HAVING COUNT(*) > 1")
        ).fetchall()
        if ioc_duplicates:
            duplicate_rows = bind.execute(
                sa.text(
                    "SELECT old.id, current.id FROM iocs AS old "
                    "JOIN iocs AS current ON current.value = old.value "
                    "AND current.id = (SELECT MAX(latest.id) FROM iocs AS latest WHERE latest.value = old.value) "
                    "WHERE old.id <> current.id"
                )
            ).fetchall()
            duplicate_map = {old_id: current_id for old_id, current_id in duplicate_rows}
            merge_groups: dict[object, list[object]] = {}
            for old_id, current_id in duplicate_map.items():
                merge_groups.setdefault(current_id, []).append(old_id)
            ioc_columns = _column_names(bind, "iocs")
            for current_id, old_ids in merge_groups.items():
                group_rows = bind.execute(
                    sa.text(
                        "SELECT id, first_seen, last_seen, ioc_type FROM iocs "
                        "WHERE value = (SELECT value FROM iocs WHERE id = :current)"
                    ),
                    {"current": current_id},
                ).fetchall() if {"first_seen", "last_seen", "ioc_type"} <= ioc_columns else []
                if not group_rows:
                    continue
                first_seen = min((row[1] for row in group_rows if row[1] is not None), default=None)
                last_seen = max((row[2] for row in group_rows if row[2] is not None), default=None)
                typed = [row[3] for row in group_rows if row[3] and str(row[3]).lower() != "unknown"]
                ioc_type = typed[0] if typed else (next((row[3] for row in group_rows if row[0] == current_id and row[3]), None) or "unknown")
                bind.execute(
                    sa.text(
                        "UPDATE iocs SET first_seen = :first_seen, last_seen = :last_seen, ioc_type = :ioc_type "
                        "WHERE id = :current"
                    ),
                    {"first_seen": first_seen, "last_seen": last_seen, "ioc_type": ioc_type, "current": current_id},
                )
            for old_id, current_id in duplicate_map.items():
                bind.execute(
                    sa.text("UPDATE lookup_results SET ioc_id = :current WHERE ioc_id = :old"),
                    {"old": old_id, "current": current_id},
                )
            if "investigation_iocs" in _table_names(bind):
                link_columns = _column_names(bind, "investigation_iocs")
                selected = ["id", "investigation_id", "ioc_id"]
                if "notes" in link_columns:
                    selected.append("notes")
                if "created_at" in link_columns:
                    selected.append("created_at")
                link_rows = bind.execute(
                    sa.text(f"SELECT {', '.join(selected)} FROM investigation_iocs")
                ).fetchall()
                links_by_target: dict[tuple[object, object], list[tuple]] = {}
                for link_row in link_rows:
                    investigation_id, ioc_id = link_row[1], link_row[2]
                    target_ioc_id = duplicate_map.get(ioc_id, ioc_id)
                    links_by_target.setdefault((investigation_id, target_ioc_id), []).append(link_row)
                for link_group in links_by_target.values():
                    keep_id = max(row[0] for row in link_group)
                    if len(link_group) > 1:
                        notes = [str(row[3]).strip() for row in link_group if len(row) > 3 and row[3]]
                        if notes:
                            bind.execute(
                                sa.text("UPDATE investigation_iocs SET notes = :notes WHERE id = :id"),
                                {"notes": "\n".join(dict.fromkeys(notes)), "id": keep_id},
                            )
                        created_values = [row[4] for row in link_group if len(row) > 4 and row[4] is not None]
                        if created_values:
                            bind.execute(
                                sa.text("UPDATE investigation_iocs SET created_at = :created_at WHERE id = :id"),
                                {"created_at": min(created_values), "id": keep_id},
                            )
                    for row in link_group:
                        if row[0] != keep_id:
                            bind.execute(
                                sa.text("DELETE FROM investigation_iocs WHERE id = :id"),
                                {"id": row[0]},
                            )
                for old_id, current_id in duplicate_map.items():
                    bind.execute(
                        sa.text("UPDATE investigation_iocs SET ioc_id = :current WHERE ioc_id = :old"),
                        {"old": old_id, "current": current_id},
                    )
            bind.execute(sa.text("DELETE FROM iocs WHERE id NOT IN (SELECT MAX(id) FROM iocs GROUP BY value)"))
        if "uq_ioc_value" not in _unique_constraint_names(bind, "iocs"):
            _drop_equivalent_unique_indexes(bind, "iocs", ["value"])
            with op.batch_alter_table("iocs") as batch_op:
                batch_op.create_unique_constraint("uq_ioc_value", ["value"])

        link_duplicates = bind.execute(
            sa.text(
                "SELECT investigation_id, ioc_id, COUNT(*) FROM investigation_iocs "
                "GROUP BY investigation_id, ioc_id HAVING COUNT(*) > 1"
            )
        ).fetchall()
        if link_duplicates:
            bind.execute(
                sa.text(
                    "DELETE FROM investigation_iocs WHERE id NOT IN "
                    "(SELECT MAX(id) FROM investigation_iocs GROUP BY investigation_id, ioc_id)"
                )
            )
        if "uq_investigation_ioc" not in _unique_constraint_names(bind, "investigation_iocs"):
            _drop_equivalent_unique_indexes(bind, "investigation_iocs", ["investigation_id", "ioc_id"])
            with op.batch_alter_table("investigation_iocs") as batch_op:
                batch_op.create_unique_constraint("uq_investigation_ioc", ["investigation_id", "ioc_id"])
    finally:
        if sqlite_fk_disabled:
            bind.exec_driver_sql("PRAGMA foreign_keys=OFF")

    legacy_indexes = {
        "iocs": _index_names(bind, "iocs"),
        "investigation_iocs": _index_names(bind, "investigation_iocs"),
        "lookup_results": _index_names(bind, "lookup_results"),
    }
    for index_name, table, columns in (
        ("ix_iocs_value", "iocs", ["value"]),
        ("ix_investigation_iocs_investigation_id", "investigation_iocs", ["investigation_id"]),
        ("ix_investigation_iocs_ioc_id", "investigation_iocs", ["ioc_id"]),
        ("ix_lookup_results_ioc_id", "lookup_results", ["ioc_id"]),
        ("ix_lookup_results_ioc_task", "lookup_results", ["ioc_id", "task_id"]),
        ("ix_lookup_results_task_id", "lookup_results", ["task_id"]),
    ):
        if index_name not in legacy_indexes[table]:
            op.create_index(index_name, table, columns)
            legacy_indexes[table].add(index_name)

    for table in ("investigations", "iocs", "investigation_iocs", "lookup_results"):
        with op.batch_alter_table(table) as batch_op:
            batch_op.alter_column("id", existing_type=sa.Integer(), nullable=False)

    lookup_columns = _column_names(bind, "lookup_results")
    if "batch_id" not in lookup_columns:
        op.add_column("lookup_results", sa.Column("batch_id", sa.String(length=32), nullable=True))

    duplicate_tasks = bind.execute(
        sa.text("SELECT task_id, COUNT(*) FROM lookup_results GROUP BY task_id HAVING COUNT(*) > 1")
    ).fetchall()
    if duplicate_tasks:
        bind.execute(
            sa.text(
                "DELETE FROM lookup_results "
                "WHERE id NOT IN (SELECT MAX(id) FROM lookup_results GROUP BY task_id)"
            )
        )

    lookup_indexes = _index_names(bind, "lookup_results")
    if "ix_lookup_results_created_at" not in lookup_indexes:
        op.create_index("ix_lookup_results_created_at", "lookup_results", ["created_at"])
    if "ix_lookup_results_ioc_created" not in lookup_indexes:
        op.create_index("ix_lookup_results_ioc_created", "lookup_results", ["ioc_id", "created_at"])
    if "ix_lookup_results_batch_id" not in lookup_indexes:
        op.create_index("ix_lookup_results_batch_id", "lookup_results", ["batch_id"])
    if "uq_lookup_results_task_id" not in _unique_constraint_names(bind, "lookup_results"):
        _drop_equivalent_unique_indexes(bind, "lookup_results", ["task_id"])
        with op.batch_alter_table("lookup_results") as batch_op:
            batch_op.create_unique_constraint("uq_lookup_results_task_id", ["task_id"])
    if bind.dialect.name == "sqlite":
        violations = bind.execute(sa.text("PRAGMA foreign_key_check")).fetchall()
        if violations:
            raise RuntimeError(f"Foreign key integrity check failed after reconciliation: {violations}")


def downgrade() -> None:
    bind = op.get_bind()
    tables = _table_names(bind)
    if "batches" in tables:
        batch_count = bind.execute(sa.text("SELECT COUNT(*) FROM batches")).scalar()
        if batch_count:
            raise RuntimeError("Refusing to downgrade: persisted batch records would be orphaned")
    if "batch_id" in _column_names(bind, "lookup_results"):
        linked_results = bind.execute(
            sa.text("SELECT COUNT(*) FROM lookup_results WHERE batch_id IS NOT NULL")
        ).scalar()
        if linked_results:
            raise RuntimeError("Refusing to downgrade: lookup_results.batch_id associations would be lost")
    batch_indexes = _index_names(bind, "batches") if "batches" in tables else set()
    for index_name in ("ix_batches_status_created", "ix_batches_created_at"):
        if index_name in batch_indexes:
            op.drop_index(index_name, table_name="batches")
    if "batches" in tables:
        op.drop_table("batches")

    lookup_indexes = _index_names(bind, "lookup_results")
    for index_name in ("ix_lookup_results_batch_id", "ix_lookup_results_ioc_created", "ix_lookup_results_created_at"):
        if index_name in lookup_indexes:
            op.drop_index(index_name, table_name="lookup_results")
    if "uq_lookup_results_task_id" in _unique_constraint_names(bind, "lookup_results"):
        with op.batch_alter_table("lookup_results") as batch_op:
            batch_op.drop_constraint("uq_lookup_results_task_id", type_="unique")
    if "batch_id" in _column_names(bind, "lookup_results"):
        with op.batch_alter_table("lookup_results") as batch_op:
            batch_op.drop_column("batch_id")
    with op.batch_alter_table("iocs") as batch_op:
        batch_op.alter_column("value", existing_type=sa.String(length=2048), type_=sa.String(length=512), existing_nullable=False)
    with op.batch_alter_table("ioc_feedback") as batch_op:
        batch_op.alter_column("ioc_value", existing_type=sa.String(length=2048), type_=sa.String(length=512), existing_nullable=False)
