"""The rule history store.

The behaviour worth protecting here is that history is APPEND-ONLY and that
lineage survives. A store that silently overwrote a rule, or lost the link
between a pasted rule and the tuned version of it, would still pass a naive
"can I save and load" test -- so most of these tests are about the second save,
not the first.
"""

from __future__ import annotations

import unittest
from decimal import Decimal

from ruleforge.codec import SCHEMA_VERSION
from ruleforge.ir import (
    Annotations,
    Comparison,
    Emit,
    FieldRef,
    Filter,
    Literal,
    Read,
    Rule,
)
from ruleforge.store import ORIGINS, Entry, RuleStore, default_store_path
from ruleforge.values import Refusal


def rule(rule_id="r", title="", threshold=1, dialect="sentinel") -> Rule:
    return Rule(
        rule_id=rule_id,
        pipeline=(
            Read(id="src", table="SecurityEvent"),
            Filter(id="f", condition=Comparison(
                ">=", FieldRef("Hits"), Literal(Decimal(threshold)))),
            Emit(id="out"),
        ),
        annotations=Annotations(title=title),
        metadata={"dialect": dialect, "language": "KQL", "artifact": "rule"},
    )


class StoreCase(unittest.TestCase):
    """An in-memory store, closed afterwards.

    `:memory:` holds one connection open for the store's lifetime, so a test
    that drops the store without closing it leaks the handle. Harmless here,
    but the same omission in the API server is a file lock on Windows.
    """

    def setUp(self):
        self.store = RuleStore(":memory:")

    def tearDown(self):
        self.store.close()


class Saving(StoreCase):
    def test_a_saved_rule_comes_back_identical(self):
        original = rule(title="LSASS access")
        entry = self.store.save(original, origin="authored")
        self.assertEqual(self.store.rule(entry.id), original)

    def test_saving_returns_the_row_it_wrote(self):
        entry = self.store.save(rule(title="t"), origin="authored")
        self.assertIsInstance(entry, Entry)
        self.assertGreater(entry.id, 0)
        self.assertEqual(entry.origin, "authored")
        self.assertEqual(entry.title, "t")

    def test_the_dialect_is_read_off_the_rule_not_passed_in(self):
        # Two sources of truth for which vendor a rule belongs to is how a
        # rule gets stored under one and looked up under another.
        entry = self.store.save(rule(dialect="splunk"), origin="imported")
        self.assertEqual(entry.dialect, "splunk")

    def test_the_title_defaults_to_the_rules_own_annotation(self):
        entry = self.store.save(rule(title="Credential Access"), origin="authored")
        self.assertEqual(entry.title, "Credential Access")

    def test_an_explicit_title_overrides_the_annotation(self):
        entry = self.store.save(
            rule(title="from the rule"), origin="authored", title="from the caller"
        )
        self.assertEqual(entry.title, "from the caller")

    def test_the_schema_version_is_recorded(self):
        # A stored rule has to be migratable, which means knowing what wrote it.
        entry = self.store.save(rule(), origin="authored")
        self.assertEqual(entry.schema_version, SCHEMA_VERSION)

    def test_the_original_text_is_kept_verbatim(self):
        # An imported rule must still be showable exactly as pasted, because
        # rendering it back from the IR is lossy in every dialect today.
        text = "SecurityEvent\n| where EventID == 4624   // analyst's comment"
        entry = self.store.save(rule(), origin="imported", source_text=text)
        self.assertEqual(self.store.entry(entry.id).source_text, text)

    def test_every_origin_is_accepted(self):
        for origin in sorted(ORIGINS):
            with self.subTest(origin=origin):
                entry = self.store.save(rule(), origin=origin)
                self.assertEqual(entry.origin, origin)

    def test_an_unknown_origin_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.store.save(rule(), origin="probably_fine")
        self.assertEqual(caught.exception.code, "STORE_ORIGIN_UNKNOWN")

    def test_saving_something_that_is_not_a_rule_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.store.save("not a rule", origin="authored")  # type: ignore[arg-type]
        self.assertEqual(caught.exception.code, "STORE_NOT_A_RULE")


class HistoryIsAppendOnly(StoreCase):
    def test_saving_the_same_rule_id_twice_keeps_both(self):
        # THE point of the store. Tuning a rule must not destroy the version
        # that was working, because "put it back how it was" is the most
        # common request during a tuning session.
        first = self.store.save(rule(threshold=5), origin="authored")
        second = self.store.save(rule(threshold=50), origin="authored")
        self.assertNotEqual(first.id, second.id)
        self.assertEqual(self.store.count(), 2)

    def test_both_versions_keep_their_own_threshold(self):
        first = self.store.save(rule(threshold=5), origin="authored")
        second = self.store.save(rule(threshold=50), origin="authored")
        self.assertEqual(
            self.store.rule(first.id).pipeline[1].condition.right.value,
            Decimal(5),
        )
        self.assertEqual(
            self.store.rule(second.id).pipeline[1].condition.right.value,
            Decimal(50),
        )

    def test_history_is_newest_first(self):
        ids = [self.store.save(rule(), origin="authored").id for _ in range(3)]
        self.assertEqual([e.id for e in self.store.history()], list(reversed(ids)))

    def test_history_pages(self):
        for _ in range(5):
            self.store.save(rule(), origin="authored")
        page = self.store.history(limit=2, offset=2)
        self.assertEqual(len(page), 2)

    def test_an_absurd_page_size_is_refused(self):
        for bad in (0, -1, 5000):
            with self.subTest(limit=bad):
                with self.assertRaises(Refusal):
                    self.store.history(limit=bad)

    def test_a_negative_offset_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.store.history(offset=-1)
        self.assertEqual(caught.exception.code, "STORE_OFFSET_INVALID")


class Lineage(StoreCase):
    """The tuning trail: what did this rule look like before I touched it?"""

    def test_a_tuned_rule_points_at_the_one_it_came_from(self):
        pasted = self.store.save(
            rule(threshold=1), origin="imported", source_text="orig"
        )
        tuned = self.store.save(
            rule(threshold=10), origin="authored", parent_id=pasted.id,
            note="raised threshold, too noisy on build agents",
        )
        self.assertEqual(tuned.parent_id, pasted.id)

    def test_lineage_reads_oldest_first(self):
        # The order the tuning happened in, which is the order it is read in.
        a = self.store.save(rule(threshold=1), origin="imported")
        b = self.store.save(rule(threshold=5), origin="authored", parent_id=a.id)
        c = self.store.save(rule(threshold=20), origin="authored", parent_id=b.id)
        self.assertEqual([e.id for e in self.store.lineage(c.id)], [a.id, b.id, c.id])

    def test_the_tuning_note_survives(self):
        a = self.store.save(rule(), origin="imported")
        b = self.store.save(
            rule(), origin="authored", parent_id=a.id,
            note="excluded C:\\Program Files\\Backup\\agent.exe",
        )
        self.assertIn("agent.exe", self.store.entry(b.id).note)

    def test_lineage_of_a_first_version_is_just_itself(self):
        only = self.store.save(rule(), origin="authored")
        self.assertEqual([e.id for e in self.store.lineage(only.id)], [only.id])

    def test_deriving_from_an_entry_that_does_not_exist_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.store.save(rule(), origin="authored", parent_id=9999)
        self.assertEqual(caught.exception.code, "STORE_PARENT_UNKNOWN")

    def test_a_rejected_save_leaves_no_row_behind(self):
        with self.assertRaises(Refusal):
            self.store.save(rule(), origin="authored", parent_id=9999)
        self.assertEqual(self.store.count(), 0)


class Forgetting(StoreCase):
    def test_a_leaf_version_can_be_removed(self):
        entry = self.store.save(rule(), origin="authored")
        self.store.forget(entry.id)
        self.assertEqual(self.store.count(), 0)

    def test_a_version_later_ones_were_tuned_from_cannot_be_removed(self):
        # Deleting it would leave a history that reads as if the rule appeared
        # fully formed, which is exactly what the lineage exists to prevent.
        parent = self.store.save(rule(), origin="imported")
        self.store.save(rule(), origin="authored", parent_id=parent.id)
        with self.assertRaises(Refusal) as caught:
            self.store.forget(parent.id)
        self.assertEqual(caught.exception.code, "STORE_ENTRY_HAS_CHILDREN")
        self.assertEqual(self.store.count(), 2)

    def test_forgetting_something_that_is_not_there_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.store.forget(4242)
        self.assertEqual(caught.exception.code, "STORE_ENTRY_UNKNOWN")


class Filtering(StoreCase):
    def setUp(self):
        super().setUp()
        self.store.save(rule(rule_id="a", title="LSASS access",
                             dialect="sentinel"), origin="imported")
        self.store.save(rule(rule_id="b", title="Brute force",
                             dialect="splunk"), origin="authored")
        self.store.save(rule(rule_id="c", title="100% CPU spike",
                             dialect="splunk"), origin="synthesized")

    def test_filtering_by_dialect(self):
        found = self.store.history(dialect="splunk")
        self.assertEqual({e.rule_id for e in found}, {"b", "c"})

    def test_filtering_by_origin(self):
        found = self.store.history(origin="synthesized")
        self.assertEqual([e.rule_id for e in found], ["c"])

    def test_an_unknown_origin_filter_is_refused(self):
        with self.assertRaises(Refusal):
            self.store.history(origin="nonsense")

    def test_searching_matches_the_title(self):
        found = self.store.history(query="LSASS")
        self.assertEqual([e.rule_id for e in found], ["a"])

    def test_searching_matches_the_rule_id(self):
        self.assertEqual([e.rule_id for e in self.store.history(query="b")], ["b"])

    def test_a_percent_sign_is_searched_for_literally(self):
        # Unescaped, `%` is the LIKE wildcard and this query would match every
        # row -- a search box that always returns everything.
        found = self.store.history(query="100%")
        self.assertEqual([e.rule_id for e in found], ["c"])

    def test_an_underscore_is_searched_for_literally(self):
        self.store.save(rule(rule_id="d", title="a_b"), origin="authored")
        found = self.store.history(query="a_b")
        self.assertEqual([e.rule_id for e in found], ["d"])
        # `_` is LIKE's single-character wildcard; unescaped this also matches
        # "axb", so a store that forgot to escape would return both.
        self.assertEqual(len(found), 1)


class Serialising(StoreCase):
    def test_a_list_row_does_not_carry_the_whole_rule(self):
        # Listing a hundred versions should not ship a hundred rule bodies to
        # the browser, nor decode and validate a hundred rules.
        entry = self.store.save(rule(title="t"), origin="authored",
                                source_text="some text")
        body = entry.as_dict()
        self.assertNotIn("rule", body)
        self.assertNotIn("source_text", body)
        self.assertTrue(body["has_source"])

    def test_an_opened_row_carries_the_rule_and_the_text(self):
        entry = self.store.save(rule(title="t"), origin="imported",
                                source_text="original text")
        body = entry.as_dict(include_rule=True)
        self.assertEqual(body["source_text"], "original text")
        self.assertEqual(body["rule"]["schema"], SCHEMA_VERSION)

    def test_a_row_with_no_source_says_so(self):
        entry = self.store.save(rule(), origin="authored")
        self.assertFalse(entry.as_dict()["has_source"])


class OnDisk(unittest.TestCase):
    """The real path, not the in-memory one, because they differ."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.path = f"{self.tmp.name}/history.sqlite3"

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_rule_survives_closing_and_reopening_the_store(self):
        first = RuleStore(self.path)
        entry = first.save(rule(title="persisted", threshold=7), origin="authored")
        again = RuleStore(self.path)
        self.assertEqual(again.count(), 1)
        self.assertEqual(
            again.rule(entry.id).pipeline[1].condition.right.value, Decimal(7)
        )

    def test_opening_an_existing_store_does_not_wipe_it(self):
        # CREATE TABLE IF NOT EXISTS, not CREATE TABLE. Getting this wrong
        # loses the entire history on the second launch.
        RuleStore(self.path).save(rule(), origin="authored")
        RuleStore(self.path)
        self.assertEqual(RuleStore(self.path).count(), 1)

    def test_the_parent_directory_is_created(self):
        nested = f"{self.tmp.name}/a/b/c/history.sqlite3"
        store = RuleStore(nested)
        self.assertEqual(store.count(), 0)

    def test_the_default_path_is_under_the_data_directory(self):
        # `data/` already exists in the repository and is empty, which is
        # where this was always meant to live.
        self.assertEqual(default_store_path().name, "history.sqlite3")
        self.assertEqual(default_store_path().parent.name, "data")

    def test_the_default_path_honours_an_override(self):
        import os
        os.environ["RULEFORGE_HOME"] = self.tmp.name
        try:
            self.assertEqual(
                str(default_store_path().parent), str(self.tmp.name)
            )
        finally:
            del os.environ["RULEFORGE_HOME"]


if __name__ == "__main__":
    unittest.main()
