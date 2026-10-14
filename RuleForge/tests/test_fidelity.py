"""Cross-dialect fidelity: no conversion may lose a predicate in silence.

Written after a silent loss shipped. `render_wazuh` pulled the first
`Correlation` and the first `Filter` out of the pipeline with `next()` and
ignored everything else -- there was no dispatch chain, so nothing could end
in a refusal. Eight stage kinds were dropped without a word, including a
SECOND filter (half a conjunction) and an `Aggregate` (the whole threshold).
A rule meaning "five failed logons from one account" rendered as "any failed
logon" and fired on the first event.

The whole suite stayed green through all of it, because every test checked a
conversion somebody had thought to check. This module does not: it walks a
corpus of rules through EVERY ready dialect and asserts a general property --
if a field name or a literal value in the source is not in the output, there
must be a diagnostic saying so.

That is why it is written as a sweep rather than as cases. A case tests what
its author remembered; a sweep tests what nobody thought of.
"""

from __future__ import annotations

import unittest
from decimal import Decimal

from ruleforge import dialects
from ruleforge.ir import (
    Arith,
    BoolOp,
    Call,
    Comparison,
    FieldRef,
    ListExpr,
    Literal,
    Not,
    Regex,
    Rule,
    Span,
)
from ruleforge.values import Refusal

#: Rule shapes per dialect, chosen to exercise the things that get dropped:
#: conjunctions, disjunctions, negation, membership, substrings, thresholds.
CORPUS: dict[str, dict[str, str]] = {
    "sentinel": {
        "and-chain": 'SecurityEvent | where EventID == 4624 and LogonType == 3 '
                     'and AuthenticationPackageName == "NTLM"',
        "or-branch": "T | where EventID == 4624 or EventID == 4625",
        "substring": 'T | where Image endswith "lsass.exe" and Cmd contains "dump"',
        "negation": 'T | where EventID == 1 and not(User == "SYSTEM")',
        "in-list": "T | where EventID in (4624, 4625, 4634)",
        "numeric": "T | where Port >= 443 and Bytes < 1000",
        "nested-or": 'T | where Cat == "auth" and (Code == 1 or Code == 2)',
        "threshold": "T | where A == 1 | summarize Hits=count() by Host "
                     "| where Hits >= 5",
    },
    "splunk": {
        "and-chain": 'index=main EventCode=4625 LogonType=3 Account="svc"',
        "eval-where": 'index=main | where src_ip="10.0.0.1" AND dest_port=445',
        "stats": "index=main EventCode=4625 | stats count as Attempts, "
                 "dc(user) as Users by src_ip | where Attempts > 5",
    },
    "sigma": {
        "endswith": "title: t\nlogsource:\n    category: process_access\n"
                    "detection:\n    selection:\n"
                    "        TargetImage|endswith: '/lsass.exe'\n"
                    "        GrantedAccess: '0x1410'\n"
                    "    condition: selection\n",
        "two-sel": "title: t\nlogsource:\n    category: process_creation\n"
                   "detection:\n    sel1:\n        Image: 'a.exe'\n"
                   "    sel2:\n        User: 'bob'\n"
                   "    condition: sel1 and sel2\n",
    },
    "qradar": {
        "and-chain": "SELECT * FROM events WHERE qid = 28250080 "
                     "AND username = 'admin' AND sourceport = 445",
        "like": "SELECT * FROM events WHERE username ILIKE '%admin%'",
        "threshold": "SELECT sourceip, COUNT(*) AS hits FROM events "
                     "WHERE qid = 1 GROUP BY sourceip HAVING COUNT(*) > 5",
    },
    "elastic": {
        "and-chain": 'process where process.name == "procdump.exe" '
                     'and process.parent.name == "cmd.exe"',
        "wildcard": 'process where process.name : "*.scr"',
        "sequence": "sequence by host.id with maxspan=5m\n"
                    '  [process where process.name == "a.exe"]\n'
                    "  [network where destination.port == 445]",
    },
    "chronicle": {
        "and-chain": "rule r {\n  events:\n"
                     '    $e.metadata.event_type = "PROCESS_OPEN"\n'
                     '    $e.target.process.file.full_path = "/lsass.exe"\n'
                     "  condition:\n    $e\n}",
    },
    "crowdstrike": {
        "and-chain": "event_simpleName:'ProcessRollup2'+FileName:'lsass.exe'",
        "list": "event_simpleName:'ProcessRollup2'+FileName:['a.exe','b.exe']",
        "wildcard": "FileName:*'*lsass*'",
    },
    "wazuh": {
        "fields": '<group name="g,"><rule id="100" level="5">'
                  '<field name="EventID">4624</field>'
                  '<field name="LogonType">3</field>'
                  "<description>d</description></rule></group>",
        # A numeric rule id: `rule 100 {` is not a YARA-L identifier, and
        # chronicle emitted exactly that before `_rule_name` existed.
        "numeric-id": '<group name="g,"><rule id="5710" level="5">'
                      '<field name="EventID">4624</field>'
                      "<description>d</description></rule></group>",
    },
}

#: Field and value shapes that are not plain ASCII.
#:
#: Added after a non-ASCII FIELD name was found to render in five dialects and
#: re-import in none of them: the renderers' "safe to write bare" checks used
#: `str.isalnum()`, which is unicode-aware, while every tokenizer here accepts
#: ASCII only. Synthesis from a localized log happily pinned such a field, so
#: an analyst could generate a rule, save it, and have the tool refuse its own
#: output.
#:
#: Kept separate because most of these must REFUSE rather than convert, and
#: the sweep treats a refusal as an honest outcome either way.
AWKWARD: dict[str, str] = {
    "cjk value": 'T | where user == "\u7ba1\u7406\u8005"',
    "emoji value": 'T | where msg == "alert \U0001F525"',
    "rtl value": 'T | where name == "\u0645\u062f\u064a\u0631"',
    "zero width": 'T | where f == "a\u200bb"',
    "quote in value": 'T | where cmd == "say \\"hi\\""',
    "backslash value": 'T | where path endswith "\\\\lsass.exe"',
    "percent in value": 'T | where ratio == "100%"',
    "spaced field": 'T | where ["Event Name"] == "Logon"',
}


def _leaves(expr) -> tuple[set[str], set[str]]:
    """Field names and literal values reachable from an expression."""
    fields: set[str] = set()
    values: set[str] = set()

    def walk(node) -> None:
        if isinstance(node, FieldRef):
            fields.add(node.name)
            fields.update(node.path)
        elif isinstance(node, Literal):
            if node.value is None or isinstance(node.value, bool):
                return
            text = str(node.value)
            if isinstance(node.value, Decimal) and "." in text:
                text = text.rstrip("0").rstrip(".")
            if text.strip():
                values.add(text)
        elif isinstance(node, Regex):
            values.add(node.pattern)
        elif isinstance(node, BoolOp):
            for operand in node.operands:
                walk(operand)
        elif isinstance(node, ListExpr):
            for item in node.items:
                walk(item)
        elif isinstance(node, Not):
            walk(node.operand)
        elif isinstance(node, (Comparison, Arith)):
            walk(node.left)
            walk(node.right)
        elif isinstance(node, Span):
            walk(node.value)
            walk(node.low)
            walk(node.high)
        elif isinstance(node, Call):
            for argument in node.args:
                walk(argument)

    walk(expr)
    return fields, values


def rule_leaves(rule: Rule) -> tuple[set[str], set[str]]:
    """Every field and value the rule's CONDITIONS mention.

    Walks bindings and sequence steps as well as the main pipeline, because a
    predicate hiding in either is exactly as droppable as one in the open.
    """
    fields: set[str] = set()
    values: set[str] = set()
    for stream in [rule.pipeline] + [b.pipeline for b in rule.bindings]:
        for node in stream:
            for attribute in ("condition", "predicate", "until"):
                sub = getattr(node, attribute, None)
                if sub is not None:
                    found_fields, found_values = _leaves(sub)
                    fields |= found_fields
                    values |= found_values
            for step in getattr(node, "steps", ()) or ():
                found_fields, found_values = _leaves(step.condition)
                fields |= found_fields
                values |= found_values
    return fields, values


def normalise(text: str) -> str:
    """Flatten the wildcard spellings, so a TRANSLATION is not read as a loss.

    `%admin%` in a LIKE pattern is `*admin*` in EQL and FQL, `^.*admin.*$` as
    a KQL regex, and `contains "admin"` once KQL's own case-insensitive
    operator is used -- which is the BEST of the four and the one the
    renderer now picks. All of them are the same test.

    So the wildcards are REMOVED rather than mapped to a common sentinel. An
    earlier version mapped them to one marker, which still called
    `contains "admin"` a dropped value: the test punished the renderer for
    improving. A detector that cries wolf about correct output stops being
    read, and four false alarms buried one real finding the first time this
    ran.
    """
    out = text
    for noise in ("^", "$", "\\", ".*", "%", "*", "_", "?"):
        out = out.replace(noise, "")
    return out


#: Shapes that were NOT in the corpus, and the four defects they exposed.
#:
#: Added after a direct question -- "are you sure the backend is ready?" --
#: was answered by probing shapes nobody had thought to probe. Four
#: render/parse asymmetries fell out in one pass, one of them introduced by a
#: fix made an hour earlier:
#:
#:   * `1e10` rendered to FQL as `1E+10`, and `+` had just stopped being a
#:     bare-value character, so the scanner read `1E` then took the `+` for an
#:     AND
#:   * `x == 1 and x == 2` rendered to Sigma as two `x:` keys in ONE selection
#:     -- a duplicate YAML key, which this module's own reader refuses
#:   * `x == ""` rendered to Wazuh as an empty `<field>`, which tests nothing
#:     and therefore matches every event
#:
#: Kept here rather than in the main corpus because they are degenerate by
#: design: contradictions, empty values and numeric extremes are what a
#: generated or machine-edited rule contains, not what a person writes.
EDGES: dict[str, str] = {
    "scientific": "T | where x == 1e10",
    "huge int": "T | where x == 99999999999999999999999999",
    "tiny decimal": "T | where x == 0.000000001",
    "negative": "T | where x == -42",
    "single-item in": "T | where x in (1)",
    "duplicate in": "T | where x in (1, 1, 1)",
    "deep nesting": "T | where ((((x == 1))))",
    "long conjunction": "T | where " + " and ".join(
        f"f{i} == {i}" for i in range(12)),
    "mixed precedence": "T | where a == 1 or b == 2 and c == 3",
    "double negation": "T | where not(not(x == 1))",
    "negated or": "T | where not(a == 1 or b == 2)",
    "same field twice": "T | where x == 1 and x == 2",
    "same field repeated": "T | where x == 1 and x == 1",
    "impossible range": "T | where x > 5 and x < 3",
    "number as string": 'T | where x == "5"',
    "bool literal": "T | where x == true",
    "two filters": "T | where a == 1 | where b == 2",
    "empty value": 'T | where x == ""',
}


class DegenerateShapesConvertOrRefuse(unittest.TestCase):
    """The shapes a generated rule contains and a person rarely writes.

    Contradictions, empty values, numeric extremes and repeated fields. Four
    real asymmetries hid here, so the corpus now carries them.
    """

    def test_every_edge_shape_lowers(self):
        for label, text in EDGES.items():
            with self.subTest(case=label):
                rule, _ = dialects.lower("sentinel", text)
                self.assertTrue(rule.pipeline)

    def test_each_one_round_trips_in_its_own_dialect(self):
        for label, text in EDGES.items():
            with self.subTest(case=label):
                rule, _ = dialects.lower("sentinel", text)
                once, _ = dialects.render("sentinel", rule)
                back, _ = dialects.lower("sentinel", once)
                twice, _ = dialects.render("sentinel", back)
                self.assertEqual(once, twice)
                self.assertEqual(
                    [type(n).__name__ for n in back.pipeline],
                    [type(n).__name__ for n in rule.pipeline],
                )

    def test_none_of_them_emits_text_its_parser_rejects(self):
        broken: list[str] = []
        targets = [e.key for e in dialects.ready_dialects() if e.can_render]
        for label, text in EDGES.items():
            rule, _ = dialects.lower("sentinel", text)
            for target in targets:
                if not dialects.get(target).can_parse:
                    continue
                try:
                    out, _ = dialects.render(target, rule)
                except Refusal:
                    continue
                try:
                    dialects.lower(target, out)
                except Refusal as exc:
                    broken.append(f"{label} -> {target}: {exc.code}")
        self.assertEqual(
            broken, [],
            "a renderer emitted a degenerate shape it cannot read back:\n  "
            + "\n  ".join(broken),
        )

    def test_a_number_never_renders_in_scientific_notation(self):
        # `str(Decimal("1e10"))` is `1E+10`. FQL reads the `+` as its AND
        # operator and refuses the rest of the filter; YAML reads it back as a
        # STRING, turning a numeric comparison into a text one. The others
        # accept an exponent, but a detection rule carrying `1E+10` where it
        # means ten billion is one nobody reviewing it reads correctly.
        #
        # Swept over every dialect, because the same `str(value)` appeared in
        # six renderers -- so it was six defects, and fixing the one FQL
        # exposed would have left five.
        leaked: list[str] = []
        for label in ("scientific", "tiny decimal", "huge int"):
            rule, _ = dialects.lower("sentinel", EDGES[label])
            for entry in dialects.ready_dialects():
                if not entry.can_render:
                    continue
                try:
                    out, _ = dialects.render(entry.key, rule)
                except Refusal:
                    continue
                if "E+" in out or "E-" in out:
                    leaked.append(f"{label} -> {entry.key}")
        self.assertEqual(
            leaked, [],
            "an exponent reached the output:\n  " + "\n  ".join(leaked),
        )

    def test_the_formatter_is_shared_rather_than_per_dialect(self):
        # Six copies of `str(value)` is how one defect became six.
        import pathlib
        import re

        from ruleforge import dialects as package

        root = pathlib.Path(package.__file__).resolve().parent
        offenders = []
        for path in sorted(root.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            if re.search(
                r"isinstance\(value, Decimal\):\s*\n\s*return str\(value\)",
                source,
            ):
                offenders.append(path.name)
        self.assertEqual(
            offenders, [],
            f"these format a Decimal themselves instead of using "
            f"`plain_number`: {offenders}",
        )

    def test_a_non_finite_number_is_refused(self):
        # No dialect here has a spelling for NaN or infinity, and a comparison
        # against one can never be true -- so writing it out produces a rule
        # that cannot fire.
        from ruleforge.dialects.common import plain_number

        for value in (Decimal("NaN"), Decimal("Infinity")):
            with self.subTest(value=str(value)):
                with self.assertRaises(Refusal) as caught:
                    plain_number(value)
                self.assertEqual(
                    caught.exception.code, "NUMBER_NOT_FINITE"
                )

    def test_two_constraints_on_one_field_become_two_selections(self):
        # A Sigma selection is a YAML mapping, so both in one is a duplicate
        # key -- invalid YAML that this module's own reader refuses.
        rule, _ = dialects.lower("sentinel", EDGES["same field twice"])
        out, _ = dialects.render("sigma", rule)
        self.assertIn("selection and selection_2", out)
        dialects.lower("sigma", out)

    def test_distinct_fields_still_share_one_selection(self):
        # The split must be narrow, or every ordinary rule grows a selection
        # per predicate and becomes unreadable.
        rule, _ = dialects.lower("sentinel", "T | where a == 1 and b == 2")
        out, _ = dialects.render("sigma", rule)
        self.assertIn("condition: selection\n", out)
        self.assertNotIn("selection_2", out)

    def test_an_empty_matcher_is_refused_rather_than_written(self):
        # In Wazuh an absence is a match, so an empty `<field>` fires on every
        # event the parent passed.
        rule, _ = dialects.lower("sentinel", EDGES["empty value"])
        with self.assertRaises(Refusal) as caught:
            dialects.render("wazuh", rule)
        self.assertEqual(
            caught.exception.code, "WAZUH_RENDER_EMPTY_VALUE"
        )


class AwkwardTextIsConvertedOrRefused(unittest.TestCase):
    """Non-ASCII and escape-heavy rules, swept the same way.

    A non-ASCII FIELD name rendered in five dialects and re-imported in none:
    the "safe to write bare" checks used `str.isalnum()`, which is
    unicode-aware, while every tokenizer here is ASCII-only. Synthesis from a
    localized log pinned such a field happily, so an analyst could generate a
    rule, save it, and have the tool refuse its own output.
    """

    def test_every_awkward_rule_lowers(self):
        for label, text in AWKWARD.items():
            with self.subTest(case=label):
                rule, _ = dialects.lower("sentinel", text)
                self.assertTrue(rule.pipeline)

    def test_awkward_text_round_trips_in_its_own_dialect(self):
        for label, text in AWKWARD.items():
            with self.subTest(case=label):
                rule, _ = dialects.lower("sentinel", text)
                once, _ = dialects.render("sentinel", rule)
                back, _ = dialects.lower("sentinel", once)
                twice, _ = dialects.render("sentinel", back)
                self.assertEqual(once, twice)

    def test_it_converts_or_refuses_but_never_emits_the_unreadable(self):
        broken: list[str] = []
        targets = [e.key for e in dialects.ready_dialects() if e.can_render]
        for label, text in AWKWARD.items():
            rule, _ = dialects.lower("sentinel", text)
            for target in targets:
                try:
                    out, _ = dialects.render(target, rule)
                except Refusal:
                    continue
                if not dialects.get(target).can_parse:
                    continue
                try:
                    dialects.lower(target, out)
                except Refusal as exc:
                    broken.append(f"{label} -> {target}: {exc.code}")
        self.assertEqual(
            broken, [],
            "a renderer emitted awkward text it cannot read back:\n  "
            + "\n  ".join(broken),
        )

    def test_a_non_ascii_field_name_is_never_written_bare(self):
        # The specific defect: every tokenizer here is ASCII-only, so a bare
        # non-ASCII identifier is unreadable by construction.
        from ruleforge.dialects.common import is_bare_identifier
        from ruleforge.ir import (
            Annotations, Comparison, Emit, FieldRef, Filter, Literal, Read,
        )

        name = "\u041f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044c"
        self.assertFalse(is_bare_identifier(name))
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table="t"),
                Filter(id="f", condition=Comparison(
                    "==", FieldRef(name), Literal("x"))),
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
        )
        for entry in dialects.ready_dialects():
            if not entry.can_render:
                continue
            with self.subTest(target=entry.key):
                try:
                    out, _ = dialects.render(entry.key, rule)
                except Refusal:
                    continue  # refusing is the honest outcome
                if entry.can_parse:
                    # If it rendered, it MUST be readable.
                    dialects.lower(entry.key, out)

    def test_the_ascii_check_is_shared_rather_than_per_dialect(self):
        # Each renderer deciding for itself is how the two definitions drifted
        # apart in the first place.
        from ruleforge.dialects.common import is_bare_identifier

        for name, expected in (
            ("abc", True), ("a_b", True), ("a.b", True),
            ("Event Name", False), ("1abc", False), ("a-b", False),
            ("", False),
            ("\u041f\u043e\u043b\u044c\u0437", False),
        ):
            with self.subTest(name=name):
                self.assertIs(is_bare_identifier(name), expected)


class RenderedOutputCanBeReadBack(unittest.TestCase):
    """Every renderer must emit text its own parser accepts.

    This is the property the suite was missing, and it is a sharper test than
    the containment sweep above. Each dialect was tested in ISOLATION --
    parse, render, compare, all within one dialect -- so cross-dialect output
    was never fed back in. `render_chronicle` emitted

        outcome:
          $count = count(1)

    for any count with no field, and `lower_chronicle` refuses `1` with
    "`1` is not a UDM field". The renderer produced a rule the renderer's own
    parser rejects, and nothing noticed, because nothing re-read the output.

    A renderer may REFUSE. What it may not do is emit text and be unable to
    read it.
    """

    def rendered(self):
        targets = [e.key for e in dialects.ready_dialects() if e.can_render]
        for source, cases in CORPUS.items():
            for label, text in cases.items():
                rule, _ = dialects.lower(source, text)
                for target in targets:
                    try:
                        out, _notes = dialects.render(target, rule)
                    except Refusal:
                        continue
                    yield source, label, target, out

    def test_every_rendered_rule_parses_in_its_own_dialect(self):
        broken: list[str] = []
        for source, label, target, out in self.rendered():
            entry = dialects.get(target)
            if not entry.can_parse:
                continue
            try:
                dialects.lower(target, out)
            except Refusal as exc:
                broken.append(
                    f"{source}/{label} -> {target}: emitted text that "
                    f"{target} cannot read back ({exc.code}: "
                    f"{exc.message[:90]})"
                )
        self.assertEqual(
            broken, [],
            "a renderer produced output its own parser rejects:\n  "
            + "\n  ".join(broken),
        )

    def test_the_stage_shape_survives_the_round_trip(self):
        # Re-reading must not quietly produce a SMALLER rule. A renderer that
        # drops a stage and a parser that cannot see the loss combine into a
        # conversion that looks successful and is not.
        shrunk: list[str] = []
        for source, label, target, out in self.rendered():
            entry = dialects.get(target)
            if not entry.can_parse:
                continue
            try:
                back, _ = dialects.lower(target, out)
            except Refusal:
                continue
            before = len([
                n for n in dialects.lower(source, CORPUS[source][label])[0]
                .pipeline
                if type(n).__name__ in ("Filter", "Aggregate", "Correlation",
                                        "Sequence", "Join")
            ])
            after = len([
                n for n in back.pipeline
                if type(n).__name__ in ("Filter", "Aggregate", "Correlation",
                                        "Sequence", "Join")
            ])
            if after < before:
                shrunk.append(
                    f"{source}/{label} -> {target}: {before} matching "
                    f"stage(s) in, {after} back out"
                )
        self.assertEqual(
            shrunk, [],
            "a conversion lost a matching stage on the way back:\n  "
            + "\n  ".join(shrunk),
        )

    def test_the_sweep_is_actually_doing_work(self):
        self.assertGreater(len(list(self.rendered())), 60)


class NoConversionLosesAPredicateSilently(unittest.TestCase):
    """The general property, swept over every dialect pair."""

    def pairs(self):
        targets = [e.key for e in dialects.ready_dialects() if e.can_render]
        for source, cases in CORPUS.items():
            for label, text in cases.items():
                rule, _ = dialects.lower(source, text)
                for target in targets:
                    if target != source:
                        yield source, label, text, target, rule

    def test_the_corpus_covers_every_ready_dialect(self):
        # A sweep that skips a dialect is a sweep that cannot find its bugs.
        ready = {e.key for e in dialects.ready_dialects()}
        self.assertEqual(sorted(ready - set(CORPUS)), [])

    def test_the_corpus_itself_lowers(self):
        for source, cases in CORPUS.items():
            for label, text in cases.items():
                with self.subTest(dialect=source, case=label):
                    rule, _ = dialects.lower(source, text)
                    self.assertTrue(rule.pipeline)

    def test_every_source_rule_actually_has_predicates_to_lose(self):
        # Without this the sweep below passes by having nothing to check.
        for source, cases in CORPUS.items():
            for label, text in cases.items():
                with self.subTest(dialect=source, case=label):
                    rule, _ = dialects.lower(source, text)
                    fields, values = rule_leaves(rule)
                    self.assertTrue(
                        fields or values,
                        "this corpus entry carries no predicate content",
                    )

    def test_nothing_is_dropped_without_a_diagnostic(self):
        losses: list[str] = []
        for source, label, _text, target, rule in self.pairs():
            want_fields, want_values = rule_leaves(rule)
            try:
                out, notes = dialects.render(target, rule)
            except Refusal:
                # An explicit refusal is the honest outcome, not a loss.
                continue
            flat = normalise(out)
            lost = [
                f for f in want_fields if f and normalise(f) not in flat
            ] + [
                v for v in want_values if v and normalise(v) not in flat
            ]
            if lost and not notes:
                losses.append(
                    f"{source}/{label} -> {target}: {sorted(lost)} gone from "
                    f"{len(out)} chars with 0 diagnostics"
                )
        self.assertEqual(
            losses, [],
            "a conversion dropped predicate content and said nothing:\n  "
            + "\n  ".join(losses),
        )

    def test_a_refusal_always_carries_a_code_and_a_reason(self):
        # "Cannot render" with no reason sends the analyst to the source.
        for source, label, _text, target, rule in self.pairs():
            try:
                dialects.render(target, rule)
            except Refusal as exc:
                with self.subTest(pair=f"{source}/{label}->{target}"):
                    self.assertTrue(exc.code.strip())
                    self.assertGreater(len(exc.message.strip()), 40)

    def test_the_sweep_is_actually_doing_work(self):
        # A guard on the guard: if `pairs()` silently yielded nothing, every
        # test above would pass.
        self.assertGreater(len(list(self.pairs())), 100)


class EveryRendererWalksItsWholePipeline(unittest.TestCase):
    """The structural version of the same property.

    `render_wazuh` did not iterate at all -- it cherry-picked two stages by
    type. So a stage could be dropped with no code path capable of refusing
    it. Each renderer is handed a rule carrying one extra stage and must
    either place it or refuse by name.
    """

    STAGES = (
        "second-filter", "Aggregate", "Sort", "Limit", "Distinct",
        "Project", "Expand", "Derive",
    )

    def build(self, kind: str) -> Rule:
        from ruleforge.ir import (
            Aggregate, Annotations, Derive, Distinct, Emit, Expand, Filter,
            Limit, Measure, Project, Read, Sort,
        )

        marker = "ZZmarkerZZ"
        extra = {
            "second-filter": Filter(id="f2", condition=Comparison(
                "==", FieldRef(marker), Literal("x"))),
            "Aggregate": Aggregate(
                id="a", measures=(Measure(function="count", name=marker),),
                keys=(FieldRef("A"),)),
            "Sort": Sort(id="so", keys=((FieldRef(marker), True),)),
            "Limit": Limit(id="l", count=4242),
            "Distinct": Distinct(id="d", keys=(FieldRef(marker),)),
            "Project": Project(id="p", keeps=(FieldRef(marker),)),
            "Expand": Expand(id="e", field=FieldRef("A"), into=marker),
            "Derive": Derive(
                id="dv", assignments=((marker, Literal(Decimal(1))),)),
        }[kind]
        return Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table="t", time_field="ts"),
                Filter(id="f1", condition=Comparison(
                    "==", FieldRef("A"), Literal("1"))),
                extra,
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
        )

    def test_a_stage_is_either_placed_or_refused(self):
        # `Limit` carries no field, so it is checked by its COUNT rather than
        # by the marker -- otherwise every dialect that correctly writes
        # `| take 77` reports as having dropped it, and five false alarms
        # bury the one real finding.
        unreported: list[str] = []
        targets = [e.key for e in dialects.ready_dialects() if e.can_render]
        for kind in self.STAGES:
            rule = self.build(kind)
            needle = "4242" if kind == "Limit" else "ZZmarkerZZ"
            for target in targets:
                try:
                    out, notes = dialects.render(target, rule)
                except Refusal:
                    continue
                if needle not in out and not notes:
                    unreported.append(f"{target} dropped {kind} silently")
        self.assertEqual(
            unreported, [],
            "a renderer ignored a stage it cannot express:\n  "
            + "\n  ".join(unreported),
        )


if __name__ == "__main__":
    unittest.main()
