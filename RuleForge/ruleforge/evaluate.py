"""Expression evaluation, with row scoping.

Two things distinguish this from a filter evaluator.

SCOPING
-------
A `left.` or `right.` reference is resolved against a DIFFERENT ROW than the one
being filtered. That is what makes a temporal correlation evaluable at all:

    right.LoginTime >= left.LSASSTime + 10m

Without scoping both sides resolve against the same row, the comparison becomes
`LoginTime >= LoginTime + 10m`, and the answer is always false -- a rule that
silently never fires. The scope is threaded through as an explicit `Scope` object
rather than inferred, so a reference outside a join is an error rather than a
quiet read of the current row.

EVALUATED VS DECLARED_ONLY
--------------------------
Evaluating a call that needs vendor-side state (`QIDNAME`, `tstats`) would mean
inventing an answer. Instead the node reports UNDECIDED with the reason, and the
caller surfaces it as "this part is not locally evaluable" rather than as a
non-match. The difference matters enormously: one is "your rule did not match",
the other is "this tool cannot tell you".
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field as dc_field
from decimal import Decimal, InvalidOperation, DivisionByZero
from typing import Any, Final

from .ir import (
    Arith,
    BoolOp,
    Call,
    Comparison,
    Expr,
    FieldRef,
    ListExpr,
    Literal,
    Not,
    Regex,
    Span,
    SubQuery,
    function_capability,
)
from .values import (
    ABSENT,
    UNDECIDED,
    Capability,
    ComparisonResult,
    Duration,
    Refusal,
    Seq,
    Undecided,
    and_,
    as_number,
    coalesce,
    compare,
    duration_seconds,
    is_absent,
    is_undecided,
    not_,
    or_,
    truthy,
    type_name,
)

__all__ = [
    "Row",
    "Scope",
    "Caveat",
    "Trace",
    "Budget",
    "Context",
    "EvaluationResult",
    "Verdict",
    "eval_expr",
    "compile_pattern",
    "REJECTED_DIALECTS",
]

#: Regex dialects that can be executed faithfully here.
#:
#: An ALLOWLIST. A blocklist of "portable constructs" was tried first and
#: classified nine patterns as portable that were not.
#:
#: PCRE is DECLARABLE but NOT executable. Every PCRE pattern is refused, including
#: ones made only of portable constructs, because this engine implements no PCRE
#: engine at all -- and evaluating with Python's `re` and calling the result
#: `pcre` would be a false claim about a security control.
#:
#: POSIX BRE is refused for a different reason: in BRE, `+ ? { | ( )` are
#: LITERALS, so a faithful translation needs re-escaping and a partial one
#: returns confidently wrong booleans.
REJECTED_DIALECTS: Final[dict[str, str]] = {
    "pcre": (
        "PCRE is modelled and rendered correctly but cannot be executed here. "
        "This engine implements no PCRE engine, and running the pattern with "
        "Python's re and calling the result PCRE would be a false claim about a "
        "security control. Every PCRE pattern is refused, including portable "
        "ones, so the refusal means one thing."
    ),
    "pcre2": (
        "PCRE2 is modelled and rendered correctly but cannot be executed here, "
        "for the same reason as PCRE: no PCRE engine is implemented."
    ),
    "posix_basic": (
        "POSIX BRE is refused because in BRE the characters + ? { | ( ) are "
        "LITERALS, not operators. A faithful translation has to re-escape them, "
        "and a partial translation returns confidently wrong booleans, which is "
        "worse than a refusal."
    ),
    "os_regex": (
        "Wazuh's OS-Regex is refused for the same reason as POSIX BRE, and the "
        "difference runs the other way: OS-Regex has NO grouping parentheses "
        "and NO bracket character classes, so `[a-z]+` and `(a|b)` are partly "
        "literal text there and are operators to every other engine. Running "
        "such a pattern with Python's re would match a different set of events "
        "than Wazuh matches, and report it as a success. Wazuh's `<match>` is a "
        "plain substring test and DOES evaluate here, which is what most Wazuh "
        "rules use."
    ),
    "java_regex": (
        "QRadar's MATCHES is Java regex, and it is refused for the same reason "
        "as PCRE: no Java regex engine is implemented here, and running the "
        "pattern with Python's re while reporting it as Java would be a false "
        "claim about a security control. Java and Python agree on the portable "
        "core but not past it -- possessive quantifiers (`a++`), "
        "`\\p{...}` blocks and Java's own lookbehind rules all parse "
        "differently -- and a refusal that applies to every Java pattern means "
        "one thing, where a refusal that applied to some would have to be read "
        "pattern by pattern. AQL's LIKE and ILIKE are SQL wildcard tests "
        "rather than regexes and DO evaluate here, which is what most AQL "
        "rules use."
    ),
}

#: Characters a portable pattern may contain literally. No backslash -- a
#: backslash is allowed only before a non-alphanumeric, so `\.` and `\+` pass and
#: `\d` and `\1` are refused.
_PORTABLE_LITERALS: Final[frozenset[str]] = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    " _-.,:;/@#%&"
    "()[]^$|*+?"
)

#: Constructs that are meaningful in one dialect and mean something else -- or
#: nothing -- in another. Refused by name so the message can say why.
_PORTABLE_REFUSALS: Final[dict[str, str]] = {
    "\\": "a backslash escape is dialect-specific: \\d and \\w are PCRE/ERE only, "
          "and \\1 is a backreference, which this engine does not implement",
    "{": "an interval quantifier {n,m} is ERE syntax; in POSIX BRE the braces "
         "are literals, so this pattern does not mean the same thing in both",
    "(?": "an extended group is PCRE/ERE syntax, not POSIX BRE, and this engine "
          "does not implement PCRE group extensions",
    "[[": "a POSIX named character class is not portable to this engine's subset",
}


# ---------------------------------------------------------------------------
# Rows and scopes
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Row:
    """One row, with its timestamp held separately from its values.

    Separating `time` from `values` keeps a timestamp column from colliding with
    the window logic: a rule that groups on the time field and a rule that
    windows on it are different rules, and only one of them means the time is a
    grouping key.
    """

    values: dict[str, Any] = dc_field(default_factory=dict)
    time: Any = None
    origin: str = ""

    def get(self, full: str) -> Any:
        """Read a field. The ONE way a row is read.

        A nested walk first, then a flat dotted key, because a payload can carry
        both shapes and the rule author meant whichever one exists.
        """
        if full in self.values:
            return self.values[full]
        current: Any = self.values
        for segment in full.split("."):
            if isinstance(current, dict) and segment in current:
                current = current[segment]
            else:
                return ABSENT
        return current

    def merged(self, other: "Row", left_prefix: str, right_prefix: str) -> "Row":
        """Combine two rows under distinct prefixes.

        Prefixing rather than overwriting is deliberate. A self-join -- the same
        stream matched against itself, which is how most lateral-movement rules
        are written -- would otherwise have the right side silently replace the
        left, and the rule would quietly mean something else.
        """
        merged = {f"{left_prefix}{k}": v for k, v in self.values.items()}
        merged.update({f"{right_prefix}{k}": v for k, v in other.values.items()})
        return Row(merged, self.time if self.time is not None else other.time)


@dataclass(slots=True)
class Scope:
    """Which row each scope name reads from.

    `current` is the row under evaluation. `left` and `right` are populated only
    inside a join predicate; outside one they are None and a reference to them is
    refused by name, because silently falling back to the current row is how a
    correlation rule turns into a rule that compares a field to itself.
    """

    current: Row | None = None
    left: Row | None = None
    right: Row | None = None

    def row_for(self, name: str) -> Row | None:
        if name == "current":
            return self.current
        if name == "left":
            return self.left
        if name == "right":
            return self.right
        return None


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Caveat:
    """Something the analyst should know that is not a refusal.

    `where` locates it (a stage id, a field, a node). `code` groups it. The
    message is written for the person who has to act on it.
    """

    code: str
    message: str
    severity: str = "caution"  # problem | caution | note
    where: str = ""
    capability: Capability | None = None


@dataclass(slots=True)
class Trace:
    """Per-stage row accounting, so a match count can be traced to a stage."""

    stage: str
    kind: str
    rows_in: int = 0
    rows_out: int = 0
    dropped: int = 0
    undecided: int = 0
    detail: str = ""


class Verdict:
    MATCHED = "matched"
    NO_MATCH = "no_match"
    NOT_EVALUATED = "not_evaluated"


@dataclass(slots=True)
class Budget:
    """A hard ceiling on evaluation work.

    A pasted rule plus a pasted sample can ask for a cartesian join of two large
    inputs. Without a ceiling that is a hang, and a hang on a rule an analyst is
    waiting on reads as a broken tool. The ceiling is spent by the operations that
    can actually blow up, and exceeding it is a named refusal rather than a stall.
    """

    limit: int = 4_000_000
    spent: int = 0

    def spend(self, amount: int = 1) -> None:
        self.spent += amount
        if self.spent > self.limit:
            raise Refusal(
                "BUDGET_EXCEEDED",
                f"this rule needed more than {self.limit:,} operations to evaluate "
                f"against these events. That usually means a join with no useful "
                f"key, or a very large sample. Narrow the sample or add a join "
                f"key.",
                "evaluate",
            )


@dataclass(slots=True)
class EvaluationResult:
    verdict: str = Verdict.NOT_EVALUATED
    rows: list[Row] = dc_field(default_factory=list)
    caveats: list[Caveat] = dc_field(default_factory=list)
    trace: list[Trace] = dc_field(default_factory=list)
    refusal: Refusal | None = None

    @property
    def matched(self) -> bool:
        return self.verdict == Verdict.MATCHED

    @property
    def undecided(self) -> int:
        return sum(t.undecided for t in self.trace)


# ---------------------------------------------------------------------------
# Regex
# ---------------------------------------------------------------------------

_REGEX_CACHE: dict[tuple[str, str, bool], re.Pattern[str]] = {}


def compile_pattern(dialect: str, pattern: str, nocase: bool = False) -> re.Pattern[str]:
    """Compile, or refuse with the reason.

    The ORDER is the design: portability screen, then catastrophic-backtracking
    screen, then compile. A pattern that would hang is refused before it is ever
    handed to the regex engine, because handing it over is what hangs.
    """
    if dialect in REJECTED_DIALECTS:
        raise Refusal("REGEX_NOT_EXECUTABLE", REJECTED_DIALECTS[dialect], "regex")

    _screen_portable(pattern)

    reason = _catastrophic_reason(pattern)
    if reason:
        raise Refusal(
            "REGEX_CATASTROPHIC_BACKTRACKING",
            f"this pattern backtracks catastrophically: {reason}. It would hang "
            f"the engine that runs it, which is usually the SIEM indexer rather "
            f"than the search.",
            "regex",
        )

    key = (dialect, pattern, nocase)
    cached = _REGEX_CACHE.get(key)
    if cached is not None:
        return cached

    flags = re.IGNORECASE if nocase else 0
    try:
        compiled = re.compile(pattern, flags)
    except RecursionError as exc:
        raise Refusal(
            "REGEX_NESTING_TOO_DEEP",
            "the pattern nests too deeply to compile. This is the pattern's "
            "shape, not a problem with your events.",
            "regex",
        ) from exc
    except re.error as exc:
        raise Refusal("REGEX_INVALID", f"the pattern does not compile: {exc}", "regex") from exc

    if len(_REGEX_CACHE) > 512:
        _REGEX_CACHE.clear()
    _REGEX_CACHE[key] = compiled
    return compiled


def _screen_portable(pattern: str) -> None:
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            if index + 1 >= len(pattern):
                raise Refusal(
                    "REGEX_INVALID", "the pattern ends with a dangling backslash",
                    "regex",
                )
            following = pattern[index + 1]
            if following.isalnum():
                raise Refusal(
                    "REGEX_DIALECT_SPECIFIC", _PORTABLE_REFUSALS["\\"], "regex"
                )
            index += 2
            continue
        if pattern.startswith("(?", index):
            raise Refusal("REGEX_DIALECT_SPECIFIC", _PORTABLE_REFUSALS["(?"], "regex")
        # `[` is a portable literal, so a POSIX named class would otherwise walk
        # straight through this screen and reach Python's `re`, which reads
        # `[[:alpha:]]` as the class {[, :, a, l, p, h} -- a pattern that
        # compiles, matches, and means something else than the author wrote.
        # That silent divergence is the whole reason this screen exists.
        if pattern.startswith("[[:", index):
            raise Refusal("REGEX_DIALECT_SPECIFIC", _PORTABLE_REFUSALS["[["], "regex")
        if char == "{":
            raise Refusal("REGEX_DIALECT_SPECIFIC", _PORTABLE_REFUSALS["{"], "regex")
        if char not in _PORTABLE_LITERALS:
            raise Refusal(
                "REGEX_DIALECT_SPECIFIC",
                f"`{char}` is not in the portable subset this engine executes, so "
                f"evaluating it would be a guess about what the vendor's engine "
                f"does with it.",
                "regex",
            )
        index += 1


# ---------------------------------------------------------------------------
# Catastrophic backtracking
#
# Two families, precisely:
#   1. prefix-overlapping alternatives inside a quantified group -- (a|aa)+$
#   2. adjacent unbounded quantifiers with nothing between them -- a*a*b$
# Both are exponential. (a|b)+c is not, and must not be refused.
# ---------------------------------------------------------------------------

_MAX_PATTERN = 4096
#: Two ADJACENT unbounded quantifiers is already enough to retry every split.
_MAX_ADJACENT_UNBOUNDED = 2
#: The TOTAL count is a separate, higher bar. A global count of 2 would refuse
#: every IPv4 address, timestamp, email and `.*\..*` pattern in existence, which
#: is how a ReDoS screen gets switched off. Four is past the point where the
#: polynomial degree stops being survivable: `a*a*a*a*$` is sixteen characters
#: and grows as n^4.
_MAX_TOTAL_UNBOUNDED = 3


def _first_set(pattern: str, start: int, stop: int | None = None) -> frozenset[str] | None:
    """Characters an atom can begin with, as an UPPER bound.

    None means "unknown", and unknown overlaps everything. The distinction
    matters: a LOWER bound used where an upper bound is needed proves the
    opposite of what is true, so every uncertain case returns None rather than a
    guess.
    """
    if start >= len(pattern) or (stop is not None and start >= stop):
        return frozenset()
    char = pattern[start]
    if char == "\\":
        if start + 1 >= len(pattern):
            return None
        kind = pattern[start + 1]
        if kind in "dDwWsS":
            return None  # a class: unknown, overlaps everything
        if kind in "bBAZzG":
            return frozenset()  # zero-width assertion
        if kind.isdigit():
            return None  # backreference
        return frozenset({kind})
    if char == "[":
        close = pattern.find("]", start + 1)
        if close == -1:
            return None
        if pattern.startswith("^", start + 1):
            return None  # a negated class overlaps nearly everything
        body = pattern[start + 1:close]
        if body.startswith("."):
            return None
        if "-" in body:
            out: set[str] = set()
            for part in body.split("-"):
                out.add(part)
            return frozenset(out)
        return frozenset(body)
    if char == ".":
        return None
    if char == "(":
        if pattern.startswith("(?", start):
            return None
        depth = 0
        for index in range(start, len(pattern)):
            if pattern[index] == "\\":
                continue
            if pattern[index] == "(":
                depth += 1
            elif pattern[index] == ")":
                depth -= 1
                if depth == 0:
                    return _first_set(pattern, start + 1, index)
        return None
    if char in "*+?|)":
        return frozenset()
    return frozenset({char})


def _alternatives_overlap(pattern: str, start: int, end: int) -> bool:
    body = pattern[start:end]
    parts = _split_alternatives(body)
    if len(parts) < 2:
        return False
    heads = [_first_set(p, 0) for p in parts]
    known = [h for h in heads if h is not None]
    if len(known) != len(heads):
        return True  # an unknown head overlaps anything
    for i, left in enumerate(known):
        for right in known[i + 1:]:
            if left & right:
                return True
    return False


def _split_alternatives(body: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body):
            current.append(body[index:index + 2])
            index += 2
            continue
        if char == "[":
            close = body.find("]", index + 1)
            if close == -1:
                current.append(char)
                index += 1
                continue
            current.append(body[index:close + 1])
            index = close + 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            parts.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    parts.append("".join(current))
    return parts


def _quantified_groups(pattern: str) -> list[tuple[int, int]]:
    """(start, end) of every quantified group body."""
    out: list[tuple[int, int]] = []
    for index, char in enumerate(pattern):
        if char == "\\":
            continue
        if char != "(":
            continue
        if index + 1 < len(pattern) and pattern[index + 1] == "?":
            continue
        depth = 0
        for close in range(index, len(pattern)):
            if pattern[close] == "\\":
                continue
            if pattern[close] == "(":
                depth += 1
            elif pattern[close] == ")":
                depth -= 1
                if depth == 0:
                    after = close + 1
                    if after < len(pattern) and pattern[after] in "*+":
                        out.append((index + 1, close))
                    break
    return out


def _nested_unbounded(pattern: str) -> bool:
    """A quantified group whose own body is unbounded: `(a+)+`, `([a-z]*)*`.

    This is the genuinely exponential family and it is the one that does not
    need parentheses to be written -- `(a+)+` is what a ReDoS payload looks like
    in the wild, and an earlier detector that only looked INSIDE groups missed
    `a*a*a*a*a*a*a*$`, which is twelve characters with no grouping at all.
    """
    for start, end in _quantified_groups(pattern):
        body = pattern[start:end]
        depth = 0
        for index, char in enumerate(body):
            if char == "\\":
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char in "*+" and depth == 0:
                if index + 1 < len(body) and body[index + 1] in "?+":
                    continue
                return True
    return False


def _count_unbounded(pattern: str) -> int:
    """Total unbounded quantifiers, ignoring lazy/possessive markers."""
    total = 0
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char in "*+":
            if index + 1 < len(pattern) and pattern[index + 1] in "?+":
                index += 1
                continue
            total += 1
        index += 1
    return total


def _adjacent_quantifiers(pattern: str) -> int:
    """Longest run of unbounded quantifiers with nothing between them.

    ADJACENCY, not a global count. `a*a*b$` is exponential and `a.*b.*c$` is not,
    and a global count cannot tell them apart -- an earlier version counted every
    `*` and `+` in the pattern, which refused every IPv4 address, timestamp and
    email regex in existence. The property that matters is that two quantifiers
    can match the same text at the same position, which requires them to be
    neighbours.
    """
    run = 0
    longest = 0
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            run = 0
            continue
        if char in "*+":
            # A lazy or possessive marker is not a second quantifier.
            if index + 1 < len(pattern) and pattern[index + 1] in "?+":
                index += 1
                continue
            run += 1
            longest = max(longest, run)
            index += 1
            continue
        if char in ")|":
            # a group boundary: still adjacent
            index += 1
            continue
        # Anything that can consume input, or assert, breaks the run.
        run = 0
        index += 1
    return longest


def _catastrophic_reason(pattern: str) -> str:
    """Why this pattern is exponential, or '' if it is not.

    An unbounded analysis is itself a denial-of-service vector wearing the
    costume of a security control, so the walk is bounded and analysis that runs
    out of budget returns the REFUSING answer rather than the safe one -- the
    opposite choice to the one that is comfortable, and the right one, because
    the consequence of guessing "safe" here is hanging an indexer.
    """
    if len(pattern) > _MAX_PATTERN:
        return f"the pattern is {len(pattern)} characters long"

    adjacent = _adjacent_quantifiers(pattern)
    if adjacent > _MAX_ADJACENT_UNBOUNDED:
        return (
            f"it has {adjacent} unbounded quantifiers in a row with nothing "
            f"between them, so the engine retries every way of splitting the "
            f"text between them"
        )

    if _nested_unbounded(pattern):
        return (
            "a repeated group contains an unbounded quantifier of its own, so "
            "the same text can be split between the two in exponentially many "
            "ways"
        )

    total = _count_unbounded(pattern)
    if total > _MAX_TOTAL_UNBOUNDED:
        return (
            f"it has {total} unbounded quantifiers, so the work grows as the "
            f"product of all of them rather than their sum. Twelve characters "
            f"like `a*a*a*a*a*a*$` are enough to hang an indexer"
        )

    seen: set[tuple[int, int]] = set()
    for start, end in _quantified_groups(pattern):
        if end - start > 200 or (start, end) in seen:
            continue
        seen.add((start, end))
        body = pattern[start:end]
        if _alternatives_overlap(pattern, start, end):
            parts = _split_alternatives(body)
            if len(parts) > 1:
                return (
                    f"`({'|'.join(p.strip() for p in parts)})` inside a repeated "
                    f"group has alternatives that can match the same text, so each "
                    f"additional character multiplies the work"
                )
    return ""


# ---------------------------------------------------------------------------
# Expression evaluation
# ---------------------------------------------------------------------------


def eval_expr(
    expr: Expr,
    scope: Scope,
    ctx: "Context | None" = None,
) -> Any:
    """Evaluate an expression to a value.

    Returns a value, UNDECIDED, or ABSENT. Never raises for a data problem --
    only for a structural one, which is a programming error and should be loud.
    """
    context = ctx or Context()

    if isinstance(expr, Literal):
        return expr.value

    if isinstance(expr, FieldRef):
        row = scope.row_for(expr.scope)
        if row is None:
            raise Refusal(
                "SCOPE_NOT_AVAILABLE",
                f"`{expr.scoped}` reads the {expr.scope} row, but no {expr.scope} "
                f"row exists here. A left/right reference is only meaningful "
                f"inside a join predicate; outside one it would silently read the "
                f"current row and compare a field with itself.",
                "eval",
            )
        return row.get(expr.full)

    if isinstance(expr, Not):
        inner = eval_expr(expr.operand, scope, context)
        if inner is UNDECIDED:
            return UNDECIDED
        if not isinstance(inner, bool):
            context.uncertain(
                "NOT_ON_NON_BOOLEAN",
                f"NOT was applied to a {type_name(inner)}, which is not a "
                f"condition. It is left undecided rather than guessed at.",
                where=render_where(expr.operand),
            )
            return UNDECIDED
        return not inner

    if isinstance(expr, BoolOp):
        return _eval_boolop(expr, scope, context)

    if isinstance(expr, Comparison):
        return _eval_comparison(expr, scope, context)

    if isinstance(expr, Span):
        return _eval_span(expr, scope, context)

    if isinstance(expr, Arith):
        return _eval_arith(expr, scope, context)

    if isinstance(expr, ListExpr):
        return Seq(tuple(eval_expr(item, scope, context) for item in expr.items))

    if isinstance(expr, Span):
        return _eval_span(expr, scope, context)

    if isinstance(expr, Arith):
        return _eval_arith(expr, scope, context)

    # A pattern is a VALUE, like a Duration. It evaluates to itself so the
    # comparison above can dispatch on it; it is never matched against anything
    # on its own, because a pattern with no subject is not a condition.
    if isinstance(expr, Regex):
        return expr

    if isinstance(expr, Call):
        return _eval_call(expr, scope, context)

    if isinstance(expr, SubQuery):
        raise Refusal(
            "SUBQUERY_NOT_IN_EXPRESSION",
            "a sub-pipeline is a stage source, not a value. It belongs on a join's "
            "side, not inside a condition.",
            "eval",
        )

    raise Refusal(
        "EXPRESSION_UNSUPPORTED",
        f"this engine cannot evaluate a {type(expr).__name__}",
        "eval",
    )


def render_where(expr: Expr) -> str:
    from .ir import render_expr
    return render_expr(expr)


def _eval_boolop(expr: BoolOp, scope: Scope, context: "Context") -> Any:
    """AND / OR, three-valuedly.

    Every operand is evaluated even after one decides the answer, because a
    sibling that cannot be decided is information the analyst needs. Short
    circuiting here would hide exactly the caveat that matters.
    """
    results: list[bool | Undecided] = []
    for operand in expr.operands:
        value = eval_expr(operand, scope, context)
        if not isinstance(value, bool) and value is not UNDECIDED:
            context.uncertain(
                "NON_BOOLEAN_OPERAND",
                f"a {type_name(value)} was used where a condition was expected, "
                f"in `{render_where(expr)}`. A value is not a condition: "
                f"`field = 1` is a comparison, `field` on its own would be "
                f"truthy for any non-empty string and match almost everything.",
                where=render_where(operand),
            )
            results.append(UNDECIDED)
            continue
        results.append(value)

    combined = and_(*results) if expr.op == "and" else or_(*results)
    return combined


def _eval_comparison(expr: Comparison, scope: Scope, context: "Context") -> Any:
    left = eval_expr(expr.left, scope, context)
    right = eval_expr(expr.right, scope, context)
    if left is UNDECIDED or right is UNDECIDED:
        return UNDECIDED

    # A pattern operator with a Regex on either side. Handled BEFORE the ABSENT
    # guard, because a Regex is a node rather than a value and asking whether it
    # is absent is the wrong question.
    if expr.op in ("matches", "=~", "!~", "like", "ilike"):
        pattern = right if isinstance(right, Regex) else (
            left if isinstance(left, Regex) else None
        )
        if pattern is not None:
            subject = left if isinstance(right, Regex) else right
            hit = _eval_regex_operand(subject, pattern, expr.op, context)
            if hit is UNDECIDED:
                # Name the field. A pattern test over an absent or non-text
                # value returned a bare UNDECIDED, so the analyst got
                # "could not decide 1 of 1 rows" and no way to find out which
                # field was missing. The text predicates have named it since
                # `_undecidable_text_predicate` was added; a pattern test is
                # the same question asked a different way, and most of them
                # arrive here because a dialect folded a case-insensitive
                # `endswith` into a regex.
                if not isinstance(subject, str):
                    _undecidable_text_predicate(expr, left, right, context)
                return UNDECIDED
            # TWO negations can apply here and both are DATA on the node. `!~`
            # negates by its own definition, and `negate` negates again on top
            # of it. Applying only the operator's half is how `NOT (cmd =~
            # /lsass/)` evaluated to `cmd =~ /lsass/` and matched exactly the
            # events the author excluded. ir.Comparison.describe() warns about
            # this failure mode for RENDERING; it is the same failure here.
            matched = (not hit) if expr.op == "!~" else hit
            return (not matched) if expr.negate else matched

    # LIKE / ILIKE against a plain string, which is the normal shape.
    #
    # A LIKE pattern is a GLOB, not a regex, so the dialects correctly lower
    # `username LIKE '%adm%'` with a `Literal` on the right rather than a
    # `Regex`. Only the Regex branch above handled these two operators, so a
    # literal pattern fell through to the generic equality path below and
    # asked whether the subject equalled the seven characters `%adm%`. That is
    # False for every row, so the rule reported a confident no_match and never
    # fired -- in AQL, SPL and KQL alike.
    #
    # `_glob_match` is the same implementation the Regex branch reaches, so
    # the two spellings cannot drift apart.
    if expr.op in ("like", "ilike"):
        if isinstance(left, str) and isinstance(right, str):
            matched = _glob_match(left, right, nocase=expr.op == "ilike")
            return (not matched) if expr.negate else matched
        # An absent or non-text operand is UNDECIDED, not False, for the same
        # reason `contains` is: a missing field has no answer to this question.
        return _undecidable_text_predicate(expr, left, right, context)

    if isinstance(left, (Seq, list)) or isinstance(right, (Seq, list)):
        return _eval_sequence_comparison(expr, left, right, context)

    # String predicates, not orderings. `compare` deliberately refuses them --
    # "is this string before that one" and "does this string end with that" are
    # different questions, and folding them together is how a rule ends up
    # needing a comparison the engine cannot make.
    if expr.op in ("contains", "startswith", "endswith"):
        subject, needle = left, right
        if isinstance(subject, str) and isinstance(needle, str):
            if expr.op == "contains":
                matched = needle in subject
            elif expr.op == "startswith":
                matched = subject.startswith(needle)
            else:
                matched = subject.endswith(needle)
            # `negate` is data on the node, so it has to be applied here too.
            # Omitting it inverted the detection: `NOT (cmd contains "lsass")`
            # evaluated as `cmd contains "lsass"`.
            return (not matched) if expr.negate else matched
        return _undecidable_text_predicate(expr, left, right, context)

    if left is ABSENT or right is ABSENT:
        missing = expr.left if left is ABSENT else expr.right
        context.uncertain(
            "COMPARISON_UNDECIDABLE",
            f"`{render_where(expr)}` could not be decided because "
            f"`{render_where(missing)}` is absent from the row. An absent field "
            f"is not an empty one and is not zero, so this is not False -- a rule "
            f"that decided it either way would match a different set of events "
            f"than the one written.",
            where=render_where(expr),
        )
        return UNDECIDED

    if left is None or right is None:
        context.uncertain(
            "COMPARISON_UNDECIDABLE",
            f"`{render_where(expr)}` could not be decided because a value is "
            f"null. Null is a third thing, distinct from absent and from empty.",
            where=render_where(expr),
        )
        return UNDECIDED

    result = compare(left, expr.op, right)
    if result.value is UNDECIDED:
        context.uncertain(
            "COMPARISON_UNDECIDABLE",
            f"`{render_where(expr)}` could not be decided: {result.reason}.",
            where=render_where(expr),
        )
        return UNDECIDED
    return (not result.value) if expr.negate else result.value


def _undecidable_text_predicate(
    expr: Comparison, left: Any, right: Any, context: "Context"
) -> Any:
    """Say WHICH operand made a text predicate undecidable, and why.

    `contains`, `startswith` and `endswith` return before reaching the ABSENT
    guard below, so without this they produced a bare UNDECIDED carrying no
    caveat at all. The analyst then saw only the filter's summary -- "could not
    decide 1 of 1 rows" -- with no field named, which is precisely the question
    this engine exists to answer. And those three operators are among the most
    common in real vendor rules, so the gap covered the usual case rather than
    an exotic one.
    """
    if left is ABSENT or right is ABSENT:
        missing = expr.left if left is ABSENT else expr.right
        reason = (
            f"`{render_where(missing)}` is absent from the row. An absent field "
            f"is not an empty one, so this is not False -- a rule that decided "
            f"it either way would match a different set of events than the one "
            f"written."
        )
    elif left is None or right is None:
        nulled = expr.left if left is None else expr.right
        reason = (
            f"`{render_where(nulled)}` is null. Null is a third thing, distinct "
            f"from absent and from empty."
        )
    else:
        value, side = (
            (left, expr.left) if not isinstance(left, str)
            else (right, expr.right)
        )
        reason = (
            f"`{render_where(side)}` is a {type_name(value)}, not text, and "
            f"`{expr.op}` is a text predicate. Coercing it would be a guess "
            f"about what the vendor's engine does with the same rule."
        )
    context.uncertain(
        "COMPARISON_UNDECIDABLE",
        f"`{render_where(expr)}` could not be decided because {reason}",
        where=render_where(expr),
    )
    return UNDECIDED


def _eval_sequence_comparison(
    expr: Comparison, left: Any, right: Any, context: "Context"
) -> Any:
    """IN / NOT IN / has_any / contains_any / contains_all, over a list.

    The two operands mean DIFFERENT things per operator, and getting it backwards
    is silent: `contains_all(cmd, [lsass, dump])` has the string on the left and
    the list on the right, while `x in [a, b]` has the list on the right too --
    but `contains_any(list, string)` would not. So the roles are decided by the
    operator, not by which side happens to hold the Seq.
    """
    # HAYSTACK-FIRST: the subject is a scalar, the options are the collection.
    haystack_ops = ("contains", "contains_any", "contains_all",
                    "starts_with", "ends_with", "has_any", "has_all")
    if expr.op in haystack_ops:
        subject, options = left, right
    else:
        subject, options = right, left

    subjects = list(subject) if isinstance(subject, (Seq, list)) else [subject]
    choices = list(options) if isinstance(options, (Seq, list)) else [options]

    if any(item is UNDECIDED for item in choices) or any(
        s is UNDECIDED for s in subjects
    ):
        return UNDECIDED

    def _hit(s: Any, c: Any) -> bool | Undecided:
        # Equality for membership (`x in [...]`), SUBSTRING semantics for the
        # string family. Using `==` for `contains_all` is the bug where
        # "contains both lsass and dump" silently becomes "equals both", which
        # is never true and reads as a rule that matches nothing.
        if expr.op in ("in", "==", "!="):
            return compare(s, "==", c).value
        if not isinstance(s, str) or not isinstance(c, str):
            return UNDECIDED
        if expr.op in ("contains", "contains_any", "has_any",
                       "contains_all", "has_all"):
            return c in s
        if expr.op == "starts_with":
            return s.startswith(c)
        if expr.op == "ends_with":
            return s.endswith(c)
        return UNDECIDED

    if expr.op in ("in", "=="):
        results = [_hit(s, c) for s in subjects for c in choices]
        if any(r is UNDECIDED for r in results):
            return UNDECIDED
        hit = any(r is True for r in results)

    elif expr.op in ("!=", "contains_any", "has_any"):
        results = [_hit(s, c) for s in subjects for c in choices]
        if any(r is UNDECIDED for r in results):
            return UNDECIDED
        # `contains_any` and `has_any` are POSITIVE. Only `!=` inverts.
        hit = any(r is True for r in results)
        if expr.op == "!=":
            hit = not hit

    elif expr.op in ("contains_all", "has_all"):
        per_subject: list[bool | Undecided] = []
        for s in subjects:
            results = [_hit(s, c) for c in choices]
            if any(r is UNDECIDED for r in results):
                return UNDECIDED
            per_subject.append(all(r is True for r in results))
        hit = all(r is True for r in per_subject)

    else:
        return UNDECIDED

    return (not hit) if expr.negate else hit


def _eval_span(expr: Span, scope: Scope, context: "Context") -> Any:
    """`x between (low .. high)`, with arbitrary bounds on either side.

    This is the KQL `where LoginTime between (LSASSTime .. LSASSTime + 10m)`
    shape, and it is why `Span` exists: the bounds are expressions that may read
    the other side of a join, so it is neither a comparison nor a list.
    """
    value = eval_expr(expr.value, scope, context)
    low = eval_expr(expr.low, scope, context)
    high = eval_expr(expr.high, scope, context)
    if value is UNDECIDED or low is UNDECIDED or high is UNDECIDED:
        return UNDECIDED
    if value is ABSENT or low is ABSENT or high is ABSENT:
        context.uncertain(
            "SPAN_UNDECIDABLE",
            f"`{render_where(expr)}` could not be decided because a bound or the "
            f"value is absent from the row.",
            where=render_where(expr),
        )
        return UNDECIDED

    number, low_n, high_n = as_number(value), as_number(low), as_number(high)
    if number is None or low_n is None or high_n is None:
        return UNDECIDED

    if expr.low_inclusive:
        if number < low_n:
            return False
    elif number <= low_n:
        return False
    if expr.high_inclusive:
        if number > high_n:
            return False
    elif number >= high_n:
        return False
    return True


def _eval_arith(expr: Arith, scope: Scope, context: "Context") -> Any:
    left = eval_expr(expr.left, scope, context)
    right = eval_expr(expr.right, scope, context)
    if left is UNDECIDED or right is UNDECIDED:
        return UNDECIDED
    if left is ABSENT or right is ABSENT:
        context.uncertain(
            "ARITH_UNDECIDABLE",
            f"`{render_where(expr)}` could not be computed because a field it "
            f"reads is absent from the row. It is left undecided rather than "
            f"treated as zero, because treating it as zero would quietly widen "
            f"the rule.",
            where=render_where(expr),
        )
        return UNDECIDED

    a, b = as_number(left), as_number(right)
    if a is None or b is None:
        context.uncertain(
            "ARITH_NOT_NUMERIC",
            f"`{render_where(expr)}` needs numbers and got a {type_name(left)} "
            f"and a {type_name(right)}",
            where=render_where(expr),
        )
        return UNDECIDED

    try:
        if expr.op == "+":
            return a + b
        if expr.op == "-":
            return a - b
        if expr.op == "*":
            return a * b
        if b == 0:
            context.uncertain(
                "ARITH_DIVIDE_BY_ZERO",
                f"`{render_where(expr)}` divides by zero, which has no value",
                where=render_where(expr),
            )
            return UNDECIDED
        return a / b
    except (DivisionByZero, InvalidOperation):
        return UNDECIDED


def _eval_regex_operand(
    subject: Any, pattern: Regex, op: str, context: "Context"
) -> Any:
    """Match a value against a pattern under a pattern operator.

    Reached from `_eval_comparison`, not from `eval_expr`: a bare `Regex` has no
    subject, so it is meaningless on its own and belongs on the right of
    `=~` / `matches` / `like` / `ilike`.
    """
    if not isinstance(subject, str):
        return UNDECIDED

    nocase = pattern.nocase or op == "ilike"
    dialect = pattern.dialect

    # Case-insensitivity is applied to the SUBJECT, never by rewriting the
    # pattern. Rewriting needs vendor-specific knowledge of case rules that
    # differ per dialect; folding the subject is exact for ASCII and the caveat
    # trail records that a fold happened.
    if op in ("like", "ilike"):
        return _glob_match(subject, pattern.pattern, nocase)

    if nocase and dialect in REJECTED_DIALECTS:
        context.refusal(
            Refusal("REGEX_NOT_EXECUTABLE", REJECTED_DIALECTS[dialect], "regex")
        )
        return UNDECIDED

    try:
        compiled = compile_pattern(dialect, pattern.pattern, nocase=False)
    except Refusal as exc:
        context.refusal(exc)
        return UNDECIDED

    text = subject.casefold() if nocase else subject
    return compiled.search(text) is not None


def _glob_match(subject: str, pattern: str, nocase: bool) -> bool:
    """LIKE / ILIKE with `%` (any run) and `_` (one char), fully anchored.

    Anchored on purpose. `ILIKE '%lsass%'` writes its own wildcards, so an
    unanchored implementation would be right for that pattern and WRONG for
    `'lsass%'` -- which under the vendor's own semantics must not match
    `not-lsass-helper.exe`. The wildcards in the pattern are the only source of
    looseness.

    A backslash escapes the next character, so `100\\%` tests for a literal
    percent sign. Without that, an escaped wildcard was passed through as a
    backslash FOLLOWED by a live wildcard: `100\\%` became "100, a backslash,
    then anything", which matches neither `100%` nor anything else a rule
    would see. Both `qradar.py` and `crowdstrike.py` escape literal wildcards
    on the way in, so every one of those patterns silently matched nothing.
    """
    if nocase:
        subject = subject.casefold()
        pattern = pattern.casefold()
    parts: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            parts.append(re.escape(pattern[index + 1]))
            index += 2
            continue
        if char == "%":
            parts.append(".*")
        elif char == "_":
            parts.append(".")
        else:
            parts.append(re.escape(char))
        index += 1
    return re.fullmatch("".join(parts), subject, re.DOTALL) is not None


#: The functions that DECIDE over an absent field rather than going undecided.
#:
#: `is_null` is NOT here, and that is the point of the list. Sigma's
#: `field: null` asks whether a field is present and null, so collapsing
#: absence into it would report a confident answer with no evidence -- which
#: `test_sigma.NullIsNotAbsent` pins down.
#:
#: `is_null_or_absent` and `is_present` exist for the vendors whose schema has
#: no notion of absence. In KQL every row has every column, so a missing value
#: IS null there; mapping `isnull()` onto the strict predicate made every
#: Sentinel rule that tests for a missing field report `not_evaluated` on
#: exactly the rows it was written to catch.
_ABSENCE_TESTS: Final[frozenset[str]] = frozenset({
    "is_null_or_absent", "is_present", "is_empty", "not_empty",
})


def _eval_call(expr: Call, scope: Scope, context: "Context") -> Any:
    name = expr.function.lower()
    capability = function_capability(expr.function)

    # An appliance function is modelled and rendered, never guessed at. Reporting
    # UNDECIDED with the reason is the difference between "your rule did not
    # match" and "this tool cannot tell you".
    if capability is Capability.DECLARED_ONLY:
        context.declared_only(
            expr.function,
            f"`{expr.function}()` is evaluated by the {expr.function} vendor's own "
            f"engine, not here. It is modelled and rendered correctly, but no "
            f"sample of events can stand in for it, so this part of the rule is "
            f"not locally testable.",
            where=render_where(expr),
        )
        return UNDECIDED

    args = [eval_expr(a, scope, context) for a in expr.args]
    if any(a is UNDECIDED for a in args):
        return UNDECIDED

    # coalesce handles absence by design, so it is checked before the ABSENT
    # guard that would otherwise reject its missing arguments.
    if name == "coalesce":
        result = ABSENT
        for value in args:
            if value is not ABSENT and value is not None:
                result = value
                break
        return result

    # The absence TESTS that a vendor defines over a missing field decide it,
    # rather than going undecided through the guard below.
    #
    # `is_null` is deliberately NOT one of them. Sigma's `field: null` asks
    # whether a field is PRESENT and null, and
    # `test_sigma.NullIsNotAbsent.test_an_absent_field_is_not_reported_as_null`
    # pins that: collapsing absent into null reports a confident answer the
    # engine has no evidence for. `is_null_or_absent` is the separate
    # predicate KQL needs, because KQL's schema is fixed -- every row has
    # every column, so a missing value there genuinely IS null and
    # `isnull(x)` returning UNDECIDED made the rule untestable on exactly the
    # rows it was written for.
    if name in _ABSENCE_TESTS:
        subject = args[0]
        missing = subject is ABSENT or subject is None
        if name in ("is_empty", "not_empty"):
            missing = missing or subject == ""
        return missing if name in (
            "is_null_or_absent", "is_empty"
        ) else not missing

    if any(a is ABSENT for a in args):
        return UNDECIDED

    handler = _FUNCTIONS.get(name)
    if handler is None:
        raise Refusal(
            "FUNCTION_UNKNOWN",
            f"`{expr.function}()` is not a function this engine knows. Either it "
            f"is a typo, or it is a vendor function that should be marked "
            f"declared-only so it renders without being executed.",
            "eval",
        )
    return handler(args, context, expr)


# ---------------------------------------------------------------------------
# Local functions -- all pure computation over their arguments
# ---------------------------------------------------------------------------


def _fn_cidr_contains(args: list[Any], ctx: "Context", node: Call) -> Any:
    address, network = args[0], args[1]
    if not isinstance(address, str) or not isinstance(network, str):
        return UNDECIDED
    try:
        parsed_address = ipaddress.ip_address(address)
        parsed_network = ipaddress.ip_network(network, strict=False)
    except ValueError:
        ctx.uncertain(
            "CIDR_UNPARSEABLE",
            f"`{address!r}` against `{network!r}` is not an address and a network, "
            f"so containment cannot be decided",
            where=render_where(node),
        )
        return UNDECIDED
    if parsed_address.version != parsed_network.version:
        ctx.uncertain(
            "CIDR_VERSION_MISMATCH",
            f"`{address}` is IPv{parsed_address.version} and `{network}` is "
            f"IPv{parsed_network.version}, so one cannot contain the other",
            where=render_where(node),
        )
        return UNDECIDED
    # Containment, never a string prefix test. `in` on strings is a prefix
    # comparison, and a prefix comparison matches hosts the rule was never
    # written for -- which for a network control is a confidently wrong answer.
    return parsed_address in parsed_network


def _fn_text(name: str):
    def handler(args: list[Any], ctx: "Context", node: Call) -> Any:
        subject = args[0]
        needle = args[1] if len(args) > 1 else ""
        if not isinstance(subject, str) or not isinstance(needle, str):
            return UNDECIDED
        if name == "starts_with":
            return subject.startswith(needle)
        if name == "ends_with":
            return subject.endswith(needle)
        return needle in subject

    return handler


def _fn_contains_any(args: list[Any], ctx: "Context", node: Call) -> Any:
    subject, needles = args[0], args[1]
    if not isinstance(subject, str):
        return UNDECIDED
    items = list(needles) if isinstance(needles, (Seq, list)) else [needles]
    return any(isinstance(n, str) and n in subject for n in items)


def _fn_contains_all(args: list[Any], ctx: "Context", node: Call) -> Any:
    subject, needles = args[0], args[1]
    if not isinstance(subject, str):
        return UNDECIDED
    items = list(needles) if isinstance(needles, (Seq, list)) else [needles]
    return all(isinstance(n, str) and n in subject for n in items)


def _fn_presence(name: str):
    def handler(args: list[Any], ctx: "Context", node: Call) -> Any:
        value = args[0]
        if name == "is_empty":
            return value is ABSENT or value is None or value == ""
        if name == "not_empty":
            return not (value is ABSENT or value is None or value == "")
        if name == "is_null":
            # The ONE deliberate exception to "absent means undecided": asking
            # whether something is null when it is not there at all is a
            # DECIDED no, and refusing it would make `isnull(field)` unusable.
            if value is ABSENT:
                return False
            return value is None
        if name == "is_not_null":
            if value is ABSENT:
                return False
            return value is not None
        return UNDECIDED

    return handler


def _fn_lower(args: list[Any], ctx: "Context", node: Call) -> Any:
    return args[0].lower() if isinstance(args[0], str) else UNDECIDED


def _fn_upper(args: list[Any], ctx: "Context", node: Call) -> Any:
    return args[0].upper() if isinstance(args[0], str) else UNDECIDED


def _fn_length(args: list[Any], ctx: "Context", node: Call) -> Any:
    value = args[0]
    if isinstance(value, (Seq, list)):
        return Decimal(len(value))
    if isinstance(value, str):
        return Decimal(len(value))
    return UNDECIDED


def _fn_to_int(args: list[Any], ctx: "Context", node: Call) -> Any:
    number = as_number(args[0])
    return number if number is not None else UNDECIDED


def _fn_to_string(args: list[Any], ctx: "Context", node: Call) -> Any:
    return str(args[0])


def _fn_math(name: str):
    def handler(args: list[Any], ctx: "Context", node: Call) -> Any:
        numbers = [as_number(a) for a in args]
        if any(n is None for n in numbers):
            return UNDECIDED
        values = [n for n in numbers if n is not None]
        if name == "abs":
            return abs(values[0])
        if name == "round":
            return values[0].quantize(Decimal(1))
        if name == "floor":
            return values[0].to_integral_value(rounding="ROUND_FLOOR")
        if name == "ceil":
            return values[0].to_integral_value(rounding="ROUND_CEILING")
        if name == "min":
            return min(values)
        if name == "max":
            return max(values)
        return UNDECIDED

    return handler


def _fn_matches_regex(args: list[Any], ctx: "Context", node: Call) -> Any:
    subject, pattern = args[0], args[1]
    if not isinstance(subject, str):
        return UNDECIDED

    # A STRING pattern is accepted as well as a `Regex` node.
    #
    # `re.regex($e.f, "p")` in YARA-L and `match(f, "p")` in EQL both put the
    # pattern in an ordinary string argument, so it arrives as a `Literal`.
    # Only the `Regex` branch existed, so those calls returned UNDECIDED and
    # the rule reported `not_evaluated` -- a regex test that silently never
    # ran. It goes through `compile_pattern` like every other pattern, so the
    # ReDoS screen and the portable-syntax screen still apply; bypassing them
    # with a direct `re.compile` is how an untrusted pattern would reach the
    # engine unscreened.
    if isinstance(pattern, str):
        pattern = Regex(pattern, "posix_extended", False)
    if not isinstance(pattern, Regex):
        return UNDECIDED

    nocase = "nocase" in node.flags or pattern.nocase
    dialect = pattern.dialect
    if nocase and dialect not in ("pcre", "pcre2", "posix_basic"):
        # Case folding applies to the SUBJECT, not the pattern. Rewriting the
        # pattern would need vendor-specific knowledge of case rules; folding
        # the subject is exact for ASCII and honest everywhere else, because the
        # trace says the fold happened.
        try:
            compiled = compile_pattern(dialect, pattern.pattern, nocase=False)
        except Refusal as exc:
            ctx.refusal(exc)
            return UNDECIDED
        return compiled.search(subject.casefold()) is not None
    try:
        compiled = compile_pattern(dialect, pattern.pattern, nocase=nocase)
    except Refusal as exc:
        ctx.refusal(exc)
        return UNDECIDED
    return compiled.search(subject) is not None


def _fn_bin(args: list[Any], ctx: "Context", node: Call) -> Any:
    span = args[0] if args else None
    if isinstance(span, Duration):
        return span.seconds
    number = as_number(span)
    return number if number is not None else UNDECIDED


def _fn_ago(args: list[Any], ctx: "Context", node: Call) -> Any:
    """`ago(30m)` is an absolute TIMESTAMP: thirty minutes before now.

    It used to return the negative offset -- `ago(30m)` was `-1800` -- on the
    reasoning that a caller could subtract it. Nothing subtracts it, and in
    KQL `ago()` IS a timestamp: `TimeGenerated > ago(1h)` compares one instant
    with another. Against `-3600` that comparison is true for every real
    timestamp, so the window check passed every row and the rule silently
    matched outside its own time bound.

    The clock comes from `_fn_now`, so the two cannot drift apart within a
    single evaluation.
    """
    value = args[0]
    seconds = value.seconds if isinstance(value, Duration) else as_number(value)
    if seconds is None:
        return UNDECIDED
    return _fn_now([], ctx, node) - seconds


def _fn_strftime(args: list[Any], ctx: "Context", node: Call) -> Any:
    """Format an epoch time, as AQL's `DATEFORMAT` does.

    Declared in `ir.LOCAL_FUNCTIONS` with no handler, so every AQL rule using
    `DATEFORMAT(starttime, 'YYYY-MM-dd')` refused at evaluation time with
    FUNCTION_UNKNOWN -- the engine claimed it could run the rule and then
    could not.

    UTC, deliberately. A local-timezone result makes the same rule produce
    different output on two machines, which is not a rule.
    """
    seconds = as_number(args[0])
    pattern = args[1] if len(args) > 1 else None
    if seconds is None or not isinstance(pattern, str):
        return UNDECIDED
    import datetime

    try:
        moment = datetime.datetime.fromtimestamp(
            float(seconds), datetime.timezone.utc
        )
        return moment.strftime(pattern)
    except (ValueError, OverflowError, OSError) as exc:
        # A format the platform rejects, or a timestamp outside its range.
        # Reported rather than raised: a formatting problem is not grounds to
        # abandon the whole rule, but it must not look like a successful
        # format either.
        ctx.uncertain(
            "STRFTIME_UNFORMATTABLE",
            f"`{pattern}` could not format the time value {seconds}: {exc}. "
            f"That part of the expression has no value, so anything comparing "
            f"against it is undecided rather than false.",
            where=render_where(node),
        )
        return UNDECIDED


def _fn_now(args: list[Any], ctx: "Context", node: Call) -> Any:
    import time
    return Decimal(int(time.time()))


def _fn_min_max_builtin(args: list[Any], ctx: "Context", node: Call) -> Any:
    numbers = [as_number(a) for a in args]
    if any(n is None for n in numbers):
        return UNDECIDED
    values = [n for n in numbers if n is not None]
    return min(values) if node.function.lower() == "min" else max(values)


_FUNCTIONS = {
    "cidr_contains": _fn_cidr_contains,
    "starts_with": _fn_text("starts_with"),
    "ends_with": _fn_text("ends_with"),
    "contains": _fn_text("contains"),
    "contains_any": _fn_contains_any,
    "contains_all": _fn_contains_all,
    "in_set": _fn_contains_any,
    "has_any": _fn_contains_any,
    "has_all": _fn_contains_all,
    "is_empty": _fn_presence("is_empty"),
    "not_empty": _fn_presence("not_empty"),
    "is_null": _fn_presence("is_null"),
    "is_not_null": _fn_presence("is_not_null"),
    "lower": _fn_lower,
    "upper": _fn_upper,
    "length": _fn_length,
    "to_int": _fn_to_int,
    "to_string": _fn_to_string,
    "abs": _fn_math("abs"),
    "round": _fn_math("round"),
    "floor": _fn_math("floor"),
    "ceil": _fn_math("ceil"),
    # `_fn_math` has implemented these two all along; they were simply never
    # registered, so `ir.LOCAL_FUNCTIONS` claimed them and every call refused
    # with FUNCTION_UNKNOWN.
    "min": _fn_math("min"),
    "max": _fn_math("max"),
    "matches_regex": _fn_matches_regex,
    "bin": _fn_bin,
    "ago": _fn_ago,
    "now": _fn_now,
    "strftime": _fn_strftime,
}


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Context:
    """Per-evaluation state: caveats, budget, and the refusals worth reporting.

    A Refusal raised while evaluating a sub-expression (a PCRE pattern, say) is
    CAUGHT here and turned into a caveat plus UNDECIDED, rather than aborting the
    whole run. One unexecutable pattern in an otherwise valid rule should not
    cost the analyst the entire evaluation -- but it must still be impossible to
    miss.
    """

    budget: Budget = dc_field(default_factory=Budget)
    caveats: list[Caveat] = dc_field(default_factory=list)
    refusals: list[Refusal] = dc_field(default_factory=list)
    _seen: set[tuple[str, str]] = dc_field(default_factory=set)

    def _once(self, code: str, where: str) -> bool:
        key = (code, where)
        if key in self._seen:
            return False
        if len(self._seen) > 400:
            return False
        self._seen.add(key)
        return True

    def uncertain(self, code: str, message: str, where: str = "") -> None:
        if self._once(code, where):
            self.caveats.append(Caveat(code, message, "caution", where))

    def declared_only(
        self, function: str, message: str, where: str = ""
    ) -> None:
        if self._once("DECLARED_ONLY", where):
            self.caveats.append(
                Caveat(
                    "DECLARED_ONLY",
                    message,
                    "note",
                    where,
                    Capability.DECLARED_ONLY,
                )
            )

    def refusal(self, exc: Refusal) -> None:
        self.refusals.append(exc)
        if self._once(exc.code, exc.where):
            self.caveats.append(
                Caveat(exc.code, exc.message, "problem", exc.where)
            )

    @property
    def has_declared_only(self) -> bool:
        return any(c.capability is Capability.DECLARED_ONLY for c in self.caveats)
