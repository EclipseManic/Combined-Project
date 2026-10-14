"""RuleForge -- a detection rule workbench for enterprise SIEM rules.

The pipeline every dialect plugs into:

    parse    native text  -> parsed structure
    lower    parsed       -> Rule          (the model in ir.py)
    render   Rule         -> native text

Nothing above the engine is allowed to know a vendor's syntax, and nothing in
the engine is allowed to know a vendor exists. That is what makes eight dialects
possible without eight tools, and it is enforced by a test rather than by
good intentions.
"""

from __future__ import annotations

from .values import (
    ABSENT,
    UNDECIDED,
    Absent,
    Capability,
    Duration,
    Refusal,
    Seq,
    Undecided,
    and_,
    as_number,
    coalesce,
    compare,
    has_value,
    is_absent,
    is_undecided,
    not_,
    or_,
)

__all__ = [
    "ABSENT",
    "UNDECIDED",
    "Absent",
    "Undecided",
    "Capability",
    "Duration",
    "Refusal",
    "Seq",
    "and_",
    "as_number",
    "coalesce",
    "compare",
    "has_value",
    "is_absent",
    "is_undecided",
    "not_",
    "or_",
]

__version__ = "0.1.0"
