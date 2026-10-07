"""Bounds for statements already selected and sanitized by a native parser.

This helper performs no syntax parsing, source extraction or reference resolution.
"""

from dataclasses import replace

from typing import Iterable

from .models import ConfigEvidence, EvidenceContext, EvidencePresentation


def bounded_context(title: str, lines: Iterable[ConfigEvidence], *, notes: Iterable[str] = (),
                    related: Iterable[EvidenceContext] = ()) -> EvidenceContext:
    statements = tuple(lines)
    # Keep proof-bearing settings before supporting context when the ceiling hits.
    if len(statements) > 200:
        ranked = sorted(enumerate(statements), key=lambda pair: (not pair[1].decisive, pair[0]))[:200]
        selected = tuple(line for _, line in sorted(ranked))
    else:
        selected = statements
    companions = tuple(related)
    annotations = tuple(notes)
    if len(companions) > 32:
        annotations += (f"{len(companions) - 32} related contexts truncated by the 32-object bound; consult source.",)
    return EvidenceContext(title, selected, annotations, max(0, len(statements) - 200), companions[:32])


def context_statement(text: str, source: str, line: int | None = None, *, decisive: bool = False,
                      presentation: EvidencePresentation | None = None) -> ConfigEvidence:
    """Bound a selected value's display length without pretending it is complete."""
    item = ConfigEvidence(text, source, line, presentation=presentation, decisive=decisive)
    if len(text) > 1024:
        item = replace(item, text=text[:1024] + " <statement truncated; consult source>",
                       presentation=EvidencePresentation.TRUNCATED)
    return item
