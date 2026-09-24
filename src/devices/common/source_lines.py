"""Map physical source lines to logical configuration statements.

Several vendor exports store one configuration value across several physical
lines, for example PEM private keys, certificates and banner text inside a
double-quoted string. Line-oriented parsers must treat such a value as one
statement. Otherwise a key body is rejected as invalid quoting, or banner text
is misread as independent commands.

This module only groups lines. Vendor parsers remain responsible for their
grammar, redaction, and whether an unterminated value is a parse error.
"""

from dataclasses import dataclass
from typing import Iterable, Optional, Sequence, Tuple


@dataclass(frozen=True)
class LogicalLine:
    """One statement spanning inclusive physical lines ``start_line..end_line``."""

    text: str
    start_line: int
    end_line: int

    @property
    def is_multiline(self) -> bool:
        return self.end_line > self.start_line


@dataclass(frozen=True)
class QuotedLineGrouping:
    """Grouping result.

    ``unterminated_line`` is the first physical line of a double-quoted value
    that is still open at end of input. The lines from that point on are
    returned one per logical line, as they were before grouping existed.
    Strict parsers should turn this into their typed parse error. Tolerant
    parsers should record a diagnostic.
    """

    lines: Tuple[LogicalLine, ...]
    unterminated_line: Optional[int] = None


def _ends_inside_double_quote(text: str, inside: bool) -> bool:
    """Return the double-quote state after scanning ``text``.

    A backslash escapes the following character both inside and outside
    quotes, matching the POSIX ``shlex`` tokenization used by the parsers.
    Single quotes are deliberately ignored: apostrophes are common in banner
    and comment text, and the supported formats quote multi-line values with
    double quotes.
    """

    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == '"':
            inside = not inside
        index += 1
    return inside


def group_double_quoted_lines(
    physical_lines: Sequence[str],
    *,
    comment_prefixes: Iterable[str] = (),
) -> QuotedLineGrouping:
    """Join physical lines while a double-quoted value remains open.

    ``physical_lines`` must not contain line terminators (use ``splitlines``).
    Joined lines keep their original content and are separated by ``"\\n"``.
    A line whose stripped text starts with one of ``comment_prefixes`` is never
    scanned when no value is open, so a quote inside a comment cannot start a
    continuation. Line numbers are 1-based.
    """

    prefixes = tuple(comment_prefixes)
    grouped = []
    index = 0
    total = len(physical_lines)
    while index < total:
        first = physical_lines[index]
        start = index
        if prefixes and first.strip().startswith(prefixes):
            grouped.append(LogicalLine(first, index + 1, index + 1))
            index += 1
            continue
        inside = _ends_inside_double_quote(first, False)
        while inside and index + 1 < total:
            index += 1
            inside = _ends_inside_double_quote(physical_lines[index], inside)
        if inside:
            grouped.extend(
                LogicalLine(line, number, number)
                for number, line in enumerate(physical_lines[start:], start=start + 1)
            )
            return QuotedLineGrouping(tuple(grouped), start + 1)
        grouped.append(
            LogicalLine("\n".join(physical_lines[start:index + 1]), start + 1, index + 1)
        )
        index += 1
    return QuotedLineGrouping(tuple(grouped))


def single_line_evidence(text: str, end_line: Optional[int] = None) -> str:
    """Return evidence text limited to its first physical line.

    Parsers call this after redaction so that a multi-line value (banner text,
    certificate body) does not flood a report. The marker tells the reader
    where the value ends in the source file.
    """

    if "\n" not in text:
        return text
    first = text.split("\n", 1)[0].rstrip()
    if end_line is not None:
        return f"{first} ... <value continues to line {end_line}>"
    return f"{first} ... <multi-line value continues>"


__all__ = [
    "LogicalLine",
    "QuotedLineGrouping",
    "group_double_quoted_lines",
    "single_line_evidence",
]
