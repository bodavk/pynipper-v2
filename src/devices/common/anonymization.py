"""Private, lossless source plans for offline sample preparation.

This is deliberately separate from effective-state/evidence APIs. Never log a
plan: tokens contain the supplied data until the rewrite boundary is crossed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
import shlex

MAX_SOURCE_TOKENS = 200_000


class AnonymizationError(ValueError):
    """A location-only public error; never accepts supplied source text."""

    def __init__(self, reason: str, line: int | None = None):
        self.reason = reason
        self.line = line
        super().__init__(f"line {line}: {reason}" if line else reason)


@dataclass(frozen=True)
class SourceToken:
    start: int
    end: int
    line: int
    value: str = field(repr=False)
    quoted: bool = False


@dataclass(frozen=True)
class SourceStatement:
    tokens: tuple[SourceToken, ...] = field(repr=False)
    start: int
    end: int
    line: int


@dataclass(frozen=True)
class Rewrite:
    token: SourceToken = field(repr=False)
    kind: str
    namespace: str = ""
    scope: str = field(default="", repr=False)


@dataclass
class RewritePlan:
    rewrites: list[Rewrite] = field(default_factory=list, repr=False)
    networks: list[tuple[str, str, int]] = field(default_factory=list, repr=False)
    ranges: list[tuple[str, str, int]] = field(default_factory=list, repr=False)
    constants: set[str] = field(default_factory=set)
    limitations: set[str] = field(default_factory=set)

    def add(self, token: SourceToken, kind: str, namespace: str = "", scope: str = "") -> None:
        self.rewrites.append(Rewrite(token, kind, namespace, scope))

    def text(self, statement: SourceStatement, source: str, label: str = "text") -> None:
        self.add(SourceToken(statement.start, statement.end, statement.line,
                             source[statement.start:statement.end]), "literal", label)


def statements(source: str, *, comments: tuple[str, ...]) -> tuple[SourceStatement, ...]:
    """Tokenize whitespace and quoted native values, retaining absolute spans.

    Comments are returned as one token for vendor-owned replacement. Strict
    decoding happens before this function; malformed quoting never falls back.
    """
    result = []
    index = 0
    line = 1
    token_count = 0
    while index < len(source):
        start = index
        number = line
        tokens = []
        while index < len(source) and source[index] not in "\r\n":
            if source[index] in " \t":
                index += 1
                continue
            if source[index].isspace():
                raise AnonymizationError("unsupported whitespace outside a quoted value", line)
            token_count += 1
            if token_count > MAX_SOURCE_TOKENS:
                raise AnonymizationError("source token budget exceeded", line)
            token_start = index
            if not tokens and source.startswith(comments, index):
                while index < len(source) and source[index] not in "\r\n":
                    index += 1
                tokens.append(SourceToken(token_start, index, line, source[token_start:index]))
                break
            quoted = source[index] in "\"'"
            if quoted:
                quote = source[index]
                index += 1
                while index < len(source):
                    if source[index] == "\\":
                        index += 2
                    elif source[index] == quote:
                        index += 1
                        break
                    else:
                        index += 1
                else:
                    raise AnonymizationError("unterminated quoted value", number)
                if index > len(source) or (index < len(source) and not source[index].isspace()):
                    raise AnonymizationError("unsupported quoted token boundary", number)
                raw = source[token_start:index]
                try:
                    values = shlex.split(raw, posix=True)
                except ValueError:
                    raise AnonymizationError("malformed quoted value", number) from None
                if len(values) != 1:
                    raise AnonymizationError("malformed quoted value", number)
                value = values[0]
                line += raw.count("\n")
            else:
                while index < len(source) and not source[index].isspace():
                    index += 1
                value = source[token_start:index]
                if any(char in value for char in "\\\"'"):
                    raise AnonymizationError("unsupported unquoted escape", number)
            tokens.append(SourceToken(token_start, index, number, value, quoted))
        result.append(SourceStatement(tuple(tokens), start, index, number))
        if index < len(source) and source[index] == "\r":
            index += 1
        if index < len(source) and source[index] == "\n":
            index += 1
            line += 1
        elif index < len(source):
            raise AnonymizationError("unsupported line separator", number)
    return tuple(result)


def require(condition: bool, reason: str, line: int) -> None:
    if not condition:
        raise AnonymizationError(reason, line)


def numeric(token: SourceToken, *, lists: bool = False) -> None:
    pattern = r"[0-9]+(?:[-:,][0-9]+)*" if lists else r"[0-9]+"
    require(bool(re.fullmatch(pattern, token.value)), "unsupported numeric setting", token.line)


def enum_values(tokens: tuple[SourceToken, ...] | list[SourceToken], allowed: str) -> None:
    choices = set(allowed.split())
    for token in tokens:
        require(token.value in choices, "unsupported enumeration value", token.line)


__all__ = ["AnonymizationError", "SourceToken", "SourceStatement", "Rewrite",
           "RewritePlan", "statements", "require", "numeric", "enum_values"]
