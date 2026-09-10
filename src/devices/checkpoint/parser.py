"""Quote-aware parser for Check Point ``*.C`` and ``*.fws`` files."""

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


class CheckPointParseError(ValueError):
    def __init__(self, source: str, line: int, column: int, message: str):
        self.source = source
        self.line = line
        self.column = column
        self.message = message
        super().__init__(f"{source}:{line}:{column}: {message}")


@dataclass(frozen=True)
class CheckPointToken:
    kind: str
    value: str
    line: int
    column: int


@dataclass(frozen=True)
class CheckPointSExpression:
    items: Tuple[Any, ...]
    line: int
    column: int


@dataclass(frozen=True)
class CheckPointDocument(Mapping):
    source: str
    expressions: Tuple[CheckPointSExpression, ...]
    data: Mapping[str, Any]

    def __getitem__(self, key):
        return self.data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.data)

    def __len__(self) -> int:
        return len(self.data)


class CheckPointFileParser:
    """Parse nested Check Point files without discarding field names or order."""

    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse(self) -> CheckPointDocument:
        with open(self.filepath, "r", encoding="utf-8", errors="replace") as config_file:
            content = config_file.read()
        tokens = self._tokenize(content)
        expressions = self._parse_expressions(tokens)
        converted = [self._to_data(expression) for expression in expressions]
        if len(converted) == 1 and isinstance(converted[0], dict):
            data = converted[0]
        else:
            data = {"_items": converted}
        return CheckPointDocument(self.filepath, tuple(expressions), data)

    def _tokenize(self, content: str) -> List[CheckPointToken]:
        tokens = []
        index = 0
        line = 1
        column = 1
        length = len(content)

        while index < length:
            char = content[index]
            if char in " \t\r":
                index += 1
                column += 1
                continue
            if char == "\n":
                index += 1
                line += 1
                column = 1
                continue
            if char == "#":
                while index < length and content[index] != "\n":
                    index += 1
                    column += 1
                continue
            if char in "()":
                tokens.append(CheckPointToken(char, char, line, column))
                index += 1
                column += 1
                continue
            if char == '"':
                start_line, start_column = line, column
                index += 1
                column += 1
                value = []
                while index < length:
                    char = content[index]
                    if char == '"':
                        index += 1
                        column += 1
                        break
                    if char == "\\":
                        index += 1
                        column += 1
                        if index >= length:
                            raise CheckPointParseError(
                                self.filepath, start_line, start_column, "Unterminated escape sequence"
                            )
                        escaped = content[index]
                        value.append({"n": "\n", "r": "\r", "t": "\t"}.get(escaped, escaped))
                        index += 1
                        column += 1
                        continue
                    if char == "\n":
                        value.append(char)
                        index += 1
                        line += 1
                        column = 1
                        continue
                    value.append(char)
                    index += 1
                    column += 1
                else:
                    raise CheckPointParseError(
                        self.filepath, start_line, start_column, "Unterminated quoted string"
                    )
                tokens.append(CheckPointToken("STRING", "".join(value), start_line, start_column))
                continue

            start = index
            start_column = column
            while index < length and content[index] not in "() \t\r\n":
                index += 1
                column += 1
            tokens.append(CheckPointToken("ATOM", content[start:index], line, start_column))

        return tokens

    def _parse_expressions(self, tokens: List[CheckPointToken]) -> List[CheckPointSExpression]:
        expressions = []
        position = 0

        def parse_list() -> CheckPointSExpression:
            nonlocal position
            opener = tokens[position]
            position += 1
            items = []
            while position < len(tokens):
                token = tokens[position]
                if token.kind == ")":
                    position += 1
                    return CheckPointSExpression(tuple(items), opener.line, opener.column)
                if token.kind == "(":
                    items.append(parse_list())
                else:
                    items.append(token)
                    position += 1
            raise CheckPointParseError(
                self.filepath, opener.line, opener.column, "Unclosed parenthesized expression"
            )

        while position < len(tokens):
            token = tokens[position]
            if token.kind == ")":
                raise CheckPointParseError(
                    self.filepath, token.line, token.column, "Unmatched closing parenthesis"
                )
            if token.kind != "(":
                raise CheckPointParseError(
                    self.filepath, token.line, token.column, "Expected an opening parenthesis"
                )
            expressions.append(parse_list())
        return expressions

    @staticmethod
    def _add_field(fields: Dict[str, Any], key: str, value: Any) -> None:
        if key not in fields:
            fields[key] = value
        elif isinstance(fields[key], list):
            fields[key].append(value)
        else:
            fields[key] = [fields[key], value]

    def _to_data(self, expression: Any) -> Any:
        if isinstance(expression, CheckPointToken):
            return expression.value

        fields: Dict[str, Any] = {}
        anonymous = []
        items = list(expression.items)
        index = 0
        while index < len(items):
            item = items[index]
            if isinstance(item, CheckPointToken) and item.kind == "ATOM" and item.value.startswith(":"):
                key = item.value[1:] or "_value"
                if index + 1 < len(items):
                    following = items[index + 1]
                    if not (
                        isinstance(following, CheckPointToken)
                        and following.kind == "ATOM"
                        and following.value.startswith(":")
                    ):
                        self._add_field(fields, key, self._to_data(following))
                        index += 2
                        continue
                self._add_field(fields, key, True)
            else:
                anonymous.append(self._to_data(item))
            index += 1

        if fields:
            if anonymous:
                fields["_items"] = anonymous
            return fields
        if not anonymous:
            return []
        if len(anonymous) == 1:
            return anonymous[0]
        return anonymous


__all__ = [
    "CheckPointDocument",
    "CheckPointFileParser",
    "CheckPointParseError",
    "CheckPointSExpression",
    "CheckPointToken",
]
