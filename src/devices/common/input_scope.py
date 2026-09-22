"""Recognize unresolved deployment substitutions without retaining their values."""

import re


_TEMPLATE_MARKER = re.compile(
    r"\{\{[^{}\r\n]{1,256}\}\}|\{%[^%\r\n]{1,256}%\}|"
    r"\$\{ACCEL_LOOKUP::[^}\r\n]{1,256}\}|"
    r"<#{0,3}PLACEHOLDER(?:[-_][A-Za-z0-9_-]{1,128})?#{0,3}>",
    re.IGNORECASE,
)


def contains_unresolved_template(value: str) -> bool:
    return bool(_TEMPLATE_MARKER.search(value))
