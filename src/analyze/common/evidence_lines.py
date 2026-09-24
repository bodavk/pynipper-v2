"""Attach source line numbers to finding evidence before reporting."""

from pathlib import PurePath
from typing import Iterable, List

from src.analyze.common.issue import Finding
from src.devices.common.base_parser import BaseDeviceParser


def attach_source_lines(parser: BaseDeviceParser, findings: Iterable[Finding]) -> List[Finding]:
    """Give each evidence entry a line number when it can be established exactly.

    Parser-owned ``ConfigEvidence`` line numbers are kept as they are. Plain
    evidence text is located only when it equals exactly one input line.
    Everything else keeps no line.
    """

    source_name = PurePath(parser.config_filepath).name or None
    findings = list(findings)
    for finding in findings:
        finding.locate_evidence(parser.locate_source_line, source_name)
    return findings


__all__ = ["attach_source_lines"]
