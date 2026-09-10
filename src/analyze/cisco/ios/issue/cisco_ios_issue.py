"""Compatibility import for the former Cisco-specific issue class."""

from src.analyze.common.issue import Finding

# New code must import and construct Finding directly. The alias keeps older
# imports working without maintaining a second data model.
CiscoIOSIssue = Finding

__all__ = ["CiscoIOSIssue"]
