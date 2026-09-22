"""Sanitized report coverage and opt-in configuration inventory builders."""

from __future__ import annotations

import os
import unicodedata
from enum import Enum
from typing import Any, Iterable

from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import KnowledgeState, NormalizedCollection


_FIELDS = (
    ("hostname", "inventory", "hostname"),
    ("device-model", "inventory", "device_model"),
    ("software-version", "inventory", "software_version"),
    ("management-services", "services", "management_services"),
    ("local-users", "credentials", "users"),
    ("interfaces", "interfaces", "interfaces"),
    ("security-policies", "filtering", "policies"),
    ("logging-destinations", "logging", "logging_destinations"),
    ("crypto-settings", "crypto", "crypto_settings"),
)
_CATEGORY_TOKENS = {
    "filtering": {"filtering", "policy", "acl"},
    "services": {"services", "service", "management"},
    "credentials": {"credentials", "credential", "password"},
}


def _safe_text(value: Any, maximum: int = 512) -> str:
    text = str(value or "")
    text = "".join(character for character in text if unicodedata.category(character) != "Cc")
    return text[:maximum]


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return _safe_text(value)


def _coverage_entry(name: str, category: str, field: Any, excluded: set[str]) -> dict:
    entry = {
        "name": name,
        "category": category,
        "knowledge-state": field.state.value,
        "audit-selection": (
            "excluded"
            if (_CATEGORY_TOKENS.get(category, {category}) & excluded)
            else "included"
        ),
    }
    if isinstance(field, NormalizedCollection):
        entry["item-count"] = len(field.items) if field.state == KnowledgeState.KNOWN else None
    if field.detail:
        entry["detail"] = _safe_text(field.detail)
    return entry


def _record(item: Any, fields: Iterable[str]) -> dict:
    return {
        field.replace("_", "-"): _plain(getattr(item, field))
        for field in fields
        if hasattr(item, field)
    }


def _inventory(normalized, requested: tuple[str, ...]) -> dict[str, list[dict]]:
    definitions = {
        "management-services": (
            normalized.management_services,
            ("protocol", "state", "interface", "zone", "scope", "permitted_sources"),
        ),
        "interfaces": (
            normalized.interfaces,
            ("name", "state", "zone", "scope", "addresses"),
        ),
        "policies": (
            normalized.policies,
            (
                "name", "state", "action", "position", "scope", "source_interfaces",
                "destination_interfaces", "sources", "destinations", "services",
                "tracking", "install_on",
            ),
        ),
        "logging-destinations": (
            normalized.logging_destinations,
            ("destination_type", "state", "address", "severity", "scope"),
        ),
    }
    result: dict[str, list[dict]] = {}
    for name in requested:
        collection, fields = definitions[name]
        if collection.state == KnowledgeState.KNOWN:
            result[name] = [_record(item, fields) for item in collection.items]
    return result


def build_report_context(parser: BaseDeviceParser) -> dict:
    """Build additive report metadata without serializing evidence or secrets."""
    normalized = parser.get_normalized_config()
    excluded = {
        item.casefold().replace("-", "_")
        for item in parser.assessment_context.excluded_categories
    }
    fields = [
        _coverage_entry(name, category, getattr(normalized, attribute), excluded)
        for name, category, attribute in _FIELDS
    ]
    diagnostics = tuple(getattr(parser, "diagnostics", ()))
    source_kind = "directory" if os.path.isdir(parser.config_filepath) else "file"
    source_count = None
    if source_kind == "directory" and isinstance(getattr(parser, "files", None), dict):
        source_count = sum(bool(value) for value in parser.files.values())
    coverage = {
        "schema-version": 1,
        "parser": parser.__class__.__name__,
        "device-type": normalized.device_type,
        "input-kind": source_kind,
        "input-artifact-count": source_count,
        "fields": fields,
        "diagnostics": [_safe_text(item) for item in diagnostics],
        "scope-note": (
            "Known means the supplied export was parsed for this normalized field; it is not a passed security check. "
            "Unknown, unsupported, parse-error, and excluded scope is not implied secure."
        ),
    }
    if getattr(parser, "template_unresolved", False):
        coverage["input-completeness"] = "unrendered-template"
        coverage["suppressed-finding-count"] = getattr(parser, "template_suppressed_findings", 0)
        coverage["diagnostics"].append(
            "Unresolved deployment substitutions were detected; absence-based security checks requiring a complete configuration were withheld."
        )
        coverage["scope-note"] = (
            "This input contains unresolved deployment substitutions. Explicit configured states may be assessed, "
            "but omitted controls cannot be judged from this template. Counts and inventory do not establish completeness."
        )
        for field in coverage["fields"]:
            if field["knowledge-state"] == "known":
                field["knowledge-state"] = "unknown"
                field.pop("item-count", None)
                field["detail"] = "Unrendered template; field inventory may be incomplete."
    return {
        "coverage": coverage,
        "configuration-inventory": (
            {} if getattr(parser, "template_unresolved", False)
            else _inventory(normalized, parser.assessment_context.report_inventory)
        ),
    }


def build_parse_error_context(device: str, parser_name: str, line_number: int, excluded_categories=()) -> dict:
    """Report a failed file parse without exposing exception text or input bytes."""
    detail = f"Configuration parsing failed at line {line_number}; security checks were not run."
    return {
        "coverage": {
            "schema-version": 1,
            "parser": parser_name,
            "device-type": device,
            "input-kind": "file",
            "input-artifact-count": None,
            "fields": [
                {
                    "name": name,
                    "category": category,
                    "knowledge-state": "parse_error",
                    "audit-selection": (
                        "excluded"
                        if _CATEGORY_TOKENS.get(category, {category}) & set(excluded_categories)
                        else "included"
                    ),
                    "detail": detail,
                }
                for name, category, _ in _FIELDS
            ],
            "diagnostics": [detail],
            "scope-note": "The input could not be parsed. An empty finding list does not indicate a successful security assessment.",
        },
        "configuration-inventory": {},
    }


__all__ = ["build_report_context", "build_parse_error_context"]
