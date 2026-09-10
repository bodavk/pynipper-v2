import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Iterator, List, Optional, Tuple

from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import (
    ConfigEvidence,
    ConfigurationState,
    NormalizedCollection,
    NormalizedConfig,
    NormalizedValue,
    SecurityPolicy,
)
from .parser import CheckPointDocument, CheckPointFileParser


@dataclass(frozen=True)
class CheckPointObject:
    name: str
    kind: str
    members: Tuple[str, ...] = ()
    address: Optional[str] = None
    netmask: Optional[str] = None
    last_address: Optional[str] = None
    firewall: bool = False
    evidence: Tuple[ConfigEvidence, ...] = ()


@dataclass(frozen=True)
class CheckPointService:
    name: str
    kind: str
    protocol: Optional[str] = None
    port: Optional[str] = None
    members: Tuple[str, ...] = ()
    evidence: Tuple[ConfigEvidence, ...] = ()


@dataclass(frozen=True)
class CheckPointRule:
    name: str
    layer: str
    position: int
    enabled: bool
    action: str
    sources: Tuple[str, ...]
    destinations: Tuple[str, ...]
    services: Tuple[str, ...]
    install_on: Tuple[str, ...]
    through: Tuple[str, ...]
    vpn: Tuple[str, ...]
    tracking: Optional[str]
    comments: Optional[str]
    time: Tuple[str, ...]
    source_negated: bool
    destination_negated: bool
    service_negated: bool
    evidence: Tuple[ConfigEvidence, ...]


@dataclass(frozen=True)
class CheckPointLayer:
    name: str
    kind: Optional[str]
    implicit_cleanup_action: Optional[str]
    rules: Tuple[CheckPointRule, ...]


class CheckPointFW1Parser(BaseDeviceParser):

    device_type = "CHECKPOINT_FW1"

    def __init__(self, config_directory: str):
        super().__init__(config_directory)
        if not os.path.isdir(config_directory):
            raise ValueError(f"CheckPoint configuration source must be a directory: {config_directory}")
        
        self.config_directory = config_directory
        self.files = self._locate_files()
        self.parsed_data = self._parse_files()

    def _locate_files(self) -> dict:
        """Locates CheckPoint database files in the provided directory."""
        files = {
            "objects": None,
            "rules": None,
            "rulebases": None
        }
        
        # Look for object files
        for obj_file in ["objects_5_0.C", "objects.C_41", "objects.C"]:
            path = os.path.join(self.config_directory, obj_file)
            if os.path.exists(path):
                files["objects"] = path
                break
        
        # Look for rule files
        for rule_file in ["rules.C"]:
            path = os.path.join(self.config_directory, rule_file)
            if os.path.exists(path):
                files["rules"] = path
                break

        # Look for rulebases
        for rb_file in ["rulebases_5_0.fws", "rulebases.fws"]:
            path = os.path.join(self.config_directory, rb_file)
            if os.path.exists(path):
                files["rulebases"] = path
                break
                
        return files

    def _parse_files(self) -> dict[str, CheckPointDocument]:
        """Parses all located CheckPoint files."""
        data = {}
        for key, path in self.files.items():
            if path:
                parser = CheckPointFileParser(path)
                data[key] = parser.parse()
        return data

    def get_hostname(self) -> str:
        # Simplistic extraction
        return "checkpoint-device"

    def get_version(self) -> str:
        # Simplistic extraction
        return "unknown"

    def get_users(self) -> list[dict]:
        # Simplistic extraction - CheckPoint stores users differently
        return []

    def get_services(self) -> dict:
        # Simplistic extraction
        return {"telnet": False, "ssh": False, "http": False}

    def get_native_config(self) -> Any:
        return self.parsed_data

    @staticmethod
    def _flatten_strings(value: object) -> Tuple[str, ...]:
        flattened: List[str] = []

        def visit(item: object) -> None:
            if isinstance(item, str):
                flattened.append(item)
            elif isinstance(item, Mapping):
                for child in item.values():
                    visit(child)
            elif isinstance(item, Sequence) and not isinstance(item, (str, bytes)):
                for child in item:
                    visit(child)

        visit(value)
        return tuple(flattened)

    @classmethod
    def _first_string(cls, value: object, default: str = "") -> str:
        values = cls._flatten_strings(value)
        return values[0] if values else default

    @classmethod
    def _references(cls, value: object) -> Tuple[str, ...]:
        references: List[str] = []

        def visit(item: object) -> None:
            if isinstance(item, Mapping):
                name = cls._field(item, "name")
                if name is not None:
                    references.extend(cls._flatten_strings(name))
                    return
                for child in item.values():
                    visit(child)
            elif isinstance(item, Sequence) and not isinstance(item, (str, bytes)):
                for child in item:
                    visit(child)
            elif isinstance(item, str) and item.lower() not in {
                "referenceobject",
                "reference_object",
            }:
                references.append(item)

        visit(value)
        return tuple(references)

    @staticmethod
    def _field(mapping: Mapping, *names: str) -> object:
        normalized = {str(key).lower().replace("-", "_"): value for key, value in mapping.items()}
        for name in names:
            if name in normalized:
                return normalized[name]
        return None

    def _iter_rule_candidates(
        self, value: object, path: Tuple[str, ...] = ()
    ) -> Iterator[Tuple[Tuple[str, ...], Mapping]]:
        if isinstance(value, Mapping):
            normalized_keys = {str(key).lower().replace("-", "_") for key in value}
            has_action = "action" in normalized_keys
            has_match = bool(
                normalized_keys.intersection(
                    {"src", "source", "dst", "destination", "services", "service", "object"}
                )
            )
            looks_named_rule = bool(path and "rule" in path[-1].lower())
            if has_action and (has_match or looks_named_rule):
                yield path, value
                return
            for key, child in value.items():
                yield from self._iter_rule_candidates(child, path + (str(key),))
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            for index, child in enumerate(value):
                yield from self._iter_rule_candidates(child, path + (str(index),))

    @classmethod
    def _choice(cls, value: object, choices: set[str], default: str = "") -> str:
        for item in cls._flatten_strings(value):
            normalized = item.strip().casefold().replace("_", "-")
            if normalized in choices:
                return normalized
        return cls._first_string(value, default).strip().casefold()

    @classmethod
    def _display_choice(cls, value: object, choices: set[str]) -> str:
        for item in cls._references(value) + cls._flatten_strings(value):
            if item.strip().casefold() in choices:
                return item.strip()
        return cls._first_string(value).strip()

    @classmethod
    def _negated(cls, value: object) -> bool:
        normalized = " ".join(cls._flatten_strings(value)).strip().casefold()
        return normalized in {
            "!",
            "not",
            "not in",
            "not-in",
            "notin",
            "true",
            "yes",
            "1",
            "enable",
            "enabled",
        }

    @staticmethod
    def _mapping_at_path(value: object, path: Tuple[str, ...]) -> Optional[Mapping]:
        current = value
        for element in path:
            if isinstance(current, Mapping):
                current = current.get(element)
            elif isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
                if not element.isdigit() or int(element) >= len(current):
                    return None
                current = current[int(element)]
            else:
                return None
        return current if isinstance(current, Mapping) else None

    def get_policy_rules(self) -> Tuple[CheckPointRule, ...]:
        # rules.C contains the rule semantics.  Legacy rulebases files often
        # repeat those rules to attach display metadata, so use them only when
        # a rules export is absent rather than double-counting the policy.
        document = self.parsed_data.get("rules") or self.parsed_data.get("rulebases")
        if document is None:
            return ()

        rules: List[CheckPointRule] = []
        positions: dict[str, int] = {}
        for path, rule in self._iter_rule_candidates(document):
            layer_path = path[:-2] if len(path) >= 2 and path[-2] == "_value" else path[:-1]
            layer = " / ".join(layer_path) or "default"
            positions[layer] = positions.get(layer, 0) + 1
            position = positions[layer]
            name_value = self._field(rule, "name", "rule_name", "uid", "chkpf_uid")
            name = (
                self._first_string(name_value)
                or self._first_string(self._field(rule, "_items"))
                or (path[-1] if path else f"rule-{position}")
            )
            action = self._choice(
                self._field(rule, "action"),
                {"accept", "allow", "drop", "reject", "ask", "encrypt"},
                "unknown",
            )
            tracking_value = self._field(rule, "track", "tracking")
            tracking = self._display_choice(
                tracking_value,
                {"log", "accounting", "alert", "mail", "snmp", "none"},
            ) or None
            disabled = self._is_true(self._first_string(self._field(rule, "disabled")))
            source_negated = self._negated(
                self._field(rule, "src_op", "source_op", "source_negated", "source_negate")
            )
            destination_negated = self._negated(
                self._field(
                    rule,
                    "dst_op",
                    "destination_op",
                    "destination_negated",
                    "destination_negate",
                )
            )
            service_negated = self._negated(
                self._field(
                    rule,
                    "services_op",
                    "service_op",
                    "service_negated",
                    "service_negate",
                )
            )
            evidence = (
                ConfigEvidence(
                    text=f"Check Point layer '{layer}' rule {position} '{name}'",
                    source=document.source,
                ),
            )
            rules.append(
                CheckPointRule(
                    name=name,
                    layer=layer,
                    position=position,
                    enabled=not disabled,
                    action=action,
                    sources=self._references(self._field(rule, "src", "source", "object")),
                    destinations=self._references(self._field(rule, "dst", "destination")),
                    services=self._references(self._field(rule, "services", "service")),
                    install_on=self._references(
                        self._field(rule, "install", "install_on", "installon")
                    ),
                    through=self._references(self._field(rule, "through")),
                    vpn=self._references(self._field(rule, "vpn", "vpn_community")),
                    tracking=tracking,
                    comments=self._first_string(self._field(rule, "comments", "comment")) or None,
                    time=self._references(
                        self._field(
                            rule,
                            "time",
                            "time_object",
                            "expiration",
                            "expiration_date",
                            "expires",
                            "expiry",
                        )
                    ),
                    source_negated=source_negated,
                    destination_negated=destination_negated,
                    service_negated=service_negated,
                    evidence=evidence,
                )
            )
        return tuple(rules)

    def get_policy_layers(self) -> Tuple[CheckPointLayer, ...]:
        document = self.parsed_data.get("rules") or self.parsed_data.get("rulebases")
        if document is None:
            return ()
        grouped: dict[str, List[CheckPointRule]] = {}
        for rule in self.get_policy_rules():
            grouped.setdefault(rule.layer, []).append(rule)
        layers = []
        for name, rules in grouped.items():
            first_path = tuple(name.split(" / ")) if name != "default" else ()
            container = self._mapping_at_path(document, first_path) or {}
            kind = self._first_string(
                self._field(container, "layer_type", "type")
            ) or None
            cleanup = self._choice(
                self._field(
                    container,
                    "implicit_cleanup_action",
                    "implicit_cleanup",
                    "default_action",
                ),
                {"accept", "allow", "drop", "reject"},
            ) or None
            layers.append(CheckPointLayer(name, kind, cleanup, tuple(rules)))
        return tuple(layers)

    def _iter_object_candidates(
        self, value: object, path: Tuple[str, ...] = ()
    ) -> Iterator[Tuple[Tuple[str, ...], Mapping]]:
        if isinstance(value, Mapping):
            keys = {str(key).casefold().replace("-", "_") for key in value}
            if keys.intersection(
                {
                    "type",
                    "class",
                    "ipaddr",
                    "ipaddr_first",
                    "ipaddr_last",
                    "netmask",
                    "members",
                    "port",
                    "protocol",
                }
            ) and path:
                yield path, value
                return
            for key, child in value.items():
                yield from self._iter_object_candidates(child, path + (str(key),))
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            for index, child in enumerate(value):
                yield from self._iter_object_candidates(child, path + (str(index),))

    def _object_records(self) -> Tuple[Tuple[CheckPointObject, ...], Tuple[CheckPointService, ...]]:
        document = self.parsed_data.get("objects")
        if document is None:
            return (), ()
        objects: List[CheckPointObject] = []
        services: List[CheckPointService] = []
        service_kinds = {
            "dcerpc",
            "gtp",
            "gtp-v1",
            "icmp",
            "other",
            "rpc",
            "service",
            "tcp",
            "tcp-subservice",
            "udp",
        }
        for path, record in self._iter_object_candidates(document):
            name = (
                self._first_string(self._field(record, "name"))
                or self._first_string(self._field(record, "_items"))
                or path[-1]
            )
            kind = self._first_string(self._field(record, "type", "class"), "unknown")
            normalized_kind = kind.casefold().replace("_", "-")
            members = self._references(
                self._field(record, "members", "member", "cluster_members")
            )
            evidence = (
                ConfigEvidence(
                    text=f"Check Point object '{name}' ({normalized_kind})",
                    source=document.source,
                ),
            )
            path_is_service = any("service" in element.casefold() for element in path[:-1])
            has_service_fields = any(
                self._field(record, field) is not None for field in ("port", "protocol")
            )
            if normalized_kind in service_kinds or path_is_service or has_service_fields:
                services.append(
                    CheckPointService(
                        name=name,
                        kind=normalized_kind,
                        protocol=self._first_string(self._field(record, "protocol")) or None,
                        port=self._first_string(self._field(record, "port")) or None,
                        members=members,
                        evidence=evidence,
                    )
                )
            else:
                objects.append(
                    CheckPointObject(
                        name=name,
                        kind=normalized_kind,
                        members=members,
                        address=self._first_string(
                            self._field(record, "ipaddr", "ipaddr_first")
                        ) or None,
                        netmask=self._first_string(self._field(record, "netmask")) or None,
                        last_address=self._first_string(
                            self._field(record, "ipaddr_last")
                        ) or None,
                        firewall=self._first_string(
                            self._field(record, "firewall")
                        ).casefold() in {"installed", "true", "yes"},
                        evidence=evidence,
                    )
                )
        return tuple(objects), tuple(services)

    def get_policy_objects(self) -> Tuple[CheckPointObject, ...]:
        return self._object_records()[0]

    def get_service_objects(self) -> Tuple[CheckPointService, ...]:
        return self._object_records()[1]

    @staticmethod
    def _is_true(value: object) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"true", "yes", "1", "enable", "enabled"}

    def _normalized_policies(self) -> NormalizedCollection[SecurityPolicy]:
        if "rules" not in self.parsed_data and "rulebases" not in self.parsed_data:
            return NormalizedCollection.unknown("No Check Point rule or rulebase export was found")

        policies = []
        global_position = 0
        for rule in self.get_policy_rules():
            global_position += 1
            policies.append(
                SecurityPolicy(
                    name=rule.name,
                    state=(
                        ConfigurationState.ENABLED
                        if rule.enabled
                        else ConfigurationState.DISABLED
                    ),
                    action=rule.action,
                    position=global_position,
                    scope=rule.layer,
                    sources=rule.sources,
                    destinations=rule.destinations,
                    services=rule.services,
                    tracking=rule.tracking,
                    install_on=rule.install_on,
                    evidence=rule.evidence,
                )
            )
        return NormalizedCollection.known(*policies)

    def get_normalized_config(self) -> NormalizedConfig:
        return NormalizedConfig(
            device_type=self.device_type,
            hostname=NormalizedValue.unknown("Management hostname is not present in these exports"),
            device_model=NormalizedValue.unsupported(
                "Firewall-1 policy exports do not identify the gateway hardware model"
            ),
            software_version=NormalizedValue.unknown(
                "Check Point release metadata was not found in the located files"
            ),
            management_services=NormalizedCollection.unsupported(
                "Firewall-1 policy exports do not describe gateway management daemons"
            ),
            users=NormalizedCollection.unsupported(
                "Administrator databases are outside the supported FW1 export set"
            ),
            interfaces=NormalizedCollection.unsupported(
                "Firewall-1 policy exports do not contain gateway interface state"
            ),
            policies=self._normalized_policies(),
            logging_destinations=NormalizedCollection.unsupported(
                "Gateway logging destinations are outside the supported FW1 export set"
            ),
            crypto_settings=NormalizedCollection.unsupported(
                "Gateway cryptographic settings are outside the supported FW1 export set"
            ),
        )


__all__ = [
    "CheckPointFW1Parser",
    "CheckPointLayer",
    "CheckPointObject",
    "CheckPointRule",
    "CheckPointService",
]
