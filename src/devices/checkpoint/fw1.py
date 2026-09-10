import os
from collections.abc import Mapping, Sequence
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
            has_action = "action" in normalized_keys or "type" in normalized_keys
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

    @staticmethod
    def _is_true(value: object) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"true", "yes", "1", "enable", "enabled"}

    def _normalized_policies(self) -> NormalizedCollection[SecurityPolicy]:
        documents = [
            document
            for key, document in self.parsed_data.items()
            if key in {"rules", "rulebases"}
        ]
        if not documents:
            return NormalizedCollection.unknown("No Check Point rule or rulebase export was found")

        policies = []
        position = 0
        for document in documents:
            for path, rule in self._iter_rule_candidates(document):
                position += 1
                name_value = self._field(rule, "name", "rule_name", "uid", "chkpf_uid")
                name = self._first_string(name_value) or (path[-1] if path else f"rule-{position}")
                disabled_value = self._field(rule, "disabled")
                state = (
                    ConfigurationState.DISABLED
                    if self._is_true(self._first_string(disabled_value))
                    else ConfigurationState.ENABLED
                )
                action = self._first_string(self._field(rule, "action", "type"), "unknown")
                sources = self._references(self._field(rule, "src", "source", "object"))
                destinations = self._references(self._field(rule, "dst", "destination"))
                services = self._references(self._field(rule, "services", "service"))
                tracking = self._first_string(self._field(rule, "track", "tracking")) or None
                install_on = self._references(
                    self._field(rule, "install", "install_on", "installon")
                )
                policies.append(
                    SecurityPolicy(
                        name=name,
                        state=state,
                        action=action.lower(),
                        position=position,
                        scope=" / ".join(path[:-1]) or None,
                        sources=sources,
                        destinations=destinations,
                        services=services,
                        tracking=tracking,
                        install_on=install_on,
                        evidence=(
                            ConfigEvidence(
                                text=f"Check Point rule {name}",
                                source=document.source,
                            ),
                        ),
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
