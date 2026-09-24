from abc import ABC, abstractmethod
import os
from typing import Dict, List, Optional

from .models import NormalizedConfig
from src.common.assessment import AssessmentContext


class BaseDeviceParser(ABC):

    device_type = "UNKNOWN"

    def __init__(self, config_filepath: str):
        self.config_filepath = config_filepath
        self.assessment_context = AssessmentContext()

    def set_assessment_context(self, context: AssessmentContext) -> None:
        if not isinstance(context, AssessmentContext):
            raise TypeError("context must be an AssessmentContext")
        self.assessment_context = context

    @abstractmethod
    def get_hostname(self) -> str:
        """Extract and return the hostname of the device."""
        pass

    @abstractmethod
    def get_version(self) -> str:
        """Extract and return the OS/firmware version of the device."""
        pass

    @abstractmethod
    def get_users(self) -> list[dict]:
        """Extract and return the list of local users on the device."""
        pass

    @abstractmethod
    def get_services(self) -> dict:
        """Extract and return configured management services (e.g. ssh, telnet, http)."""
        pass

    @abstractmethod
    def get_native_config(self) -> object:
        """Return the vendor-native parsing object for vendor-specific plugins."""
        pass

    def get_raw_config(self) -> object:
        """Compatibility alias for :meth:`get_native_config`.

        New common logic must consume :meth:`get_normalized_config`. Vendor-
        specific rules may use ``get_native_config`` when the normalized model
        does not yet expose a required construct.
        """

        return self.get_native_config()

    def get_normalized_config(self) -> NormalizedConfig:
        """Return a complete normalized snapshot with explicit unknown state.

        Vendor parsers override this method as their normalized implementations
        are completed. Returning an explicit unknown snapshot is safer than
        converting legacy empty collections or ``False`` placeholders into
        assertions about effective configuration.
        """

        return NormalizedConfig.unknown(self.device_type)

    def locate_source_line(self, text: str) -> Optional[int]:
        """Return the line number of ``text`` if exactly one source line equals it.

        This is a conservative lookup for evidence that a plugin reports as a
        verbatim configuration line without a parser-owned line number. The
        comparison ignores surrounding whitespace only. Redacted, summarized
        or repeated text returns ``None``: the report then shows no line
        rather than a guessed one. Multi-file inputs return ``None`` unless a
        parser overrides this method.
        """

        numbers = self._source_line_index().get(text.strip())
        if numbers is not None and len(numbers) == 1:
            return numbers[0]
        return None

    def _source_line_index(self) -> Dict[str, List[int]]:
        index = getattr(self, "_located_source_line_index", None)
        if index is not None:
            return index
        index = {}
        if os.path.isfile(self.config_filepath):
            with open(self.config_filepath, "r", encoding="utf-8-sig", errors="replace") as source:
                for number, line in enumerate(source.read().split("\n"), start=1):
                    stripped = line.strip()
                    if stripped:
                        index.setdefault(stripped, []).append(number)
        self._located_source_line_index = index
        return index
