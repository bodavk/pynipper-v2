"""Map a device family and exported software version to an NVD CPE product (PT-010).

Only unambiguous release strings are mapped. A release train such as IOS-XE
``17.9`` cannot be matched to affected releases, so it is reported as imprecise
and the operator may supply the exact release instead. Nothing here performs
network access.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ProductVersion:
    """A CPE 2.3 product plus the version/update components used for lookup."""

    part: str
    vendor: str
    product: str
    version: str
    update: str = ""
    note: str = ""

    @property
    def product_prefix(self) -> str:
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}"

    def match_string(self) -> str:
        text = f"{self.product_prefix}:{escape_cpe(self.version)}"
        return f"{text}:{escape_cpe(self.update)}" if self.update else text

    @property
    def display(self) -> str:
        return f"{self.version} ({self.update})" if self.update else self.version

    def to_dict(self) -> dict:
        return {
            "part": self.part, "vendor": self.vendor, "product": self.product,
            "version": self.version, "update": self.update,
        }


class VersionUnavailable(ValueError):
    """The version cannot be mapped; ``reason`` is a stable code, ``args[0]`` the text."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def escape_cpe(value: str) -> str:
    """Quote CPE 2.3 formatted-string punctuation (for example ``(`` becomes ``\\(``)."""

    return re.sub(r"([^A-Za-z0-9._\-])", r"\\\1", value)


def split_cpe(name: str) -> list[str]:
    """Split a CPE 2.3 formatted string on unescaped colons and unquote each field."""

    fields = re.split(r"(?<!\\):", name)
    return [re.sub(r"\\(.)", r"\1", field).casefold() for field in fields]


_IOS_FAMILIES = {"IOS_SWITCH", "IOS_ROUTER", "IOS_CATALYST", "IOS_XE"}
_UNSUPPORTED = {
    "CHECKPOINT_FW1": "A Check Point policy export does not contain the gateway software version.",
    "HP_PROCURVE": "The NVD naming of AOS-S releases is not qualified yet.",
    "PIX": "PIX release naming is not qualified (see SC-020).",
}


def _imprecise(version: str, example: str) -> VersionUnavailable:
    return VersionUnavailable(
        "imprecise-version",
        f"The configuration only states '{version}', which is not an exact release. "
        f"Supply the running release with --software-version (for example {example}).",
    )


def _ios(device: str, version: str) -> ProductVersion:
    classic = re.fullmatch(r"\d+\.\d+\(\d+[a-z]?\)[a-z0-9]*", version, re.IGNORECASE)
    if classic:
        return ProductVersion("o", "cisco", "ios", version.casefold())
    xe = re.fullmatch(r"(\d{2})\.(\d{1,2})\.(\d{1,2})([a-z]?)", version, re.IGNORECASE)
    if xe:
        major, minor, patch, suffix = xe.groups()
        return ProductVersion("o", "cisco", "ios_xe", f"{int(major)}.{int(minor)}.{int(patch)}{suffix.casefold()}")
    example = "17.9.4a" if device == "IOS_XE" or re.match(r"1[6-9]\.", version) else "15.2(4)M7"
    raise _imprecise(version, example)


def product_version(device: str, version: str) -> ProductVersion:
    """Return the CPE product and version for ``device`` or raise ``VersionUnavailable``."""

    device = str(device).upper()
    version = (version or "").strip()
    if device in _UNSUPPORTED:
        raise VersionUnavailable("unsupported-family", _UNSUPPORTED[device])
    if not version or version in {"?", "unknown"}:
        raise VersionUnavailable(
            "no-version",
            "The configuration does not state a software version. Supply it with --software-version.",
        )
    if device in _IOS_FAMILIES:
        return _ios(device, version)
    if device == "ASA":
        match = re.fullmatch(r"(\d+)\.(\d+)\((\d+)\)(\d+)?", version)
        if not match:
            raise _imprecise(version, "9.18(4)22")
        parts = [part for part in match.groups() if part is not None]
        return ProductVersion("a", "cisco", "adaptive_security_appliance_software", ".".join(parts))
    if device == "FORTIOS":
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise _imprecise(version, "7.4.6")
        return ProductVersion("o", "fortinet", "fortios", version)
    if device == "JUNOS":
        match = re.fullmatch(r"(\d+\.\d+(?:x\d+)?)-?([rd]\d+(?:-s\d+)?)(?:\.\d+)?", version, re.IGNORECASE)
        if not match:
            raise _imprecise(version, "22.4R3-S2")
        return ProductVersion("o", "juniper", "junos", match.group(1).casefold(), match.group(2).casefold())
    if device == "SCREENOS":
        match = re.fullmatch(r"(\d+\.\d+\.\d+)(r\d+)(?:\.\d+)?", version, re.IGNORECASE)
        if not match:
            raise _imprecise(version, "6.3.0r27")
        return ProductVersion("o", "juniper", "screenos", match.group(1), match.group(2).casefold())
    if device == "PAN_OS":
        match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-(h\d+))?", version, re.IGNORECASE)
        if not match:
            raise _imprecise(version, "11.2.3-h1")
        return ProductVersion("o", "paloaltonetworks", "pan-os", match.group(1), (match.group(2) or "").casefold())
    if device == "ARISTA_EOS":
        if not re.fullmatch(r"\d+\.\d+\.\d+[a-z]*", version, re.IGNORECASE):
            raise _imprecise(version, "4.29.2F")
        return ProductVersion("o", "arista", "eos", version.casefold())
    if device == "SONICOS":
        if not re.fullmatch(r"\d+\.\d+\.\d+(?:-\d+)?", version):
            raise _imprecise(version, "7.1.2-7019")
        return ProductVersion("o", "sonicwall", "sonicos", version)
    if device == "F5_BIGIP":
        if not re.fullmatch(r"\d+\.\d+\.\d+(?:\.\d+)?", version):
            raise _imprecise(version, "16.1.5")
        return ProductVersion(
            "a", "f5", "big-ip_local_traffic_manager", version,
            note="BIG-IP CVEs are recorded per module; only the LTM module was queried.",
        )
    raise VersionUnavailable("unsupported-family", f"CVE lookup is not qualified for {device}.")


__all__ = ["ProductVersion", "VersionUnavailable", "escape_cpe", "product_version", "split_cpe"]
