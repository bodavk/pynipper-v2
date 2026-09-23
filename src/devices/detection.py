"""Conservative, secret-free identification of recognizable configuration exports."""

from __future__ import annotations

import re
from pathlib import Path


class DeviceDetectionError(ValueError):
    """The input does not prove exactly one supported configuration family."""


def detect_device_type(input_path: str) -> str:
    """Return a canonical registry ID only for a distinctive export signature.

    This is format identification, not device-role inference. No source text is
    included in diagnostics because configuration lines may contain secrets.
    """
    path = Path(input_path)
    if path.is_dir():
        if (path / "rules.C").is_file() and (path / "objects.C").is_file():
            return "CHECKPOINT_FW1"
        raise DeviceDetectionError(
            "Directory is not a recognizable Check Point FW1 export "
            "(expected rules.C and objects.C); choose -d explicitly."
        )
    if not path.is_file():
        raise DeviceDetectionError("Input file does not exist; check -i.")

    with path.open("r", encoding="utf-8", errors="replace") as source:
        sample = source.read(131072)

    matches: set[str] = set()
    if re.search(r"(?m)^#TMSH-VERSION:\s*\S+", sample):
        matches.add("F5_BIGIP")
    if re.search(r"(?m)^#config-version=\S+", sample):
        matches.add("FORTIOS")
    if re.search(r"(?m)^ASA Version\s+\S+", sample):
        matches.add("ASA")
    if re.search(r'(?m)^firmware-version\s+"SonicOS\s+[^\"]+"', sample):
        matches.add("SONICOS")
    if re.search(r"(?m)^! device:.*\bEOS-[^\s)]+", sample):
        matches.add("ARISTA_EOS")
    if re.search(r"(?m)^;.*Configuration Editor;.*release\s+#", sample):
        matches.add("HP_PROCURVE")
    if (re.search(r"(?m)^set version\s+\"?6\.\d", sample)
            and re.search(r"(?m)^set chassis\s+", sample)):
        matches.add("SCREENOS")
    if (re.search(r"(?m)^set version\s+\d+\.\d+R\d+", sample)
            and re.search(r"(?m)^set system\s+", sample)):
        matches.add("JUNOS")
    if (re.search(r"<config\b[^>]*\bversion=", sample)
            and re.search(r"<(?:mgt-config|devices|shared)\b", sample)):
        matches.add("PAN_OS")

    cisco_style = (
        re.search(r"(?m)^version\s+\d+\.\d+", sample)
        and re.search(r"(?m)^(?:line (?:vty|con|aux)\b|ip http\b|ip ssh\b)", sample)
    )
    if cisco_style:
        if re.search(r"Cisco IOS XE Software|(?m:^version\s+1[67]\.)", sample):
            matches.add("IOS_XE")
        elif re.search(r"Cisco IOS Software|(?m:^version\s+12\.)", sample):
            matches.add("IOS_ROUTER")
        else:
            raise DeviceDetectionError(
                "Cisco IOS and IOS-XE cannot be distinguished reliably from this export; "
                "choose -d cisco-ios or -d cisco-ios-xe."
            )

    if len(matches) == 1:
        return matches.pop()
    if matches:
        raise DeviceDetectionError(
            "Input contains conflicting device-family signatures; choose -d explicitly."
        )
    raise DeviceDetectionError(
        "Could not identify this configuration confidently; choose -d explicitly "
        "(run --help for recommended names)."
    )
