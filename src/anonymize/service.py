"""Input-preserving, network-free sample preparation and output publication."""
from __future__ import annotations

import csv
from functools import partial
import io
import json
import os
from pathlib import Path
import re
import subprocess

from src.devices.common.anonymization import AnonymizationError
from src.devices.registry import get_device_definition
from src.devices.detection import detect_device_type, DeviceDetectionError
from src.devices.cisco.anonymization import build_plan as cisco_plan
from src.devices.fortinet.anonymization import build_plan as fortios_plan
from .engine import MAX_INPUT_BYTES, render


ADAPTER_VERSION = "1"
# Capability registrations, not another device catalogue. PIX is intentionally
# absent: sharing an audit parser does not qualify its export rewrite dialect.
ADAPTERS = {
    "FORTIOS": fortios_plan,
    "IOS_ROUTER": cisco_plan,
    "IOS_SWITCH": cisco_plan,
    "IOS_CATALYST": cisco_plan,
    "IOS_XE": cisco_plan,
    "ASA": partial(cisco_plan, asa=True),
}


def anonymize_text(source: str, device: str) -> tuple[str, dict]:
    """Private library boundary; source data never appears in public errors."""
    if not isinstance(source, str):
        raise AnonymizationError("input must be UTF-8 text")
    try:
        size = len(source.encode("utf-8"))
    except UnicodeError:
        raise AnonymizationError("input must be supported UTF-8 text") from None
    if size > MAX_INPUT_BYTES or source.count("\n") > 100_000:
        raise AnonymizationError("input size or statement budget exceeded")
    if any((ord(char) < 32 and char not in "\t\r\n\x03") or char in "\x85\u2028\u2029" for char in source):
        raise AnonymizationError("unsupported control character")
    try:
        canonical = get_device_definition(device).canonical_id
    except ValueError:
        raise AnonymizationError("unknown device selector; see --help") from None
    adapter = ADAPTERS.get(canonical)
    if adapter is None:
        raise AnonymizationError("anonymization is not implemented for this device family")
    plan = adapter(source)
    result, summary = render(source, plan)
    # Revalidate the entire transformed source with the same strict grammar.
    # This does not certify cross-control or credential equivalence.
    adapter(result)
    if source.count("\n") != result.count("\n"):
        raise AnonymizationError("physical line preservation failed")
    summary.update({"device": canonical, "adapter-version": ADAPTER_VERSION,
                    "grammar-validation": "passed",
                    "share-review": "Owner authorization and human review are still required."})
    return result, summary


def _restrict_directory(path: Path) -> bool:
    """Restrict Windows directory inheritance before ANY file is written.

    Unlike report-file cleanup this never deletes files, even on failure.
    """
    if os.name != "nt":
        return True
    try:
        arguments = {"capture_output": True, "text": True, "check": False,
                     "creationflags": subprocess.CREATE_NO_WINDOW, "timeout": 15}
        identity = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], **arguments)
        rows = list(csv.reader(io.StringIO(identity.stdout.strip())))
        if (identity.returncode != 0 or len(rows) != 1 or len(rows[0]) != 2
                or not re.fullmatch(r"S-1-(?:\d+-)+\d+", rows[0][1])):
            return False
        secured = subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                                  f"*{rows[0][1]}:(OI)(CI)F"], **arguments)
        return secured.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _prepare_file(input_file: str | Path, device: str | None, output_dir: str | Path | None,
                  *, check_only: bool = False) -> dict:
    """No original or partial content is written before qualification finishes."""
    # Reject explicit network paths before any existence check or resolution.
    for value in (input_file, output_dir):
        if value is None:
            continue
        raw = str(value)
        if raw.replace("\\", "/").startswith("//") or "://" in raw:
            raise AnonymizationError("only local filesystem paths are accepted")
        if os.name == "nt":
            import ctypes
            from pathlib import PureWindowsPath
            drive = PureWindowsPath(raw).drive or PureWindowsPath(os.getcwd()).drive
            get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
            get_drive_type.argtypes = [ctypes.c_wchar_p]
            get_drive_type.restype = ctypes.c_uint
            if not drive or get_drive_type(drive + "\\") in {0, 1, 4}:
                raise AnonymizationError("only known local drives are accepted")
    source_path = Path(input_file).resolve()
    if not source_path.is_file():
        raise AnonymizationError("expected a local native text export file; directory adapters are not implemented")
    destination = Path(output_dir).resolve() if output_dir is not None else None
    if not check_only:
        if destination is None:
            raise AnonymizationError("--output-dir is required unless --check-only is used")
        if destination.exists() or destination == source_path or source_path.is_relative_to(destination):
            raise AnonymizationError("output must be a new directory that does not contain the supplied input")
    if device is None or device == "auto":
        try:
            device = detect_device_type(str(source_path))
        except DeviceDetectionError:
            raise AnonymizationError("device type is ambiguous or unrecognized; supply -d explicitly") from None
    with source_path.open("rb") as stream:
        data = stream.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise AnonymizationError("input size budget exceeded")
    try:
        source = data.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        raise AnonymizationError("input must be a supported UTF-8 text export") from None
    result, summary = anonymize_text(source, device)
    if check_only:
        return summary
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(mode=0o700)
    if not _restrict_directory(destination):
        raise PermissionError("output directory permissions could not be restricted; no files were written")
    # Summary is the completion marker, written LAST. On failure leave the
    # directory intact and unapproved, never delete or overwrite anything.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination / "config.conf", flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
        stream.write(result)
        stream.flush()
        os.fsync(stream.fileno())
    # Reserve the final marker exclusively. It stays empty on any pending-write
    # failure. Only replace our own empty reservation after the prepared summary
    # has been completely flushed/fsynced. No supplied/existing file is replaced.
    final_marker = destination / "sanitization-summary.json"
    pending_marker = destination / "sanitization-summary.pending"
    descriptor = os.open(final_marker, flags, 0o600)
    reservation = os.fstat(descriptor)
    os.close(descriptor)
    descriptor = os.open(pending_marker, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
        stream.write(json.dumps(summary, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    current = final_marker.lstat()
    if (current.st_dev, current.st_ino, current.st_size) != (reservation.st_dev, reservation.st_ino, 0):
        raise PermissionError("completion marker reservation changed; package is not approved")
    if not pending_marker.resolve().is_relative_to(destination) or not final_marker.resolve().is_relative_to(destination):
        raise PermissionError("completion marker escaped its private directory")
    os.replace(pending_marker, final_marker)
    return summary


def prepare_file(input_file: str | Path, device: str | None, output_dir: str | Path | None,
                 *, check_only: bool = False) -> dict:
    """Public file boundary also sanitizes OS exceptions containing filenames."""
    try:
        return _prepare_file(input_file, device, output_dir, check_only=check_only)
    except OSError:
        raise OSError("local input or protected output access failed; no approved package was produced") from None
