"""Explicit advisory acquisition, separate from configuration auditing."""

import argparse
from pathlib import Path

from src.devices.registry import get_device_definition
from .service import AdvisoryRequest, api_key_from, lookup_software_advisories


def main(argv=None):
    parser = argparse.ArgumentParser(description="Download public advisory data without reading device configurations.")
    parser.add_argument("command", choices=["fetch"])
    parser.add_argument("--device", "-d", required=True)
    parser.add_argument("--software-version", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--configuration", "-c", help="Optional NVD API-key configuration file")
    parser.add_argument("--module", action="append", default=[], help="Provisioned F5 module, repeat as needed (for example ltm, apm)")
    args = parser.parse_args(argv)
    try:
        device = get_device_definition(args.device).canonical_id
    except ValueError as error:
        parser.error(str(error))
    if Path(args.output).exists():
        parser.error("--output must be a new file")
    _, status = lookup_software_advisories(device, args.software_version, AdvisoryRequest(
        online=True, save_path=args.output, api_key=api_key_from(args.configuration)),
        modules={module: "nominal" for module in args.module} or None)
    print(f"Advisory acquisition: {status['status']}")
    if status.get("reason"):
        print(status["reason"])
    if status.get("save-error"):
        print(status["save-error"])
    return 0 if status.get("saved-bundle") else 1


if __name__ == "__main__":
    raise SystemExit(main())
