"""python -m src.anonymize; the same CLI as scripts/anonymize_config.py."""
from __future__ import annotations

import argparse
import json
import sys

from src.devices.common.anonymization import AnonymizationError
from src.devices.registry import get_recommended_device_choices
from .service import prepare_file


class PrivateArguments(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error can echo supplied client filenames/arguments.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid arguments; use --help for the supported options.\n")


def main(argv=None) -> int:
    parser = PrivateArguments(
        description="Prepare offline pseudonymized configuration samples; never install output on a device.",
        epilog="Initial bounded adapters: FortiOS, Cisco IOS/IOS-XE and ASA. Unknown syntax blocks output. "
               "Other audit families are not anonymization-supported yet. No guarantees of anonymity or identical findings.",
    )
    parser.add_argument("-i", "--input", required=True, help="Local native UTF-8 text export")
    parser.add_argument("-d", "--device", default="auto", help="Family or alias; audit selectors: " + ", ".join(get_recommended_device_choices()))
    parser.add_argument("--output-dir", help="NEW shareable package directory; originals are never modified")
    parser.add_argument("--check-only", action="store_true", help="Check supported syntax/mapping without writing files")
    args = parser.parse_args(argv)
    try:
        summary = prepare_file(args.input, args.device, args.output_dir, check_only=args.check_only)
    except AnonymizationError as error:
        print(f"Blocked: {error}. No approved package was produced.", file=sys.stderr)
        return 2
    except (OSError, ValueError):
        # No exception string: OS errors often include customer filenames.
        print("I/O failure: input could not be read or new output could not be safely written. "
              "Any incomplete directory is not approved for sharing.", file=sys.stderr)
        return 3
    print(json.dumps(summary, indent=2))
    if args.check_only:
        print("Check completed; no files written.")
    else:
        print("Prepared config.conf and sanitization-summary.json. Review both and obtain owner approval before sharing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
