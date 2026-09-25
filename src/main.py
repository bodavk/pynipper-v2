import argparse
import os
import sys
from dataclasses import replace
from pathlib import Path

from typing import List
from typing import Optional

from .common.banner import display_banner
from .devices.registry import (
    get_device_definition, get_recommended_device_choices,
    get_recommended_device_groups,
)
from .devices.detection import DeviceDetectionError, detect_device_type
from .report.secret_evidence import SUPPORTED_SECRET_REPORT_DEVICES
from .report.common.types import ReportType
from .analyze.analyze_device import analyze_device
from .common.assessment import AssessmentContext
from .advisories.service import AdvisoryRequest, api_key_from


def main(argv: Optional[List[str]] = None) -> int:

    display_banner()

    recommended_devices = ", ".join(get_recommended_device_choices())
    device_help = "\n".join(
        f"  {group + ':':<11} {', '.join(choices)}"
        for group, choices in get_recommended_device_groups()
    )
    report_type_list = [report.name for report in ReportType]

    parser = argparse.ArgumentParser(
        description="Static security analysis for exported network-device configurations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            f"Recommended -d names:\n{device_help}\n"
            "Legacy IDs remain accepted. Auto-detection stops when the export is ambiguous."
        )
    )

    parser.add_argument('--device', '-d', help="Configuration family (default: auto). Use -d explicitly when auto cannot identify an export.",
                        dest="device_type", action="store", default="auto"
                        )
    parser.add_argument('--input', '-i', help="Configuration file, or export directory for supported devices",
                        dest="input_file", action="store",
                        type=str, required=True
                        )
    parser.add_argument('--output-filename', '-f', help="Report filename",
                        dest="output_file", action="store",
                        type=str
                        )
    parser.add_argument('--output-type', '-o', help="Report type",
                        dest="output_type", action="store",
                        choices=report_type_list, default=ReportType.HTML._name_
                        )
    parser.add_argument('--configuration', '-c', help="Configuration file",
                        dest="conf_file", action="store", type=str,
                        default=os.path.dirname(os.path.abspath(__file__)) + "/common/default.conf"
                        )
    parser.add_argument('--offline', '-x',
                        help="Disable the Cisco openVuln advisory lookup (NVD lookups are opt-in via --cve-lookup)",
                        dest="offline", action='store_true'
                        )
    parser.add_argument('--cve-lookup', action='store_true',
                        help="Opt in: look up CVEs for the configured software release in the NVD API "
                             "(sends only the product and version to NVD)")
    parser.add_argument('--cve-data', dest="cve_data", metavar="FILE",
                        help="Use a saved NVD bundle (from --cve-save) instead of querying NVD")
    parser.add_argument('--cve-save', dest="cve_save", metavar="FILE",
                        help="With --cve-lookup, save the NVD responses to a new file for offline replay")
    parser.add_argument('--software-version', dest="software_version", metavar="RELEASE",
                        help="Exact running release for the CVE lookup when the export only states a train "
                             "(for example 17.9.4a)")
    parser.add_argument('--assessment-policy',
                        help="Optional JSON assessment policy with explicit roles and exclusions",
                        dest="assessment_policy", action="store", type=str
                        )
    parser.add_argument('--show-secrets', action='store_true',
                        help="Opt in to unmasked credential source lines in the report; supported families only, new output file and secure directory recommended")

    args = parser.parse_args(argv)

    args_dict = vars(args)
    if args_dict["show_secrets"] and not args_dict["output_file"]:
        parser.error("--show-secrets requires an explicit -f output path")
    args_dict["output_file"] = args_dict["output_file"] or "./report.html"

    if args_dict["device_type"].strip().casefold() == "auto":
        try:
            args_dict["device_type"] = detect_device_type(args_dict["input_file"])
        except DeviceDetectionError as error:
            parser.error(str(error))
        except OSError:
            parser.error("Could not read input for automatic identification; check -i.")
        print(f"Detected configuration family: {args_dict['device_type']}")
    else:
        try:
            args_dict["device_type"] = get_device_definition(
                args_dict["device_type"]
            ).canonical_id
        except ValueError:
            parser.error(f"Unknown device family. Recommended names: {recommended_devices}")

    output_path = Path(args_dict["output_file"])
    if output_path.resolve() == Path(args_dict["input_file"]).resolve():
        parser.error("Report output path must differ from the input configuration")

    if args_dict["show_secrets"]:
        if args_dict["device_type"] not in SUPPORTED_SECRET_REPORT_DEVICES:
            parser.error("--show-secrets is not supported for this family; normal reports remain masked")
        if output_path.exists():
            parser.error("--show-secrets requires a new output path and cannot overwrite an existing report")
        print(
            "WARNING: the report will contain unmasked credential source lines. "
            "Store and share it as sensitive material.",
            file=sys.stderr,
        )

    if args_dict["cve_lookup"] and args_dict["offline"]:
        parser.error("--cve-lookup queries NVD and cannot be combined with -x/--offline")
    if args_dict["cve_lookup"] and args_dict["cve_data"]:
        parser.error("use either --cve-lookup or --cve-data, not both")
    if args_dict["cve_save"] and not args_dict["cve_lookup"]:
        parser.error("--cve-save requires --cve-lookup")
    if args_dict["cve_save"] and Path(args_dict["cve_save"]).exists():
        parser.error("--cve-save requires a new file and does not overwrite an existing one")
    if args_dict["cve_data"] and not Path(args_dict["cve_data"]).is_file():
        parser.error("--cve-data file does not exist")
    if args_dict["software_version"] and not (args_dict["cve_lookup"] or args_dict["cve_data"]):
        parser.error("--software-version is only used with --cve-lookup or --cve-data")
    advisory_request = AdvisoryRequest(
        online=args_dict["cve_lookup"],
        bundle_path=args_dict["cve_data"],
        save_path=args_dict["cve_save"],
        software_version=(args_dict["software_version"] or "").strip() or None,
        api_key=api_key_from(args_dict["conf_file"]) if args_dict["cve_lookup"] else None,
    )

    assessment_context = (
        AssessmentContext.from_file(args_dict["assessment_policy"])
        if args_dict["assessment_policy"]
        else AssessmentContext()
    )
    if args_dict["show_secrets"]:
        assessment_context = replace(assessment_context, report_secret_evidence=True)
    result = analyze_device(args_dict["device_type"], args_dict["input_file"], args_dict["output_file"],
                   args_dict["output_type"], args_dict["conf_file"], not args_dict["offline"],
                   assessment_context,
                   # Only passed when requested, so default runs keep the original call.
                   **({"advisory_request": advisory_request} if advisory_request.requested else {})
                   )

    return result or 0


if __name__ == "__main__":
    raise SystemExit(main())
