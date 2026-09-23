"""Public analyzer for saved BIG-IP TMOS tmsh/SCF text."""

import os

from src.common.assessment import AssessmentContext
from src.devices import get_parser
from src.devices.f5.bigip import F5ParseError
from src.error.files_errors import PynipperConfigurationFileNotFound
from src.report.coverage import build_parse_error_context, build_report_context
from src.report.report import generate_report
from .core.process_bigip_conf import process_bigip_conf


def analyze_bigip_device(device, input_filename, output_filename, output_type,
                         configuration, online, assessment_context=None) -> int:
    try:
        parser = get_parser(device, input_filename)
    except F5ParseError as error:
        context = assessment_context or AssessmentContext()
        data = {
            "hostname": "unknown",
            "device-type": str(device),
            "assessment-policy": context.to_dict(),
            **build_parse_error_context(str(device), "F5BIGIPParser", error.line_number,
                                        context.excluded_categories),
        }
        generate_report(output_type, output_filename, {}, [], data)
        print(f"BIG-IP configuration parsing failed at line {error.line_number}; checks were not run.")
        return 2
    if assessment_context is not None:
        parser.set_assessment_context(assessment_context)
    if not os.path.isfile(configuration):
        raise PynipperConfigurationFileNotFound("ERROR: Pynipper configuration file doesn't exist")
    findings = process_bigip_conf(parser)
    data = {
        "hostname": parser.get_hostname(),
        "device-type": str(device),
        "assessment-policy": parser.assessment_context.to_dict(),
        **build_report_context(parser),
    }
    generate_report(output_type, output_filename, findings, [], data)
    return 0
