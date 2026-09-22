import os
from src.devices import get_parser
from .core.process_fortios_conf import process_fortios_conf
from src.report.report import generate_report
from src.report.coverage import build_report_context, build_parse_error_context
from src.devices.fortinet.fortios import FortiOSParseError
from src.common.assessment import AssessmentContext
from src.error.files_errors import PynipperConfigurationFileNotFound


def analyze_fortinet_device(device, input_filename, output_filename, output_type, configuration, online, assessment_context=None):

    print("[1/4] Initializing pynipper-ng (Fortinet FortiOS)")
    
    # Instantiate pluggable Fortinet parser
    try:
        parser = get_parser(device, input_filename)
    except FortiOSParseError as error:
        context = assessment_context or AssessmentContext()
        data = {
            "hostname": "unknown",
            "device-type": str(device),
            "assessment-policy": context.to_dict(),
            **build_parse_error_context(str(device), "FortiOSParser", error.line_number, context.excluded_categories),
        }
        generate_report(output_type, output_filename, {}, [], data)
        print(f"Configuration parsing failed at line {error.line_number}; security checks were not run.")
        return 2
    if assessment_context is not None:
        parser.set_assessment_context(assessment_context)
    
    if not os.path.isfile(configuration):
        raise PynipperConfigurationFileNotFound(
            "ERROR: Pynipper configuration file doesn't exists"
        )

    # Vulnerabilities scan is done offline/mocked unless API keys are present
    print("[2/4] Fetching Fortinet API information")
    vulns = []  # Empty for FortiOS by default

    # Get FortiOS report misconfigurations
    print("[3/4] Checking misconfiguration vulnerabilities")
    issues = process_fortios_conf(parser)

    # Device data to generate report
    data = {}
    data['hostname'] = parser.get_hostname()
    data['device-type'] = str(device)
    data['assessment-policy'] = parser.assessment_context.to_dict()
    data.update(build_report_context(parser))

    # Generate report
    print("[4/4] Generating report")
    generate_report(output_type, output_filename, issues, vulns, data)
