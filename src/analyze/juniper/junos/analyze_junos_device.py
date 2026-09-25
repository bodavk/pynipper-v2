import os
from src.advisories import software_advisories
from src.devices import get_parser
from .core.process_junos_conf import process_junos_conf
from src.report.report import generate_report
from src.report.coverage import build_report_context
from src.error.files_errors import PynipperConfigurationFileNotFound


def analyze_junos_device(device, input_filename, output_filename, output_type, configuration, online, assessment_context=None, advisory_request=None):

    print("[1/4] Initializing pynipper-ng (Juniper JunOS)")
    
    # Instantiate pluggable JunOS parser
    parser = get_parser(device, input_filename)
    if assessment_context is not None:
        parser.set_assessment_context(assessment_context)
    
    if not os.path.isfile(configuration):
        raise PynipperConfigurationFileNotFound(
            "ERROR: Pynipper configuration file doesn't exists"
        )

    # Vulnerabilities scan is done offline/mocked unless API keys are present
    print("[2/4] Fetching JunOS API information")
    vulns, advisory_status = software_advisories(device, parser, advisory_request)

    # Get JunOS report misconfigurations
    print("[3/4] Checking misconfiguration vulnerabilities")
    issues = process_junos_conf(parser)

    # Device data to generate report
    data = {}
    data['hostname'] = parser.get_hostname()
    data['device-type'] = str(device)
    data['assessment-policy'] = parser.assessment_context.to_dict()
    data.update(build_report_context(parser))
    data['software-advisories'] = advisory_status

    # Generate report
    print("[4/4] Generating report")
    generate_report(output_type, output_filename, issues, vulns, data)
