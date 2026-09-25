
from src.advisories import software_advisories
import os

from src.devices import get_parser
from .api.cisco_ios_vulns_service import get_api_vulnerabilities
from .core.process_cisco_ios_conf import process_cisco_ios_conf

from ....report.report import generate_report
from src.report.coverage import build_report_context
from ....error.files_errors import PynipperConfigurationFileNotFound


def analyze_cisco_device(device, input_filename, output_filename, output_type, configuration, online, assessment_context=None, advisory_request=None):

    print("[1/4] Initializing pynipper-ng")
    
    # Instantiate pluggable parser
    parser = get_parser(device, input_filename)
    if assessment_context is not None:
        parser.set_assessment_context(assessment_context)
    
    version_cisco_device = parser.get_version()
    if not os.path.isfile(configuration):
        raise PynipperConfigurationFileNotFound(
            "ERROR: Pynipper configuration file doesn't exists"
        )

    # Get vulns by Cisco API
    print("[2/4] Fetching Cisco API information")
    vulns = get_api_vulnerabilities(configuration, version_cisco_device, online)
    nvd_advisories, advisory_status = software_advisories(device, parser, advisory_request)
    vulns = list(vulns) + nvd_advisories

    # Get Cisco report missconfigurations
    print("[3/4] Checking missconfiguration vulnerabilities")
    issues = process_cisco_ios_conf(parser)

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
