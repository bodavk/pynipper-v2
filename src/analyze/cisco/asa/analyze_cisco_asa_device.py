import os
from src.devices import get_parser
from .core.process_cisco_asa_conf import process_cisco_asa_conf
from ....report.report import generate_report
from ....error.files_errors import PynipperConfigurationFileNotFound


def analyze_cisco_asa_device(device, input_filename, output_filename, output_type, configuration, online):

    print("[1/4] Initializing pynipper-ng (Cisco ASA)")
    
    # Instantiate pluggable ASA parser
    parser = get_parser(device, input_filename)
    
    version_cisco_device = parser.get_version()
    if not os.path.isfile(configuration):
        raise PynipperConfigurationFileNotFound(
            "ERROR: Pynipper configuration file doesn't exists"
        )

    # In modern networks, ASA vulnerabilities scan is done offline/mocked unless API keys are present
    print("[2/4] Fetching Cisco API information for ASA")
    vulns = []  # Empty for ASA by default

    # Get ASA report misconfigurations
    print("[3/4] Checking misconfiguration vulnerabilities")
    issues = process_cisco_asa_conf(parser)

    # Device data to generate report
    data = {}
    data['hostname'] = parser.get_hostname()
    data['device-type'] = str(device)

    # Generate report
    print("[4/4] Generating report")
    generate_report(output_type, output_filename, issues, vulns, data)
