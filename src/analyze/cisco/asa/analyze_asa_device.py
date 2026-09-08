import os
from src.devices import get_parser
from .core.process_asa_conf import process_asa_conf
from ....report.report import generate_report
from ....error.files_errors import PynipperConfigurationFileNotFound


def analyze_asa_device(device, input_filename, output_filename, output_type, configuration, online):

    print("[1/4] Initializing pynipper-ng (ASA)")
    
    # Instantiate pluggable parser
    parser = get_parser(device, input_filename)
    
    # ASA doesn't use the Cisco API for vulns in the same way IOS does (for now)
    # So we'll skip get_api_vulnerabilities or implement it later
    vulns = []

    # Get ASA report missconfigurations
    print("[3/4] Checking missconfiguration vulnerabilities")
    issues = process_asa_conf(parser)

    # Device data to generate report
    data = {}
    data['hostname'] = parser.get_hostname()
    data['device-type'] = str(device)

    # Generate report
    print("[4/4] Generating report")
    generate_report(output_type, output_filename, issues, vulns, data)
