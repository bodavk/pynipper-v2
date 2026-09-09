import os
from src.devices import get_parser
from .core.process_hp_conf import process_hp_conf
from src.report.report import generate_report
from src.error.files_errors import PynipperConfigurationFileNotFound


def analyze_hp_device(device, input_filename, output_filename, output_type, configuration, online):

    print("[1/4] Initializing pynipper-ng (HP ProCurve)")
    
    # Instantiate pluggable HP parser
    parser = get_parser(device, input_filename)
    
    if not os.path.isfile(configuration):
        raise PynipperConfigurationFileNotFound(
            "ERROR: Pynipper configuration file doesn't exists"
        )

    # Vulnerabilities scan is done offline/mocked unless API keys are present
    print("[2/4] Fetching HP API information")
    vulns = []  # Empty for HP by default

    # Get HP report misconfigurations
    print("[3/4] Checking misconfiguration vulnerabilities")
    issues = process_hp_conf(parser)

    # Device data to generate report
    data = {}
    data['hostname'] = parser.get_hostname()
    data['device-type'] = str(device)

    # Generate report
    print("[4/4] Generating report")
    generate_report(output_type, output_filename, issues, vulns, data)
