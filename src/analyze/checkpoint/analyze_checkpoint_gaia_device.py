import os

from src.advisories import software_advisories
from src.devices import get_parser
from src.error.files_errors import PynipperConfigurationFileNotFound
from src.report.coverage import build_report_context
from src.report.report import generate_report
from .core.process_checkpoint_gaia_conf import process_checkpoint_gaia_conf


def analyze_checkpoint_gaia_device(device, input_filename, output_filename, output_type, configuration, online,
                                   assessment_context=None, advisory_request=None):
    print("[1/4] Initializing pynipper-ng (Check Point Gaia OS)")
    parser = get_parser(device, input_filename)
    if assessment_context is not None:
        parser.set_assessment_context(assessment_context)
    if not os.path.isfile(configuration):
        raise PynipperConfigurationFileNotFound("ERROR: Pynipper configuration file doesn't exists")

    print("[2/4] Software advisories")
    vulns, advisory_status = software_advisories(device, parser, advisory_request)

    print("[3/4] Checking misconfiguration vulnerabilities")
    issues = process_checkpoint_gaia_conf(parser)

    data = {
        "hostname": parser.get_hostname(),
        "device-type": str(device),
        "assessment-policy": parser.assessment_context.to_dict(),
    }
    data.update(build_report_context(parser))
    data["software-advisories"] = advisory_status

    print("[4/4] Generating report")
    generate_report(output_type, output_filename, issues, vulns, data)
