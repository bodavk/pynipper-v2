from .analyze_asa_device import analyze_asa_device


def analyze_cisco_asa_device(device, input_filename, output_filename, output_type, configuration, online):
    """Compatibility wrapper for the former second ASA analyzer."""

    return analyze_asa_device(
        device, input_filename, output_filename, output_type, configuration, online
    )
