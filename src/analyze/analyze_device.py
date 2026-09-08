import os

from ..error.files_errors import DeviceConfigurationFileNotFound

from .cisco.ios.analyze_cisco_device import analyze_cisco_device
from .cisco.asa.analyze_asa_device import analyze_asa_device
from .checkpoint.analyze_checkpoint_fw1_device import analyze_checkpoint_fw1_device
from .juniper.analyze_juniper_device import analyze_juniper_device


def analyze_device(device, input_filename, output_filename, output_type, configuration, online) -> None:

    # Check configuration file exists
    if not os.path.isfile(input_filename) and not os.path.isdir(input_filename):
        raise DeviceConfigurationFileNotFound(
            "ERROR: Device configuration file/directory doesn't exists")

    device_str = str(device).upper()

    if "ASA" in device_str:
        analyze_asa_device(device, input_filename, output_filename, output_type, configuration, online)
    elif "CHECKPOINT" in device_str:
        analyze_checkpoint_fw1_device(device, input_filename, output_filename, output_type, configuration, online)
    elif "SCREENOS" in device_str:
        analyze_juniper_device(device, input_filename, output_filename, output_type, configuration, online)
    else:
        # Default to Cisco IOS
        analyze_cisco_device(device, input_filename, output_filename, output_type, configuration, online)
