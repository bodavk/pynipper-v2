import os

from ..error.files_errors import DeviceConfigurationFileNotFound
from ..devices.registry import get_device_definition


def analyze_device(device, input_filename, output_filename, output_type, configuration, online) -> None:

    # Check configuration file exists
    if not os.path.isfile(input_filename) and not os.path.isdir(input_filename):
        raise DeviceConfigurationFileNotFound(
            "ERROR: Device configuration file/directory doesn't exists")

    definition = get_device_definition(device)
    analyzer = definition.load_analyzer()
    analyzer(device, input_filename, output_filename, output_type, configuration, online)

