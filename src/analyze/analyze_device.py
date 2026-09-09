import os

from ..error.files_errors import DeviceConfigurationFileNotFound

from .cisco.ios.analyze_cisco_device import analyze_cisco_device
from .cisco.asa.analyze_asa_device import analyze_asa_device
from .cisco.iosxe.analyze_iosxe_device import analyze_iosxe_device
from .checkpoint.analyze_checkpoint_fw1_device import analyze_checkpoint_fw1_device
from .juniper.analyze_juniper_device import analyze_juniper_device
from .juniper.junos.analyze_junos_device import analyze_junos_device
from .sonicwall.analyze_sonicwall_device import analyze_sonicwall_device
from .hp.analyze_hp_device import analyze_hp_device
from .paloalto.analyze_panos_device import analyze_panos_device
from .fortinet.analyze_fortinet_device import analyze_fortinet_device
from .arista.analyze_arista_device import analyze_arista_device


def analyze_device(device, input_filename, output_filename, output_type, configuration, online) -> None:

    # Check configuration file exists
    if not os.path.isfile(input_filename) and not os.path.isdir(input_filename):
        raise DeviceConfigurationFileNotFound(
            "ERROR: Device configuration file/directory doesn't exists")

    device_str = str(device).upper()

    if "ASA" in device_str:
        analyze_asa_device(device, input_filename, output_filename, output_type, configuration, online)
    elif "IOS_XE" in device_str:
        analyze_iosxe_device(device, input_filename, output_filename, output_type, configuration, online)
    elif "CHECKPOINT" in device_str:
        analyze_checkpoint_fw1_device(device, input_filename, output_filename, output_type, configuration, online)
    elif "SCREENOS" in device_str:
        analyze_juniper_device(device, input_filename, output_filename, output_type, configuration, online)
    elif "JUNOS" in device_str:
        analyze_junos_device(device, input_filename, output_filename, output_type, configuration, online)
    elif "SONICOS" in device_str:
        analyze_sonicwall_device(device, input_filename, output_filename, output_type, configuration, online)
    elif "HP_PROCURVE" in device_str:
        analyze_hp_device(device, input_filename, output_filename, output_type, configuration, online)
    elif "PAN_OS" in device_str:
        analyze_panos_device(device, input_filename, output_filename, output_type, configuration, online)
    elif "FORTIOS" in device_str:
        analyze_fortinet_device(device, input_filename, output_filename, output_type, configuration, online)
    elif "ARISTA_EOS" in device_str:
        analyze_arista_device(device, input_filename, output_filename, output_type, configuration, online)
    else:
        # Default to Cisco IOS
        analyze_cisco_device(device, input_filename, output_filename, output_type, configuration, online)

