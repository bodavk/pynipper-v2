import re
from typing import Any
from ciscoconfparse import CiscoConfParse
from src.devices.common.base_parser import BaseDeviceParser


class CiscoIOSParser(BaseDeviceParser):

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        self.parser = CiscoConfParse(config_filepath, syntax='ios')

    def get_hostname(self) -> str:
        host = self.parser.find_objects("^hostname")
        if len(host) > 0:
            return host[0].re_match_typed(r'^hostname\s+(\S+)', default='')
        return "?"

    def get_version(self) -> str:
        regex = re.compile(r'.+\(.+\).*')
        version = self.parser.find_objects("^version")
        if len(version) > 0:
            version_number = version[0].re_match_typed(r'^version\s+(\S+)', default='')
            if not regex.search(version_number):
                version_number = version_number + '(1)'
            return version_number
        return "?"

    def get_users(self) -> list[dict]:
        users = []
        user_lines = self.parser.find_objects("^username")
        for line in user_lines:
            text = line.text
            # Simple match for username and optional privilege/password
            match_name = re.search(r'^username\s+(\S+)', text)
            if match_name:
                name = match_name.group(1)
                priv_match = re.search(r'privilege\s+(\d+)', text)
                priv = int(priv_match.group(1)) if priv_match else 1
                users.append({
                    "username": name,
                    "privilege": priv,
                    "raw_line": text
                })
        return users

    def get_services(self) -> dict:
        services = {}
        # Telnet
        transport_disable = self.parser.find_objects("transport input none")
        ssh_enable = self.parser.find_objects("transport input ssh")
        telnet_disable = self.parser.find_objects("no transport input telnet")
        if len(transport_disable) > 0 or len(ssh_enable) > 0 or len(telnet_disable) > 0:
            services["telnet"] = False
        else:
            services["telnet"] = True

        # HTTP / HTTPS
        http_enable = self.parser.find_objects("ip http server")
        http_disable = self.parser.find_objects("no ip http server")
        if len(http_enable) > 0:
            services["http"] = True
        elif len(http_disable) > 0:
            services["http"] = False
        else:
            services["http"] = True  # by default IOS Cisco devices have HTTP enabled

        return services

    def get_raw_config(self) -> CiscoConfParse:
        return self.parser

    # Keep classic helper functions as methods of the parser to facilitate transition
    def get_passwd_enc(self) -> bool:
        passwd_enc = self.parser.find_objects("no service password-encryption")
        return len(passwd_enc) > 0

    def get_passwd_length(self) -> str:
        passwd_length = self.parser.find_objects("security passwords min-length")
        if len(passwd_length) > 0:
            return passwd_length[0].re_match_typed(r'^security passwords min-length\s+(\S+)', default='')
        return "No specified"

    def get_ip_source_routing(self) -> bool:
        ip_src_routing = self.parser.find_objects("no ip source routing")
        return len(ip_src_routing) == 0

    def get_bootp(self) -> bool:
        bootp_server = self.parser.find_objects("no ip bootp server")
        return len(bootp_server) == 0

    def get_tcp_keep_alives_in(self) -> bool:
        keep_alives_in = self.parser.find_objects("service tcp-keepalives-in")
        return len(keep_alives_in) > 0

    def get_tcp_keep_alives_out(self) -> bool:
        keep_alives_out = self.parser.find_objects("service tcp-keepalives-out")
        return len(keep_alives_out) > 0
