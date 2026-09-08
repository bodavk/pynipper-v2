import re
from typing import Any
from ciscoconfparse import CiscoConfParse
from src.devices.common.base_parser import BaseDeviceParser


class CiscoASAParser(BaseDeviceParser):

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        # ciscoconfparse supports 'asa' syntax
        self.parser = CiscoConfParse(config_filepath, syntax='asa')

    def get_hostname(self) -> str:
        host = self.parser.find_objects("^hostname")
        if len(host) > 0:
            return host[0].re_match_typed(r'^hostname\s+(\S+)', default='')
        return "?"

    def get_version(self) -> str:
        # ASA version is typically at the top, e.g., "ASA Version 9.12(4)" or "version 9.12"
        version_line = self.parser.find_objects("^ASA Version")
        if len(version_line) > 0:
            return version_line[0].re_match_typed(r'^ASA Version\s+(\S+)', default='')
        
        # Fallback to standard version command
        version_line = self.parser.find_objects("^version")
        if len(version_line) > 0:
            return version_line[0].re_match_typed(r'^version\s+(\S+)', default='')
        
        return "?"

    def get_users(self) -> list[dict]:
        users = []
        user_lines = self.parser.find_objects("^username")
        for line in user_lines:
            text = line.text
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
        # Telnet in ASA is configured like: "telnet <ip> <mask> <interface>"
        telnet_lines = self.parser.find_objects("^telnet")
        services["telnet"] = len(telnet_lines) > 0

        # SSH in ASA: "ssh <ip> <mask> <interface>"
        ssh_lines = self.parser.find_objects("^ssh")
        services["ssh"] = len(ssh_lines) > 0

        # HTTP/HTTPS in ASA: "http server enable"
        http_server = self.parser.find_objects("^http server enable")
        services["http"] = len(http_server) > 0

        return services

    def get_raw_config(self) -> CiscoConfParse:
        return self.parser

    # Helper methods specific to ASA audit checks
    def get_enable_password(self) -> str:
        enable_line = self.parser.find_objects("^enable password")
        if len(enable_line) > 0:
            return enable_line[0].re_match_typed(r'^enable password\s+(\S+)', default='')
        return ""

    def get_snmp_communities(self) -> list[str]:
        communities = []
        snmp_lines = self.parser.find_objects("^snmp-server community")
        for line in snmp_lines:
            comm = line.re_match_typed(r'^snmp-server community\s+(\S+)', default='')
            if comm:
                communities.append(comm)
        return communities

    def get_ssh_hosts(self) -> list[dict]:
        hosts = []
        ssh_lines = self.parser.find_objects("^ssh ")
        for line in ssh_lines:
            match = re.search(r'^ssh\s+(\S+)\s+(\S+)\s+(\S+)', line.text)
            if match:
                hosts.append({
                    "ip": match.group(1),
                    "mask": match.group(2),
                    "interface": match.group(3)
                })
        return hosts

    def get_logging_enabled(self) -> bool:
        logging_lines = self.parser.find_objects("^logging enable")
        # In ASA, logging is explicitly enabled with "logging enable"
        return len(logging_lines) > 0

    def get_ssl_min_version(self) -> str:
        ssl_lines = self.parser.find_objects("^ssl minimum-version")
        if len(ssl_lines) > 0:
            return ssl_lines[0].re_match_typed(r'^ssl minimum-version\s+(\S+)', default='')
        return ""

    def get_interfaces(self) -> list[dict]:
        interfaces = []
        int_blocks = self.parser.find_objects("^interface")
        for block in int_blocks:
            name = block.re_match_typed(r'^interface\s+(\S+)', default='')
            nameif = ""
            sec_level = -1
            
            # Sub-commands under interface
            for child in block.children:
                if "nameif" in child.text:
                    nameif = child.re_match_typed(r'^\s*nameif\s+(\S+)', default='')
                elif "security-level" in child.text:
                    sec_level_str = child.re_match_typed(r'^\s*security-level\s+(\d+)', default='')
                    sec_level = int(sec_level_str) if sec_level_str else -1
            
            if nameif:
                interfaces.append({
                    "name": name,
                    "nameif": nameif,
                    "security_level": sec_level
                })
        return interfaces

    def get_acl_bindings(self) -> list[dict]:
        bindings = []
        # e.g., "access-group outside_access_in in interface outside"
        groups = self.parser.find_objects("^access-group")
        for group in groups:
            match = re.search(r'^access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)', group.text)
            if match:
                bindings.append({
                    "acl_name": match.group(1),
                    "direction": match.group(2),
                    "interface": match.group(3)
                })
        return bindings

    def get_acl_rules(self, acl_name: str) -> list[str]:
        # Fetch lines for specified access-list
        rules = []
        acl_lines = self.parser.find_objects(f"^access-list\\s+{acl_name}\\s")
        for line in acl_lines:
            rules.append(line.text)
        return rules
