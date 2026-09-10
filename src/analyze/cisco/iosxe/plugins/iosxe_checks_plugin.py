import re

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser


class PluginIOSXEChecks(BasePlugin):
    """IOS-XE-only MACsec and active cryptographic-suite checks."""

    CRYPTO_POLICY = "pynipper-2026-baseline-v1"
    _L2_INTERFACE_TYPES = (
        "Ethernet",
        "FastEthernet",
        "GigabitEthernet",
        "TenGigabitEthernet",
        "TwentyFiveGigE",
        "FortyGigabitEthernet",
        "HundredGigE",
        "Port-channel",
    )
    _WEAK_ENCRYPTION = {"des", "3des", "esp-des", "esp-3des"}
    _WEAK_INTEGRITY = {"md5", "sha", "sha1", "esp-md5-hmac", "esp-sha-hmac"}
    _WEAK_DH_GROUPS = {"1", "2", "5", "14", "15", "16"}

    @staticmethod
    def _children(parent) -> list[str]:
        return [child.text.strip() for child in parent.children]

    def _macsec_candidate(self, interface) -> bool:
        name = interface.re_match_typed(r"^interface\s+(\S+)", default="")
        if not name.startswith(self._L2_INTERFACE_TYPES):
            return False
        children = self._children(interface)
        if "shutdown" in children:
            return False
        return any(line == "switchport" or line.startswith("switchport ") for line in children)

    @staticmethod
    def _named_blocks(conf_parse, prefix: str) -> dict[str, object]:
        blocks = {}
        for block in conf_parse.find_objects(rf"^{re.escape(prefix)}\s+"):
            name = block.re_match_typed(rf"^{re.escape(prefix)}\s+(\S+)", default="")
            if name:
                blocks[name.lower()] = block
        return blocks

    def check_macsec(self, parser: BaseDeviceParser) -> None:
        conf_parse = parser.get_native_config()
        policies = self._named_blocks(conf_parse, "mka policy")
        key_chains = {
            name: block
            for name, block in self._named_blocks(conf_parse, "key chain").items()
            if re.fullmatch(r"key chain\s+\S+\s+macsec", block.text.strip())
        }

        for interface in conf_parse.find_objects(r"^interface\s+"):
            if not self._macsec_candidate(interface):
                continue
            children = self._children(interface)
            policy_match = next(
                (re.fullmatch(r"mka policy\s+(\S+)", line) for line in children if line.startswith("mka policy ")),
                None,
            )
            key_match = next(
                (
                    re.fullmatch(r"mka pre-shared-key key-chain\s+(\S+)", line)
                    for line in children
                    if line.startswith("mka pre-shared-key key-chain ")
                ),
                None,
            )
            policy_name = policy_match.group(1) if policy_match else ""
            key_name = key_match.group(1) if key_match else ""
            activation = next((line for line in children if re.fullmatch(r"macsec(?:\s+.*)?", line)), "")
            policy = policies.get(policy_name.lower())
            key_chain = key_chains.get(key_name.lower())
            configured_ciphers = (
                self._tokens_after(self._children(policy), "macsec-cipher-suite")
                if policy
                else set()
            )
            # IOS-XE uses GCM-AES-128 when no data-plane suite is overridden.
            effective_ciphers = configured_ciphers or {"gcm-aes-128"}
            approved_ciphers = {
                "gcm-aes-128",
                "gcm-aes-256",
                "gcm-aes-xpn-128",
                "gcm-aes-xpn-256",
            }
            cipher_valid = bool(effective_ciphers) and effective_ciphers <= approved_ciphers
            key_material_configured = bool(
                key_chain
                and any(
                    child.text.strip().startswith("key-string ")
                    for child in key_chain.all_children
                )
            )
            if activation and policy and key_chain and cipher_valid and key_material_configured:
                continue

            missing = []
            if not activation:
                missing.append("MACsec activation")
            if not policy_name:
                missing.append("MKA policy attachment")
            elif not policy:
                missing.append(f"defined MKA policy '{policy_name}'")
            elif not cipher_valid:
                missing.append(f"approved cipher suite in MKA policy '{policy_name}'")
            if not key_name:
                missing.append("MKA key-chain attachment")
            elif not key_chain or not key_material_configured:
                missing.append(f"defined MACsec key chain '{key_name}'")

            self.add_issue(
                Finding(
                    rule_id="cisco.iosxe.macsec.missing",
                    device=parser.device_type,
                    title="MACsec is incomplete on an active Layer-2 link",
                    observation=f"{interface.text.strip()} is in MACsec scope but lacks: {', '.join(missing)}.",
                    impact="Traffic on the Layer-2 link is not assured to have hop-by-hop integrity and confidentiality.",
                    severity=Severity.MEDIUM,
                    exploitability="An attacker with access to the local link may observe or alter unprotected frames.",
                    recommendation="Attach a valid MKA policy and MACsec key chain, select an approved cipher suite, and activate MACsec.",
                    evidence=(interface.text.strip(), *children),
                )
            )

    @staticmethod
    def _tokens_after(children: list[str], command: str) -> set[str]:
        values = set()
        for line in children:
            match = re.fullmatch(rf"{re.escape(command)}\s+(.+)", line)
            if match:
                values.update(token.lower() for token in match.group(1).split())
        return values

    def _ikev2_weaknesses(self, proposal) -> list[str]:
        children = self._children(proposal)
        encryption = self._tokens_after(children, "encryption")
        integrity = self._tokens_after(children, "integrity")
        prf = self._tokens_after(children, "prf")
        groups = self._tokens_after(children, "group")
        weaknesses = []
        if not encryption or encryption & self._WEAK_ENCRYPTION:
            weaknesses.append("missing or weak encryption")
        uses_gcm = any("gcm" in value for value in encryption)
        if not uses_gcm and (not integrity or integrity & self._WEAK_INTEGRITY):
            weaknesses.append("missing or weak integrity")
        if not prf or prf & self._WEAK_INTEGRITY:
            weaknesses.append("missing or weak PRF")
        if not groups or groups & self._WEAK_DH_GROUPS:
            weaknesses.append("missing or weak Diffie-Hellman group")
        return weaknesses

    def _add_crypto_finding(
        self,
        parser: BaseDeviceParser,
        rule_id: str,
        family: str,
        block,
        weaknesses: list[str],
    ) -> None:
        self.add_issue(
            Finding(
                rule_id=rule_id,
                device=parser.device_type,
                title=f"Active {family} suite violates the cryptographic baseline",
                observation=f"{block.text.strip()} uses {', '.join(weaknesses)} under policy {self.CRYPTO_POLICY}.",
                impact="Weak or incomplete cryptographic suites reduce confidentiality, integrity, or key-exchange strength.",
                severity=Severity.HIGH,
                exploitability="A capable on-path attacker may target legacy algorithms or weak key exchange.",
                recommendation="Use AES-GCM or AES-256, SHA-256 or stronger where required, a strong PRF, and DH group 19 or stronger.",
                evidence=(block.text.strip(), *self._children(block)),
            )
        )

    def check_legacy_crypto(self, parser: BaseDeviceParser) -> None:
        conf_parse = parser.get_native_config()

        proposals = self._named_blocks(conf_parse, "crypto ikev2 proposal")
        referenced_proposals = set()
        for policy in conf_parse.find_objects(r"^crypto ikev2 policy\s+"):
            referenced_proposals.update(self._tokens_after(self._children(policy), "proposal"))
        for name in sorted(referenced_proposals):
            proposal = proposals.get(name)
            if proposal is None:
                continue
            weaknesses = self._ikev2_weaknesses(proposal)
            if weaknesses:
                self._add_crypto_finding(
                    parser,
                    "cisco.iosxe.crypto.legacy_ikev2",
                    "IKEv2",
                    proposal,
                    weaknesses,
                )

        for policy in conf_parse.find_objects(r"^crypto (?:isakmp|ikev1) policy\s+"):
            children = self._children(policy)
            encryption = self._tokens_after(children, "encryption")
            integrity = self._tokens_after(children, "hash")
            groups = self._tokens_after(children, "group")
            weaknesses = []
            if not encryption or encryption & self._WEAK_ENCRYPTION:
                weaknesses.append("missing or weak encryption")
            if not integrity or integrity & self._WEAK_INTEGRITY:
                weaknesses.append("missing or weak hash")
            if not groups or groups & self._WEAK_DH_GROUPS:
                weaknesses.append("missing or weak Diffie-Hellman group")
            if weaknesses:
                self._add_crypto_finding(
                    parser,
                    "cisco.iosxe.crypto.legacy_ikev1",
                    "IKEv1",
                    policy,
                    weaknesses,
                )

        transform_sets = self._named_blocks(conf_parse, "crypto ipsec transform-set")
        referenced_transforms = set()
        for obj in conf_parse.find_objects(r"^crypto map\s+"):
            text = obj.text.strip()
            match = re.search(r"\bset transform-set\s+(.+)$", text)
            if match:
                referenced_transforms.update(match.group(1).split())
            referenced_transforms.update(self._tokens_after(self._children(obj), "set transform-set"))
        for name in sorted(referenced_transforms):
            transform = transform_sets.get(name)
            if transform is None:
                continue
            tokens = {token.lower() for token in transform.text.split()[4:]}
            weak = sorted(tokens & (self._WEAK_ENCRYPTION | self._WEAK_INTEGRITY))
            if weak:
                self._add_crypto_finding(
                    parser,
                    "cisco.iosxe.crypto.legacy_ipsec",
                    "IPsec transform-set",
                    transform,
                    [f"weak algorithms: {', '.join(weak)}"],
                )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_macsec(parser)
        self.check_legacy_crypto(parser)
