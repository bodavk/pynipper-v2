"""SC-060: CIS F5 follow-ups (remote auth fallback, remote-user console access)."""

import contextlib
import io

from src.analyze.common.guidance import guidance_for
from src.analyze.f5.core.process_bigip_conf import process_bigip_conf
from src.devices.f5.bigip import F5BIGIPParser


def _ids(tmp_path, content):
    path = tmp_path / "device.scf"
    path.write_text("sys global-settings {\n    hostname bigip.example.test\n}\n" + content, encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        return {f.rule_id for f in process_bigip_conf(F5BIGIPParser(str(path))).values()}


def test_fallback_and_console_access(tmp_path):
    ids = _ids(tmp_path, "auth source {\n    fallback true\n    type tacacs\n}\n"
                         "auth remote-user {\n    remote-console-access tmsh\n}\n")
    assert {"f5.bigip.auth.remote_fallback_local", "f5.bigip.auth.remote_console_access"} <= ids
    assert guidance_for("f5.bigip.auth.remote_fallback_local") and guidance_for("f5.bigip.auth.remote_console_access")


def test_safe_values(tmp_path):
    ids = _ids(tmp_path, "auth source {\n    fallback false\n    type tacacs\n}\n"
                         "auth remote-user {\n    remote-console-access disabled\n}\n")
    assert not {"f5.bigip.auth.remote_fallback_local", "f5.bigip.auth.remote_console_access"} & ids


def test_ssh_include_weak_algorithms(tmp_path):
    ids = _ids(tmp_path, 'sys sshd {\n    include "Ciphers aes128-cbc,aes256-ctr\nMACs hmac-sha1,hmac-sha2-256"\n}\n')
    assert "f5.bigip.ssh.weak_algorithms" in ids and guidance_for("f5.bigip.ssh.weak_algorithms")
    assert "f5.bigip.ssh.weak_algorithms" not in _ids(
        tmp_path, 'sys sshd {\n    include "Ciphers aes256-gcm@openssh.com\nMACs hmac-sha2-256"\n}\n')
