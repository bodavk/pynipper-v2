"""Pure-Python verification of Unix crypt(3) password hashes ($1$, $5$, $6$).

Used only to recognise vendor-documented default passwords in exported hashes
(for example F5 BIG-IP ``admin``/``admin``, K13121). It never searches other values.
Implements the MD5-crypt and the Ulrich Drepper SHA-crypt algorithms, so it works
on every platform without the removed ``crypt`` module.
"""

from __future__ import annotations

import hashlib
import hmac
import re

_ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_HASH = re.compile(r"^\$(1|5|6)\$(?:rounds=(\d+)\$)?([^$]{0,16})\$([./0-9A-Za-z]+)$")


def _b64_from_24bit(b2: int, b1: int, b0: int, n: int) -> str:
    w = (b2 << 16) | (b1 << 8) | b0
    out = []
    for _ in range(n):
        out.append(_ITOA64[w & 0x3F])
        w >>= 6
    return "".join(out)


def _md5_crypt(password: bytes, salt: bytes) -> str:
    magic = b"$1$"
    alt = hashlib.md5(password + salt + password).digest()
    ctx = hashlib.md5(password + magic + salt)
    length = len(password)
    while length > 0:
        ctx.update(alt[:min(16, length)])
        length -= 16
    i = len(password)
    while i:
        ctx.update(b"\0" if i & 1 else password[:1])
        i >>= 1
    final = ctx.digest()
    for i in range(1000):
        c = hashlib.md5()
        c.update(password if i & 1 else final)
        if i % 3:
            c.update(salt)
        if i % 7:
            c.update(password)
        c.update(final if i & 1 else password)
        final = c.digest()
    f = final
    encoded = (_b64_from_24bit(f[0], f[6], f[12], 4) + _b64_from_24bit(f[1], f[7], f[13], 4)
               + _b64_from_24bit(f[2], f[8], f[14], 4) + _b64_from_24bit(f[3], f[9], f[15], 4)
               + _b64_from_24bit(f[4], f[10], f[5], 4) + _b64_from_24bit(0, 0, f[11], 2))
    return f"$1${salt.decode()}${encoded}"


_SHA256_ORDER = [(0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14), (15, 25, 5),
                 (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29)]
_SHA512_ORDER = [(0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26),
                 (6, 27, 48), (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32),
                 (12, 33, 54), (34, 55, 13), (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38),
                 (18, 39, 60), (40, 61, 19), (62, 20, 41)]


def _sha_crypt(kind: str, password: bytes, salt: bytes, rounds: int | None) -> str:
    algorithm = hashlib.sha256 if kind == "5" else hashlib.sha512
    size = 32 if kind == "5" else 64
    effective_rounds = 5000 if rounds is None else max(1000, min(rounds, 999_999_999))
    b = algorithm(password + salt + password).digest()
    a = algorithm(password + salt)
    length = len(password)
    while length > size:
        a.update(b)
        length -= size
    a.update(b[:length])
    i = len(password)
    while i:
        a.update(b if i & 1 else password)
        i >>= 1
    a_digest = a.digest()
    dp = algorithm(password * len(password)).digest()
    p = (dp * (len(password) // size + 1))[:len(password)]
    ds = algorithm(salt * (16 + a_digest[0])).digest()
    s = (ds * (len(salt) // size + 1))[:len(salt)]
    c = a_digest
    for i in range(effective_rounds):
        ctx = algorithm()
        ctx.update(p if i & 1 else c)
        if i % 3:
            ctx.update(s)
        if i % 7:
            ctx.update(p)
        ctx.update(c if i & 1 else p)
        c = ctx.digest()
    if kind == "5":
        encoded = "".join(_b64_from_24bit(c[x], c[y], c[z], 4) for x, y, z in _SHA256_ORDER)
        encoded += _b64_from_24bit(0, c[31], c[30], 3)
    else:
        encoded = "".join(_b64_from_24bit(c[x], c[y], c[z], 4) for x, y, z in _SHA512_ORDER)
        encoded += _b64_from_24bit(0, 0, c[63], 2)
    rounds_part = f"rounds={rounds}$" if rounds is not None else ""
    return f"${kind}${rounds_part}{salt.decode()}${encoded}"


def crypt_matches(password: str, stored: str) -> bool:
    """True when ``stored`` ($1$, $5$ or $6$) is the crypt(3) hash of ``password``."""
    match = _HASH.match(stored.strip('"'))
    if not match:
        return False
    kind, rounds, salt = match.group(1), match.group(2), match.group(3).encode()
    secret = password.encode()
    if kind == "1":
        computed = _md5_crypt(secret, salt[:8])
    else:
        computed = _sha_crypt(kind, secret, salt, int(rounds) if rounds else None)
    return hmac.compare_digest(computed, stored.strip('"'))


__all__ = ["crypt_matches"]
