"""Frase de paso (scrypt), TOTP (RFC 6238) y utilidades de sesión. Solo biblioteca estándar."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from typing import Optional

MIN_PASSPHRASE = 12
_SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)


# ---------------- frase de paso ----------------

def hash_passphrase(passphrase: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, **_SCRYPT)
    return digest.hex(), salt.hex()


def verify_passphrase(passphrase: str, hash_hex: str, salt_hex: str) -> bool:
    digest = hashlib.scrypt(passphrase.encode("utf-8"), salt=bytes.fromhex(salt_hex), **_SCRYPT)
    return hmac.compare_digest(digest.hex(), hash_hex)


# ---------------- TOTP ----------------

def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret_b32: str) -> bytes:
    pad = "=" * (-len(secret_b32) % 8)
    return base64.b32decode(secret_b32.upper() + pad)


def hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    mac = hmac.new(_key(secret_b32), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def current_step(now: float, period: int = 30) -> int:
    return int(now // period)


def find_totp_step(secret_b32: str, code: str, last_step: int, now: float,
                   window: int = 1, digits: int = 6) -> Optional[int]:
    """Devuelve el paso de tiempo en el que el código es válido y MAYOR que `last_step`
    (cada código se puede usar una sola vez), o None."""
    code = (code or "").strip().replace(" ", "")
    if len(code) != digits or not code.isdigit():
        return None
    base = current_step(now)
    found = None
    for delta in range(-window, window + 1):           # recorre todos: tiempo constante
        step = base + delta
        if hmac.compare_digest(hotp(secret_b32, step, digits), code) and step > last_step:
            found = step if found is None else max(found, step)
    return found


def otpauth_uri(secret_b32: str, account: str = "dani", issuer: str = "APE") -> str:
    return (f"otpauth://totp/{issuer}:{account}?secret={secret_b32}"
            f"&issuer={issuer}&algorithm=SHA1&digits=6&period=30")


# ---------------- sesiones ----------------

def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def csrf_for(token: str) -> str:
    return hmac.new(token.encode("utf-8"), b"ape-csrf", hashlib.sha256).hexdigest()
