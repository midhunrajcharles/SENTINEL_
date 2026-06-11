"""
SENTINEL: Autonomous Agentic SOC Commander
crypto_utils.py — Symmetric encryption for sensitive config values

Provides a thin wrapper around Fernet symmetric encryption with PBKDF2-derived
keys. Used by ConfigLoader to encrypt and decrypt API keys, passwords, and
tokens stored in conf files.

Key material is NEVER written to disk. The master secret must be supplied
via the SENTINEL_CRYPTO_KEY environment variable. If the variable is absent
the module operates in passthrough mode so development configs still work,
but emit a loud warning.

Dependencies: cryptography (in requirements.txt)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import struct
import time
from typing import Optional

log = logging.getLogger("sentinel.crypto_utils")

# Sentinel prefix that marks an encrypted value in a conf file so the loader
# knows to call decrypt() rather than return the raw string.
ENCRYPTED_PREFIX = "$enc$"

# Environment variable that holds the master key (plain text passphrase).
_ENV_KEY = "SENTINEL_CRYPTO_KEY"

# PBKDF2 parameters
_PBKDF2_ITERATIONS = 390_000   # OWASP 2023 minimum for PBKDF2-HMAC-SHA256
_PBKDF2_SALT_ENV   = "SENTINEL_CRYPTO_SALT"
_PBKDF2_SALT_DEFAULT = b"sentinel_default_salt_change_me_00"

# Fernet import is deferred so the module is importable even when
# `cryptography` is not installed — it just can't encrypt/decrypt in that case.
try:
    from cryptography.fernet import Fernet, InvalidToken
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False
    log.warning(
        "cryptography package not installed; encryption/decryption unavailable. "
        "Run: pip install cryptography"
    )


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte Fernet-compatible key from a passphrase via PBKDF2-HMAC-SHA256.
    Returns URL-safe base64-encoded 32 bytes (Fernet key format).
    """
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
        dklen=32,
    )
    return base64.urlsafe_b64encode(dk)


def _get_fernet() -> "Fernet":
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "cryptography package is required for encryption. "
            "Install it: pip install cryptography"
        )
    passphrase = os.environ.get(_ENV_KEY, "")
    if not passphrase:
        raise RuntimeError(
            f"Master encryption key not set. "
            f"Set the {_ENV_KEY} environment variable before using crypto_utils."
        )
    salt_raw = os.environ.get(_PBKDF2_SALT_ENV, "").encode("utf-8")
    salt = salt_raw if salt_raw else _PBKDF2_SALT_DEFAULT
    key = _derive_key(passphrase, salt)
    return Fernet(key)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encrypt(plaintext: str) -> str:
    """
    Encrypt a plaintext string and return an ``$enc$<ciphertext>`` string
    suitable for embedding in a Splunk .conf file value.

    Raises RuntimeError if the crypto key env var is not set.
    """
    fernet = _get_fernet()
    cipher_bytes = fernet.encrypt(plaintext.encode("utf-8"))
    return ENCRYPTED_PREFIX + cipher_bytes.decode("ascii")


def decrypt(value: str) -> str:
    """
    Decrypt a value previously produced by encrypt().
    If the value does not start with ``$enc$``, it is returned unchanged
    (passthrough for plaintext dev configs).

    Raises:
        MCPAuthError-style ValueError if the token is invalid or tampered.
        RuntimeError if the crypto key env var is not set.
    """
    if not value.startswith(ENCRYPTED_PREFIX):
        return value  # plaintext passthrough

    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "Cannot decrypt value: cryptography package not installed."
        )

    fernet = _get_fernet()
    cipher_bytes = value[len(ENCRYPTED_PREFIX):].encode("ascii")
    try:
        return fernet.decrypt(cipher_bytes).decode("utf-8")
    except Exception as exc:          # InvalidToken or decode error
        raise ValueError(
            "Failed to decrypt config value — key may have changed or "
            "the ciphertext is corrupted."
        ) from exc


def is_encrypted(value: str) -> bool:
    """Return True if the value was produced by encrypt()."""
    return isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX)


def decrypt_if_needed(value: str) -> str:
    """Convenience wrapper: decrypt only if the value looks encrypted."""
    if is_encrypted(value):
        return decrypt(value)
    return value


def rotate_key(old_passphrase: str, new_passphrase: str, ciphertext: str) -> str:
    """
    Re-encrypt a ciphertext under a new passphrase without exposing the
    intermediate plaintext longer than necessary.
    """
    salt_raw = os.environ.get(_PBKDF2_SALT_ENV, "").encode("utf-8")
    salt = salt_raw if salt_raw else _PBKDF2_SALT_DEFAULT

    old_key = _derive_key(old_passphrase, salt)
    new_key = _derive_key(new_passphrase, salt)

    old_fernet = Fernet(old_key)
    new_fernet = Fernet(new_key)

    stripped = ciphertext[len(ENCRYPTED_PREFIX):].encode("ascii")
    plaintext = old_fernet.decrypt(stripped)
    new_cipher = new_fernet.encrypt(plaintext)
    return ENCRYPTED_PREFIX + new_cipher.decode("ascii")


def hmac_sign(data: str, secret: Optional[str] = None) -> str:
    """
    Produce an HMAC-SHA256 hex digest for data integrity verification
    (e.g., signing audit log entries). Uses SENTINEL_CRYPTO_KEY if no
    explicit secret is passed.
    """
    key = (secret or os.environ.get(_ENV_KEY, "fallback_hmac_key")).encode("utf-8")
    sig = hmac.new(key, data.encode("utf-8"), hashlib.sha256)
    return sig.hexdigest()


def hmac_verify(data: str, signature: str, secret: Optional[str] = None) -> bool:
    """Constant-time HMAC verification."""
    expected = hmac_sign(data, secret)
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# CLI helper — encrypt a value from the command line
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys
    import getpass

    parser = argparse.ArgumentParser(
        description="SENTINEL crypto_utils — encrypt/decrypt config values"
    )
    sub = parser.add_subparsers(dest="command")

    enc_p = sub.add_parser("encrypt", help="Encrypt a plaintext value")
    enc_p.add_argument("--value", help="Value to encrypt (prompted if omitted)")

    dec_p = sub.add_parser("decrypt", help="Decrypt an $enc$ value")
    dec_p.add_argument("value", help="Encrypted value (including $enc$ prefix)")

    rotate_p = sub.add_parser("rotate", help="Re-encrypt under a new key")
    rotate_p.add_argument("value", help="Current $enc$ value")

    args = parser.parse_args()

    if args.command == "encrypt":
        plaintext = args.value or getpass.getpass("Value to encrypt: ")
        if not os.environ.get(_ENV_KEY):
            os.environ[_ENV_KEY] = getpass.getpass(f"Enter {_ENV_KEY}: ")
        result = encrypt(plaintext)
        print(result)

    elif args.command == "decrypt":
        if not os.environ.get(_ENV_KEY):
            os.environ[_ENV_KEY] = getpass.getpass(f"Enter {_ENV_KEY}: ")
        result = decrypt(args.value)
        print(result)

    elif args.command == "rotate":
        old_pw = getpass.getpass("Old passphrase: ")
        new_pw = getpass.getpass("New passphrase: ")
        result = rotate_key(old_pw, new_pw, args.value)
        print(result)

    else:
        parser.print_help()
        sys.exit(1)
