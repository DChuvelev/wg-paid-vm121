from __future__ import annotations

import base64
import binascii
import json
import os
import stat
from pathlib import Path

from app.services.credential_crypto import CredentialCipher, CredentialCryptoError

DEFAULT_CREDENTIAL_KEYRING_PATH = Path("/opt/wg-access/runtime/credential-keyring.json")


def _decode_key(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CredentialCryptoError("credential keyring contains invalid key encoding") from exc
    if len(raw) != 32:
        raise CredentialCryptoError("credential keyring keys must be exactly 32 bytes")
    return raw


def load_credential_cipher(path: str | os.PathLike[str] = DEFAULT_CREDENTIAL_KEYRING_PATH) -> CredentialCipher:
    keyring_path = Path(path)
    try:
        st = keyring_path.stat()
    except OSError as exc:
        raise CredentialCryptoError("credential keyring is unavailable") from exc
    if not stat.S_ISREG(st.st_mode):
        raise CredentialCryptoError("credential keyring is not a regular file")
    if st.st_uid != 0 or st.st_gid != 0:
        raise CredentialCryptoError("credential keyring ownership is invalid")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise CredentialCryptoError("credential keyring permissions are too broad")
    try:
        document = json.loads(keyring_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise CredentialCryptoError("credential keyring is invalid") from exc
    if not isinstance(document, dict):
        raise CredentialCryptoError("credential keyring is invalid")
    if set(document) != {"schema", "active_version", "keys"}:
        raise CredentialCryptoError("credential keyring fields are invalid")
    if document["schema"] != "wg-paid-credential-keyring-v1":
        raise CredentialCryptoError("credential keyring schema is unsupported")
    keys_doc = document["keys"]
    if not isinstance(keys_doc, dict) or not keys_doc:
        raise CredentialCryptoError("credential keyring has no keys")
    try:
        active_version = int(document["active_version"])
    except (TypeError, ValueError) as exc:
        raise CredentialCryptoError("credential keyring active version is invalid") from exc
    keys: dict[int, bytes] = {}
    for raw_version, encoded in keys_doc.items():
        try:
            version = int(raw_version)
        except (TypeError, ValueError) as exc:
            raise CredentialCryptoError("credential keyring version is invalid") from exc
        if str(version) != str(raw_version) or version < 1 or not isinstance(encoded, str):
            raise CredentialCryptoError("credential keyring version is invalid")
        if version in keys:
            raise CredentialCryptoError("credential keyring version is duplicated")
        keys[version] = _decode_key(encoded)
    return CredentialCipher(keys, active_version=active_version)
