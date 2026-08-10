from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CredentialCryptoError(RuntimeError):
    pass


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:
        raise CredentialCryptoError("invalid credential ciphertext encoding") from exc


@dataclass(frozen=True)
class CredentialEnvelope:
    ciphertext: str
    key_version: int


class CredentialCipher:
    """Versioned AES-256-GCM envelope.

    Key bytes are supplied by the caller. This module never persists or logs
    master keys and intentionally does not define a default production key.
    """

    FORMAT = "aes256gcm-v1"

    def __init__(self, keys: Mapping[int, bytes], *, active_version: int):
        normalized: dict[int, bytes] = {}
        for version, key in keys.items():
            iv = int(version)
            raw = bytes(key)
            if iv < 1 or len(raw) != 32:
                raise CredentialCryptoError("credential keys must be version>=1 and 32 bytes")
            normalized[iv] = raw
        if active_version not in normalized:
            raise CredentialCryptoError("active credential key version is unavailable")
        self._keys = normalized
        self.active_version = int(active_version)

    @staticmethod
    def associated_data(*, profile_id: str, revision: int) -> bytes:
        return f"wg-paid/domain-v2/peer-credential/{profile_id}/r{int(revision)}".encode("utf-8")

    def encrypt_json(
        self,
        payload: Mapping[str, str],
        *,
        profile_id: str,
        revision: int,
    ) -> CredentialEnvelope:
        if revision < 1:
            raise CredentialCryptoError("credential revision must be >=1")
        plaintext = json.dumps(
            dict(payload),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        nonce = os.urandom(12)
        aad = self.associated_data(profile_id=profile_id, revision=revision)
        encrypted = AESGCM(self._keys[self.active_version]).encrypt(nonce, plaintext, aad)
        return CredentialEnvelope(
            ciphertext=f"{self.FORMAT}.{_b64e(nonce)}.{_b64e(encrypted)}",
            key_version=self.active_version,
        )

    def decrypt_json(
        self,
        ciphertext: str,
        *,
        key_version: int,
        profile_id: str,
        revision: int,
    ) -> dict[str, str]:
        key = self._keys.get(int(key_version))
        if key is None:
            raise CredentialCryptoError("credential key version is unavailable")
        parts = str(ciphertext).split(".")
        if len(parts) != 3 or parts[0] != self.FORMAT:
            raise CredentialCryptoError("unsupported credential ciphertext format")
        nonce = _b64d(parts[1])
        encrypted = _b64d(parts[2])
        if len(nonce) != 12:
            raise CredentialCryptoError("invalid credential nonce")
        aad = self.associated_data(profile_id=profile_id, revision=revision)
        try:
            plaintext = AESGCM(key).decrypt(nonce, encrypted, aad)
        except InvalidTag as exc:
            raise CredentialCryptoError("credential authentication failed") from exc
        try:
            value = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise CredentialCryptoError("credential plaintext is invalid") from exc
        if not isinstance(value, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in value.items()
        ):
            raise CredentialCryptoError("credential plaintext shape is invalid")
        return value


def store_credential_revision(
    db,
    *,
    profile_id,
    public_key: str,
    secret_material: Mapping[str, str],
    cipher: CredentialCipher,
    supersede_previous: bool = True,
):
    """Persist one encrypted credential revision.

    This is storage-layer state only. It does not claim that VM100 runtime
    identity has been provisioned, disabled, or reissued.
    """
    from datetime import datetime, timezone
    import uuid
    from sqlalchemy import select
    from app.models import ConnectionProfile, PeerCredential

    profile = db.execute(
        select(ConnectionProfile)
        .where(ConnectionProfile.id == profile_id)
        .with_for_update()
    ).scalar_one_or_none()
    if profile is None:
        raise CredentialCryptoError("connection profile does not exist")

    previous = db.execute(
        select(PeerCredential)
        .where(PeerCredential.connection_profile_id == profile.id)
        .order_by(PeerCredential.revision.desc())
        .with_for_update()
    ).scalars().first()
    revision = 1 if previous is None else previous.revision + 1
    if previous is not None and supersede_previous and previous.revoked_at is None:
        previous.revoked_at = datetime.now(timezone.utc)

    envelope = cipher.encrypt_json(
        secret_material,
        profile_id=str(profile.id),
        revision=revision,
    )
    row = PeerCredential(
        id=uuid.uuid4(),
        connection_profile_id=profile.id,
        revision=revision,
        public_key=public_key,
        secret_ciphertext=envelope.ciphertext,
        key_version=envelope.key_version,
    )
    db.add(row)
    db.flush()
    return row
