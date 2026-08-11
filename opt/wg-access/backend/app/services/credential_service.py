from __future__ import annotations

from dataclasses import dataclass
import uuid

from app.models import PeerCredential
from app.services.credential_crypto import CredentialCryptoError, store_credential_revision
from app.services.credential_keyring import load_credential_cipher
from app.services.wireguard import generate_wg_keypair, generate_wg_psk


class CredentialServiceError(RuntimeError):
    """Secret-safe credential service failure."""


@dataclass(frozen=True)
class CredentialCreationResult:
    credential: PeerCredential
    private_key: str
    preshared_key: str


def create_profile_credential_revision(
    db,
    *,
    profile_id: uuid.UUID,
    supersede_previous: bool = True,
) -> CredentialCreationResult:
    """Generate WG-compatible key material and persist only encrypted secrets.

    The plaintext private key and PSK exist only in process memory and are
    returned to the immediate caller for future config rendering. They are not
    logged or persisted by this service.
    """
    private_key, public_key = generate_wg_keypair()
    preshared_key = generate_wg_psk()
    try:
        cipher = load_credential_cipher()
        row = store_credential_revision(
            db,
            profile_id=profile_id,
            public_key=public_key,
            secret_material={
                "private_key": private_key,
                "preshared_key": preshared_key,
            },
            cipher=cipher,
            supersede_previous=supersede_previous,
        )
    except CredentialCryptoError as exc:
        raise CredentialServiceError("credential storage failed") from exc
    return CredentialCreationResult(
        credential=row,
        private_key=private_key,
        preshared_key=preshared_key,
    )


def decrypt_profile_credential(credential: PeerCredential) -> dict[str, str]:
    """Decrypt one stored revision using the key version recorded on the row."""
    try:
        cipher = load_credential_cipher()
        return cipher.decrypt_json(
            credential.secret_ciphertext,
            key_version=credential.key_version,
            profile_id=str(credential.connection_profile_id),
            revision=credential.revision,
        )
    except CredentialCryptoError as exc:
        raise CredentialServiceError("credential decrypt failed") from exc
