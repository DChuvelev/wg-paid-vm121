from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat

from app.config import settings


class AdminAuthorizationUnavailable(RuntimeError):
    pass


def _read_root_secret(path_value: str, *, label: str) -> str:
    path_text = str(path_value or "").strip()
    if not path_text:
        raise AdminAuthorizationUnavailable(f"{label} is not configured")
    path = Path(path_text)
    try:
        st = path.stat()
    except OSError as exc:
        raise AdminAuthorizationUnavailable(f"{label} is unavailable") from exc
    if not stat.S_ISREG(st.st_mode):
        raise AdminAuthorizationUnavailable(f"{label} is unavailable")
    if st.st_uid != 0:
        raise AdminAuthorizationUnavailable(f"{label} has unsafe ownership")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise AdminAuthorizationUnavailable(f"{label} has unsafe permissions")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise AdminAuthorizationUnavailable(f"{label} is unavailable") from exc
    if len(value) < 32 or len(value) > 4096:
        raise AdminAuthorizationUnavailable(f"{label} is invalid")
    return value


def load_admin_token() -> str:
    if str(settings.auth_admin_token_file or "").strip():
        return _read_root_secret(
            settings.auth_admin_token_file,
            label="admin authorization secret",
        )
    if bool(settings.auth_admin_token_env_fallback):
        value = str(settings.auth_admin_token or "").strip()
        if 32 <= len(value) <= 4096:
            return value
    raise AdminAuthorizationUnavailable("admin authorization is not configured")


def admin_token_matches(provided: str | None) -> bool:
    if not provided:
        return False
    expected = load_admin_token()
    return secrets.compare_digest(str(provided), expected)


def admin_authorization_status() -> dict[str, object]:
    source = "none"
    configured = False
    if str(settings.auth_admin_token_file or "").strip():
        source = "file"
        try:
            _read_root_secret(
                settings.auth_admin_token_file,
                label="admin authorization secret",
            )
            configured = True
        except AdminAuthorizationUnavailable:
            configured = False
    elif bool(settings.auth_admin_token_env_fallback):
        source = "env_fallback"
        value = str(settings.auth_admin_token or "").strip()
        configured = 32 <= len(value) <= 4096
    return {
        "configured": configured,
        "source": source,
        "env_fallback_enabled": bool(settings.auth_admin_token_env_fallback),
    }
