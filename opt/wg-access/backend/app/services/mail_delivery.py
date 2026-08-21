from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path
import smtplib
import ssl
import stat
from urllib.parse import quote

from app.config import settings


class MailDeliveryError(RuntimeError):
    pass


def _read_root_secret(path_value: str, *, label: str) -> str:
    path_text = str(path_value or "").strip()
    if not path_text:
        raise MailDeliveryError(f"{label} is not configured")
    path = Path(path_text)
    try:
        st = path.stat()
    except OSError as exc:
        raise MailDeliveryError(f"{label} is unavailable") from exc
    if not stat.S_ISREG(st.st_mode):
        raise MailDeliveryError(f"{label} is unavailable")
    if st.st_uid != 0:
        raise MailDeliveryError(f"{label} has unsafe ownership")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise MailDeliveryError(f"{label} has unsafe permissions")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise MailDeliveryError(f"{label} is unavailable") from exc
    if not value or len(value) > 4096:
        raise MailDeliveryError(f"{label} is invalid")
    return value


def _magic_link_url(token: str) -> str:
    template = str(settings.auth_magic_link_public_url_template or "").strip()
    if template.count("{token}") != 1:
        raise MailDeliveryError("magic-link URL template is not configured")
    raw = str(token or "")
    if not raw:
        raise MailDeliveryError("magic-link token is unavailable")
    return template.replace("{token}", quote(raw, safe=""))


def _delivery_settings() -> tuple[str, int, str, str, str, str, int]:
    if not bool(settings.smtp_delivery_active):
        raise MailDeliveryError("SMTP delivery is disabled")
    host = str(settings.smtp_host or "").strip()
    port = int(settings.smtp_port)
    security = str(settings.smtp_security or "").strip().lower()
    username = str(settings.smtp_username or "").strip()
    from_email = str(settings.smtp_from_email or "").strip()
    from_name = str(settings.smtp_from_name or "").strip() or "WG Paid"
    timeout = int(settings.smtp_timeout_seconds)
    if not host or not from_email or port < 1 or port > 65535 or timeout < 1 or timeout > 120:
        raise MailDeliveryError("SMTP delivery settings are incomplete")
    if security not in {"starttls", "tls"}:
        raise MailDeliveryError("SMTP plaintext transport is forbidden")
    return host, port, security, username, from_email, from_name, timeout


def smtp_delivery_status() -> dict[str, object]:
    active = bool(settings.smtp_delivery_active)
    security = str(settings.smtp_security or "").strip().lower()
    configured = False
    if active:
        try:
            host, port, security, username, from_email, from_name, timeout = _delivery_settings()
            if username:
                _read_root_secret(settings.smtp_password_file, label="SMTP password")
            configured = True
        except MailDeliveryError:
            configured = False
    return {
        "active": active,
        "configured": configured,
        "security": security,
    }


def deliver_magic_link_email(*, to_email: str, token: str) -> None:
    host, port, security, username, from_email, from_name, timeout = _delivery_settings()
    recipient = str(to_email or "").strip()
    if not recipient:
        raise MailDeliveryError("recipient is unavailable")
    url = _magic_link_url(token)

    msg = EmailMessage()
    msg["Subject"] = "Your WG Paid sign-in link"
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = recipient
    msg.set_content(
        "Use this one-time link to sign in to WG Paid. "
        "The link expires automatically and can only be used once.\n\n"
        f"{url}\n"
    )

    context = ssl.create_default_context()
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise MailDeliveryError("TLS verification is unavailable")

    password = ""
    if username:
        password = _read_root_secret(settings.smtp_password_file, label="SMTP password")

    try:
        if security == "tls":
            with smtplib.SMTP_SSL(
                host=host,
                port=port,
                timeout=timeout,
                context=context,
            ) as client:
                if username:
                    client.login(username, password)
                client.send_message(msg)
        else:
            with smtplib.SMTP(host=host, port=port, timeout=timeout) as client:
                client.ehlo()
                client.starttls(context=context)
                client.ehlo()
                if username:
                    client.login(username, password)
                client.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        raise MailDeliveryError("SMTP delivery failed") from exc
