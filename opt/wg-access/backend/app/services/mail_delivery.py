from __future__ import annotations

from datetime import datetime, timezone
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
    from_name = str(settings.smtp_from_name or "").strip() or "Secret Studio"
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


def deliver_magic_link_email(*, to_email: str, token: str, issued_at: datetime | None = None) -> None:
    host, port, security, username, from_email, from_name, timeout = _delivery_settings()
    recipient = str(to_email or "").strip()
    if not recipient:
        raise MailDeliveryError("recipient is unavailable")
    url = _magic_link_url(token)

    stamp = issued_at or datetime.now(timezone.utc)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    stamp = stamp.astimezone(timezone.utc)

    msg = EmailMessage()
    msg["Subject"] = f"Secret Studio sign-in link — {stamp:%Y-%m-%d %H:%M UTC}"
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = recipient
    msg.set_content(
        "Use this one-time link to sign in to Secret Studio. "
        "The link expires automatically and can only be used once. "
        "If you requested another link later, use the newest message.\n\n"
        f"Issued: {stamp:%Y-%m-%d %H:%M:%S UTC}\n"
        f"{url}\n"
    )

    _send_message(msg)


SUPPORT_EMAIL = "support@secret-studio.ru"


def _send_message(msg: EmailMessage) -> None:
    host, port, security, username, _from_email, _from_name, timeout = _delivery_settings()
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


def deliver_support_message(*, reply_to_email: str, user_id: str, message: str) -> None:
    _host, _port, _security, _username, from_email, from_name, _timeout = _delivery_settings()
    reply_to = str(reply_to_email or "").strip()
    user_ref = str(user_id or "").strip()
    body = str(message or "").strip()
    if not reply_to or not user_ref or not body or len(body) > 500:
        raise MailDeliveryError("support message is invalid")

    msg = EmailMessage()
    msg["Subject"] = f"Secret Studio support — {reply_to}"
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = SUPPORT_EMAIL
    msg["Reply-To"] = reply_to
    msg.set_content(
        f"Registered email: {reply_to}\n"
        f"User ID: {user_ref}\n\n"
        f"{body}\n"
    )
    _send_message(msg)

_RU_MONTHS = (
    "", "января", "февраля", "марта", "апреля", "мая", "июня",
    "июля", "августа", "сентября", "октября", "ноября", "декабря",
)
_EN_MONTHS = (
    "", "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)


def deliver_renewal_reminder_email(*, to_email: str, token: str, period_end: datetime) -> None:
    _host, _port, _security, _username, from_email, from_name, _timeout = _delivery_settings()
    recipient = str(to_email or "").strip()
    if not recipient:
        raise MailDeliveryError("recipient is unavailable")
    if period_end.tzinfo is None:
        period_end = period_end.replace(tzinfo=timezone.utc)
    period_end = period_end.astimezone(timezone.utc)
    url = _magic_link_url(token)
    ru_date = f"{period_end.day} {_RU_MONTHS[period_end.month]} {period_end.year} г."
    en_date = f"{_EN_MONTHS[period_end.month]} {period_end.day}, {period_end.year}"

    msg = EmailMessage()
    msg["Subject"] = "Secret Studio — напоминание о продлении / Renewal reminder"
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = recipient
    msg.set_content(
        "Здравствуйте!\n\n"
        f"Оплаченный период вашего доступа к Secret Studio заканчивается {ru_date}\n\n"
        "Чтобы продлить доступ, перейдите в личный кабинет по персональной ссылке:\n\n"
        f"{url}\n\n"
        "Если вы уже продлили доступ, дополнительных действий не требуется.\n\n"
        "С уважением,\nSecret Studio\n\n"
        "----------------------------------------\n\n"
        "Hello!\n\n"
        f"Your paid access to Secret Studio expires on {en_date}.\n\n"
        "To renew your access, open your account using the personal link below:\n\n"
        f"{url}\n\n"
        "If you have already renewed your access, no further action is required.\n\n"
        "Best regards,\nSecret Studio\n"
    )
    _send_message(msg)

