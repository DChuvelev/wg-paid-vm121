from __future__ import annotations

from dataclasses import dataclass
import base64
import json
from pathlib import Path
import socket
from typing import Any
import urllib.error
import urllib.request

from app.config import settings


class YooKassaError(RuntimeError):
    pass


class YooKassaUnavailable(YooKassaError):
    pass


class YooKassaRejected(YooKassaError):
    pass


@dataclass(frozen=True)
class YooKassaCredentials:
    shop_id: str
    secret_key: str


def _load_credentials() -> YooKassaCredentials:
    path = Path(settings.yookassa_credentials_file)
    try:
        raw = path.read_text()
    except OSError as exc:
        raise YooKassaUnavailable("YooKassa credentials are unavailable") from exc
    values: dict[str, str] = {}
    for source_line in raw.splitlines():
        line = source_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise YooKassaUnavailable("YooKassa credentials file is malformed")
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    shop_id = values.get("YOOKASSA_SHOP_ID", "")
    secret_key = values.get("YOOKASSA_SECRET_KEY", "")
    if not shop_id or not secret_key:
        raise YooKassaUnavailable("YooKassa credentials file is incomplete")
    return YooKassaCredentials(shop_id=shop_id, secret_key=secret_key)


def _authorization_header(credentials: YooKassaCredentials) -> str:
    token = base64.b64encode(
        f"{credentials.shop_id}:{credentials.secret_key}".encode("utf-8")
    ).decode("ascii")
    return f"Basic {token}"


def _request_json(
    *,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    idempotence_key: str | None = None,
) -> dict[str, Any]:
    credentials = _load_credentials()
    headers = {
        "Authorization": _authorization_header(credentials),
        "Accept": "application/json",
        "User-Agent": "SecretStudio-P29D/1",
    }
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    if idempotence_key is not None:
        headers["Idempotence-Key"] = idempotence_key
    request = urllib.request.Request(
        f"https://api.yookassa.ru{path}",
        method=method,
        headers=headers,
        data=data,
    )
    try:
        with urllib.request.urlopen(request, timeout=settings.yookassa_timeout_seconds) as response:
            payload = response.read()
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        status = int(exc.code)
        try:
            data_obj = json.loads(payload.decode("utf-8")) if payload else {}
        except Exception:
            data_obj = {}
        code = str(data_obj.get("code") or "provider_http_error")
        if status >= 500 or status == 429:
            raise YooKassaUnavailable(f"YooKassa temporarily unavailable ({status}/{code})") from exc
        raise YooKassaRejected(f"YooKassa rejected request ({status}/{code})") from exc
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
        raise YooKassaUnavailable("YooKassa request outcome is unavailable") from exc

    if status < 200 or status >= 300:
        raise YooKassaUnavailable(f"unexpected YooKassa status {status}")
    try:
        result = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise YooKassaUnavailable("YooKassa returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise YooKassaUnavailable("YooKassa returned invalid object")
    return result


def create_payment(
    *,
    idempotence_key: str,
    amount_kopeks: int,
    currency: str,
    description: str,
    billing_payment_id: str,
    billing_account_id: str,
    kind: str,
) -> dict[str, Any]:
    value = f"{int(amount_kopeks) // 100}.{int(amount_kopeks) % 100:02d}"
    return _request_json(
        method="POST",
        path="/v3/payments",
        idempotence_key=idempotence_key,
        body={
            "amount": {"value": value, "currency": currency},
            "capture": True,
            "confirmation": {
                "type": "redirect",
                "return_url": settings.yookassa_return_url,
            },
            "description": description,
            "save_payment_method": False,
            "metadata": {
                "billing_payment_id": billing_payment_id,
                "billing_account_id": billing_account_id,
                "kind": kind,
            },
        },
    )


def get_payment(provider_payment_id: str) -> dict[str, Any]:
    payment_id = str(provider_payment_id).strip()
    if not payment_id or "/" in payment_id:
        raise YooKassaRejected("invalid YooKassa payment id")
    return _request_json(method="GET", path=f"/v3/payments/{payment_id}")
