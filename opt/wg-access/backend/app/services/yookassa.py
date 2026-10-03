from __future__ import annotations

from dataclasses import dataclass
import base64
import json
from pathlib import Path
import re
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


RECEIPT_VAT_CODE = 1  # Без НДС.
RECEIPT_PAYMENT_SUBJECT = "service"
RECEIPT_MEASURE = "piece"
_RECEIPT_LINE_RULES: dict[str, tuple[str, str]] = {
    "reactivation_period": ("Secret Studio — доступ на 1 месяц", "full_payment"),
    "current_proration": ("Secret Studio — доплата за текущий период", "full_payment"),
    "next_period": ("Secret Studio — доступ на следующий месяц", "full_prepayment"),
    "next_period_top_up": ("Secret Studio — доплата за следующий месяц", "full_prepayment"),
}
_PREPAYMENT_LINE_KINDS = frozenset({"next_period", "next_period_top_up"})
_FORBIDDEN_CUSTOMER_PAYMENT_PATTERNS = tuple(
    re.compile(rf"(?<![A-Za-z0-9]){re.escape(token)}(?![A-Za-z0-9])", re.IGNORECASE)
    for token in ("VPN", "WireGuard", "AmneziaWG", "Amnezia", "AWG", "WG")
)


def _assert_customer_facing_text_safe(value: str, *, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise YooKassaRejected(f"customer-facing payment text is empty: {field}")
    for pattern in _FORBIDDEN_CUSTOMER_PAYMENT_PATTERNS:
        if pattern.search(text):
            raise YooKassaRejected(f"forbidden customer-facing payment term: {field}")
    return text


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
        "User-Agent": "SecretStudio-P29H/1",
    }
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
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


def _money_value(amount_kopeks: int) -> str:
    amount = int(amount_kopeks)
    if amount <= 0:
        raise YooKassaRejected("receipt amount must be positive")
    return f"{amount // 100}.{amount % 100:02d}"


def _receipt_line(line: dict[str, Any], *, currency: str, force_full_payment: bool = False) -> dict[str, Any]:
    kind = str(line.get("kind") or "")
    rule = _RECEIPT_LINE_RULES.get(kind)
    if rule is None:
        raise YooKassaRejected(f"unsupported receipt calculation line: {kind or 'missing'}")
    description, payment_mode = rule
    description = _assert_customer_facing_text_safe(description, field=f"receipt.{kind}.description")
    if force_full_payment:
        if kind not in _PREPAYMENT_LINE_KINDS:
            raise YooKassaRejected("only a prepayment line can be settled")
        payment_mode = "full_payment"
    amount_kopeks = int(line.get("amount_kopeks") or 0)
    return {
        "description": description,
        "quantity": 1.0,
        "amount": {"value": _money_value(amount_kopeks), "currency": currency},
        "vat_code": RECEIPT_VAT_CODE,
        "payment_mode": payment_mode,
        "payment_subject": RECEIPT_PAYMENT_SUBJECT,
        "measure": RECEIPT_MEASURE,
    }


def _payment_receipt(
    *,
    customer_email: str,
    currency: str,
    amount_kopeks: int,
    calculation: dict[str, Any] | None,
) -> dict[str, Any]:
    email = str(customer_email or "").strip()
    if not email or "@" not in email:
        raise YooKassaRejected("receipt customer email is unavailable")
    if not isinstance(calculation, dict):
        raise YooKassaRejected("receipt calculation is unavailable")
    contract = calculation.get("receipt_contract")
    if not isinstance(contract, dict) or not (
        int(contract.get("version") or 0) == 1
        and str(contract.get("provider") or "") == "yookassa"
        and str(contract.get("provider_mode") or "") == "live"
        and int(contract.get("vat_code") or 0) == RECEIPT_VAT_CODE
    ):
        raise YooKassaRejected("live receipt contract is unavailable")
    raw_lines = calculation.get("lines")
    if not isinstance(raw_lines, list) or not raw_lines:
        raise YooKassaRejected("receipt calculation lines are unavailable")
    items: list[dict[str, Any]] = []
    total = 0
    for raw_line in raw_lines:
        if not isinstance(raw_line, dict):
            raise YooKassaRejected("receipt calculation line is invalid")
        total += int(raw_line.get("amount_kopeks") or 0)
        items.append(_receipt_line(raw_line, currency=currency))
    if total != int(amount_kopeks):
        raise YooKassaRejected("receipt total does not match payment amount")
    return {
        "customer": {"email": email},
        "items": items,
        "internet": True,
    }


def create_payment(
    *,
    idempotence_key: str,
    amount_kopeks: int,
    currency: str,
    description: str,
    billing_payment_id: str,
    billing_account_id: str,
    kind: str,
    customer_email: str,
    calculation: dict[str, Any] | None,
) -> dict[str, Any]:
    value = _money_value(amount_kopeks)
    public_description = _assert_customer_facing_text_safe(description, field="payment.description")
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
            "description": public_description,
            "save_payment_method": False,
            "receipt": _payment_receipt(
                customer_email=customer_email,
                currency=currency,
                amount_kopeks=amount_kopeks,
                calculation=calculation,
            ),
            "metadata": {
                "billing_payment_id": billing_payment_id,
                "billing_account_id": billing_account_id,
                "kind": kind,
            },
        },
    )


def create_prepayment_settlement_receipt(
    *,
    idempotence_key: str,
    provider_payment_id: str,
    customer_email: str,
    currency: str,
    calculation_line: dict[str, Any],
) -> dict[str, Any]:
    provider_id = str(provider_payment_id or "").strip()
    if not provider_id or "/" in provider_id:
        raise YooKassaRejected("invalid YooKassa payment id")
    email = str(customer_email or "").strip()
    if not email or "@" not in email:
        raise YooKassaRejected("receipt customer email is unavailable")
    item = _receipt_line(calculation_line, currency=currency, force_full_payment=True)
    amount = item["amount"]
    return _request_json(
        method="POST",
        path="/v3/receipts",
        idempotence_key=idempotence_key,
        body={
            "type": "payment",
            "payment_id": provider_id,
            "customer": {"email": email},
            "send": True,
            "items": [item],
            "internet": True,
            "settlements": [
                {
                    "type": "prepayment",
                    "amount": {"value": amount["value"], "currency": amount["currency"]},
                }
            ],
        },
    )


def get_payment(provider_payment_id: str) -> dict[str, Any]:
    payment_id = str(provider_payment_id).strip()
    if not payment_id or "/" in payment_id:
        raise YooKassaRejected("invalid YooKassa payment id")
    return _request_json(method="GET", path=f"/v3/payments/{payment_id}")
