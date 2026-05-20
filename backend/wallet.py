from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import time
import urllib.parse
import urllib.request
from calendar import monthrange
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_CEILING
from typing import Any, Callable

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.system_program import TransferParams, transfer
from solana.exceptions import SolanaRpcException
from solana.rpc.async_api import AsyncClient
from solana.rpc.commitment import Commitment
from solana.rpc.types import TxOpts
from solana.transaction import Transaction

from . import access_db
from .access_security import (
    AccessConfigError,
    decrypt_deposit_secret,
    encrypt_claim_payload,
    encrypt_deposit_secret,
    env_bool,
    env_float,
    env_int,
    generate_restore_key,
    generate_user_key,
    hash_access_key,
    hash_restore_key,
    isoformat,
    parse_datetime,
    safe_error,
    utcnow,
)


log = logging.getLogger("nulltrace.wallet")

LAMPORTS_PER_SOL = 1_000_000_000

PLAN_CONFIG = {
    "1m": {"label": "1 month", "price_env": "NULLTRACE_PRICE_1M_USD", "months": 1, "default_usd": 100},
    "6m": {"label": "6 months", "price_env": "NULLTRACE_PRICE_6M_USD", "months": 6, "default_usd": 400},
    "1y": {"label": "1 year", "price_env": "NULLTRACE_PRICE_1Y_USD", "months": 12, "default_usd": 600},
}

_PRICE_CACHE: dict[str, float | None] = {"ts": 0.0, "usd": None}


class DevnetFundingError(RuntimeError):
    pass


def use_devnet() -> bool:
    return env_bool("SOL_USE_DEVNET", True)


def solana_rpc_url() -> str:
    return os.getenv(
        "SOLANA_RPC_DEV" if use_devnet() else "SOLANA_RPC_MAIN",
        "https://api.devnet.solana.com" if use_devnet() else "https://api.mainnet-beta.solana.com",
    )


def payment_finality() -> str:
    return os.getenv("PAYMENT_FINALITY", "finalized").strip() or "finalized"


def payment_poll_interval_seconds() -> int:
    return env_int("PAYMENT_POLL_INTERVAL_SECONDS", 10)


def sweep_poll_interval_seconds() -> int:
    return env_int("SWEEP_POLL_INTERVAL_SECONDS", 60)


def devnet_payment_faucet_enabled() -> bool:
    return use_devnet() and env_bool("DEVNET_PAYMENT_FAUCET_ENABLED", False)


def list_plans() -> list[dict[str, Any]]:
    plans = []
    for plan_id, cfg in PLAN_CONFIG.items():
        plans.append(
            {
                "id": plan_id,
                "label": cfg["label"],
                "usdPrice": plan_price_usd(plan_id),
            }
        )
    return plans


def plan_price_usd(plan: str) -> float:
    if plan not in PLAN_CONFIG:
        raise ValueError("invalid plan")
    cfg = PLAN_CONFIG[plan]
    env_key = cfg["price_env"]
    value = env_float(env_key, float(cfg["default_usd"]))
    if value is None or value <= 0:
        raise AccessConfigError(f"{env_key} must be set to a positive number")
    return float(value)


def add_plan_duration(start: datetime, plan: str) -> datetime:
    if plan not in PLAN_CONFIG:
        raise ValueError("invalid plan")
    months = int(PLAN_CONFIG[plan]["months"])
    source = start.astimezone(timezone.utc)
    month_index = source.month - 1 + months
    year = source.year + month_index // 12
    month = month_index % 12 + 1
    day = min(source.day, monthrange(year, month)[1])
    return source.replace(year=year, month=month, day=day)


def calculate_sol_amount_lamports(usd_price: float, sol_usd_rate: float) -> int:
    if usd_price <= 0:
        raise ValueError("usd_price must be positive")
    if sol_usd_rate <= 0:
        raise ValueError("sol_usd_rate must be positive")
    lamports = (Decimal(str(usd_price)) / Decimal(str(sol_usd_rate))) * Decimal(LAMPORTS_PER_SOL)
    return int(lamports.to_integral_value(rounding=ROUND_CEILING))


def lamports_to_sol_string(lamports: int) -> str:
    whole = lamports // LAMPORTS_PER_SOL
    frac = lamports % LAMPORTS_PER_SOL
    return f"{whole}.{frac:09d}".rstrip("0").rstrip(".")


def create_deposit_wallet() -> tuple[str, bytes]:
    keypair = Keypair()
    return str(keypair.pubkey()), bytes(keypair)


def encrypt_secret_key(secret_key: bytes) -> str:
    return encrypt_deposit_secret(secret_key)


def decrypt_secret_key(encrypted_secret_key: str) -> bytes:
    return decrypt_deposit_secret(encrypted_secret_key)


def _load_keypair(secret_key: bytes) -> Keypair:
    if len(secret_key) == 32:
        return Keypair.from_seed(secret_key)
    if len(secret_key) == 64:
        return Keypair.from_bytes(secret_key)
    raise ValueError("deposit secret key must be 32 or 64 bytes")


def _fetch_sol_usd_price_sync(provider: str) -> float:
    if provider != "coingecko":
        raise AccessConfigError(f"unsupported SOL_PRICE_PROVIDER: {provider}")
    params = urllib.parse.urlencode({"ids": "solana", "vs_currencies": "usd"})
    url = f"https://api.coingecko.com/api/v3/simple/price?{params}"
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        data = json.loads(response.read().decode("utf-8"))
    price = float(data.get("solana", {}).get("usd", 0))
    if price <= 0:
        raise RuntimeError("CoinGecko returned no SOL/USD price")
    return price


async def _fetch_sol_usd_price(provider: str) -> float:
    return await asyncio.to_thread(_fetch_sol_usd_price_sync, provider)


async def get_sol_usd_price_cached() -> float:
    cache_seconds = env_int("SOL_PRICE_CACHE_SECONDS", 300)
    now_ts = time.time()
    cached = _PRICE_CACHE.get("usd")
    if cached and now_ts - float(_PRICE_CACHE.get("ts") or 0) < cache_seconds:
        return float(cached)

    provider = os.getenv("SOL_PRICE_PROVIDER", "coingecko").strip().lower() or "coingecko"
    try:
        price = await _fetch_sol_usd_price(provider)
        _PRICE_CACHE.update(ts=now_ts, usd=price)
        return float(price)
    except Exception as exc:
        fallback = env_float("SOL_PRICE_USD_FALLBACK")
        if fallback and fallback > 0:
            log.warning("SOL price provider failed; using fallback: %s", safe_error(exc))
            _PRICE_CACHE.update(ts=now_ts, usd=fallback)
            return float(fallback)
        if cached:
            log.warning("SOL price provider failed; using previous cached price: %s", safe_error(exc))
            return float(cached)
        raise


async def get_deposit_balance_lamports(
    deposit_public_key: str,
    *,
    client: AsyncClient | None = None,
    commitment: str | None = None,
) -> int:
    own_client = client is None
    rpc_client = client or AsyncClient(solana_rpc_url())
    try:
        response = await rpc_client.get_balance(
            Pubkey.from_string(deposit_public_key),
            commitment=Commitment(commitment or payment_finality()),
        )
        return int(response.value or 0)
    finally:
        if own_client:
            await rpc_client.close()


async def fund_devnet_payment_order(
    order: dict[str, Any],
    *,
    lamports: int | None = None,
) -> dict[str, Any]:
    if not use_devnet():
        raise AccessConfigError("devnet funding requires SOL_USE_DEVNET=1")
    if not devnet_payment_faucet_enabled():
        raise AccessConfigError("DEVNET_PAYMENT_FAUCET_ENABLED must be enabled")
    if order["status"] != "pending":
        raise ValueError("payment order is not pending")

    amount_lamports = int(lamports if lamports is not None else order["sol_amount_lamports"])
    max_lamports = env_int("DEVNET_PAYMENT_FAUCET_MAX_LAMPORTS", 2 * LAMPORTS_PER_SOL)
    if amount_lamports <= 0:
        raise ValueError("airdrop amount must be positive")
    if amount_lamports > max_lamports:
        raise ValueError("airdrop amount exceeds DEVNET_PAYMENT_FAUCET_MAX_LAMPORTS")

    pubkey = Pubkey.from_string(order["deposit_public_key"])
    async with AsyncClient(solana_rpc_url()) as client:
        response = await client.request_airdrop(
            pubkey,
            amount_lamports,
            commitment=Commitment(payment_finality()),
        )
        signature = getattr(response, "value", None)
        if signature is None:
            error_text = safe_error(response)
            if hasattr(response, "to_json"):
                try:
                    error_text = response.to_json()
                except Exception:
                    pass
            raise DevnetFundingError(f"devnet airdrop failed: {error_text}")
        await _confirm_signature(client, signature)
        balance = await get_deposit_balance_lamports(
            order["deposit_public_key"],
            client=client,
            commitment=payment_finality(),
        )
    return {
        "status": "funded",
        "signature": str(signature),
        "lamports": amount_lamports,
        "balanceLamports": balance,
        "solAmount": lamports_to_sol_string(amount_lamports),
    }


async def _confirm_signature(
    client: AsyncClient,
    signature: Signature,
    *,
    tries: int = 8,
    delay: float = 0.75,
) -> bool:
    for attempt in range(tries):
        try:
            response = await client.confirm_transaction(signature, commitment=payment_finality())
            value = getattr(response, "value", None)
            if value is None or getattr(value, "err", None) is None:
                return True
        except SolanaRpcException as exc:
            if "429" not in str(exc) and attempt == tries - 1:
                raise
        await asyncio.sleep(delay)
        delay = min(delay * 1.6, 5.0)
    return False


def _create_account_for_confirmed_order(
    conn,
    *,
    order: dict[str, Any],
    confirmed_balance_lamports: int,
    now: datetime,
) -> tuple[int, str, str, datetime]:
    user_key = generate_user_key()
    restore_key = generate_restore_key()
    paid_until = add_plan_duration(now, order["plan"])
    now_iso = isoformat(now)
    cur = conn.execute(
        """
        INSERT INTO access_accounts(
          user_key_hash, restore_key_hash, plan, paid_until, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            hash_access_key(user_key),
            hash_restore_key(restore_key),
            order["plan"],
            isoformat(paid_until),
            now_iso,
            now_iso,
        ),
    )
    account_id = int(cur.lastrowid)
    claim_payload = encrypt_claim_payload(
        {
            "userKey": user_key,
            "restoreKey": restore_key,
            "paidUntil": isoformat(paid_until),
        }
    )
    conn.execute(
        """
        UPDATE payment_orders
        SET status = 'confirmed',
            confirmed_at = ?,
            confirmed_balance_lamports = ?,
            created_account_id = ?,
            encrypted_claim_payload = ?,
            updated_at = ?
        WHERE id = ? AND status = 'pending'
        """,
        (
            now_iso,
            int(confirmed_balance_lamports),
            account_id,
            claim_payload,
            now_iso,
            int(order["id"]),
        ),
    )
    access_db.audit_event(
        "payment_confirmed",
        account_id=account_id,
        payment_order_id=int(order["id"]),
        metadata={
            "deposit_public_key": order["deposit_public_key"],
            "confirmed_balance_lamports": int(confirmed_balance_lamports),
            "required_lamports": int(order["sol_amount_lamports"]),
        },
        conn=conn,
    )
    access_db.audit_event(
        "account_created",
        account_id=account_id,
        payment_order_id=int(order["id"]),
        metadata={"plan": order["plan"], "paid_until": isoformat(paid_until)},
        conn=conn,
    )
    return account_id, user_key, restore_key, paid_until


async def confirm_payment_order_if_funded(order_id: int) -> dict[str, Any]:
    access_db.init_db()
    order = access_db.get_order(order_id)
    if not order:
        return {"status": "missing"}
    if order["status"] != "pending":
        return {"status": order["status"], "changed": False}

    now = utcnow()
    expires_at = parse_datetime(order.get("expires_at"))
    if expires_at and expires_at < now:
        with access_db.db() as conn:
            _mark_order_expired(conn, int(order["id"]), now)
        return {"status": "expired", "changed": True}

    balance = await get_deposit_balance_lamports(order["deposit_public_key"])
    if balance < int(order["sol_amount_lamports"]):
        return {
            "status": "pending",
            "changed": False,
            "balanceLamports": balance,
            "requiredLamports": int(order["sol_amount_lamports"]),
        }

    with access_db.db() as conn:
        current = access_db.row_to_dict(
            conn.execute("SELECT * FROM payment_orders WHERE id = ?", (int(order["id"]),)).fetchone()
        )
        if not current:
            return {"status": "missing"}
        if current["status"] != "pending":
            return {"status": current["status"], "changed": False}
        account_id, _user_key, _restore_key, paid_until = _create_account_for_confirmed_order(
            conn,
            order=current,
            confirmed_balance_lamports=balance,
            now=utcnow(),
        )

    log.info(
        "payment confirmed order_id=%s deposit=%s lamports=%s",
        order["id"],
        order["deposit_public_key"],
        balance,
    )
    return {
        "status": "confirmed",
        "changed": True,
        "accountId": account_id,
        "paidUntil": isoformat(paid_until),
        "balanceLamports": balance,
        "requiredLamports": int(order["sol_amount_lamports"]),
    }


def _mark_order_expired(conn, order_id: int, now: datetime) -> None:
    conn.execute(
        """
        UPDATE payment_orders
        SET status = 'expired', updated_at = ?
        WHERE id = ? AND status = 'pending'
        """,
        (isoformat(now), int(order_id)),
    )
    access_db.audit_event(
        "payment_expired",
        payment_order_id=int(order_id),
        metadata={},
        conn=conn,
    )


async def poll_pending_payments(*, run_forever: bool = False) -> dict[str, int]:
    totals = {"checked": 0, "confirmed": 0, "expired": 0, "short": 0, "failed": 0}
    while True:
        access_db.init_db()
        now = utcnow()
        for order in access_db.pending_orders():
            totals["checked"] += 1
            expires_at = parse_datetime(order["expires_at"])
            if expires_at and expires_at < now:
                with access_db.db() as conn:
                    _mark_order_expired(conn, int(order["id"]), now)
                totals["expired"] += 1
                continue

            try:
                result = await confirm_payment_order_if_funded(int(order["id"]))
            except Exception as exc:
                log.warning(
                    "payment balance check failed order_id=%s deposit=%s error=%s",
                    order["id"],
                    order["deposit_public_key"],
                    safe_error(exc),
                )
                totals["failed"] += 1
                continue

            if result.get("status") == "expired":
                totals["expired"] += 1
                continue
            if result.get("status") == "pending":
                totals["short"] += 1
                continue
            if result.get("status") == "confirmed" and result.get("changed"):
                totals["confirmed"] += 1

        if not run_forever:
            return totals
        await asyncio.sleep(payment_poll_interval_seconds())


def calculate_sweep_amount(balance_lamports: int, estimated_fee_lamports: int) -> int:
    return int(balance_lamports) - int(estimated_fee_lamports)


async def estimate_transfer_fee_lamports(
    client: AsyncClient,
    *,
    from_pubkey: Pubkey,
    to_pubkey: Pubkey,
    blockhash,
) -> int:
    tx = Transaction(recent_blockhash=blockhash, fee_payer=from_pubkey).add(
        transfer(
            TransferParams(
                from_pubkey=from_pubkey,
                to_pubkey=to_pubkey,
                lamports=1,
            )
        )
    )
    response = await client.get_fee_for_message(tx.compile_message(), commitment=Commitment(payment_finality()))
    fee = int(response.value or 0)
    if fee <= 0:
        raise RuntimeError("RPC returned no transfer fee")
    return fee


async def send_transfer_lamports(
    client: AsyncClient,
    *,
    keypair: Keypair,
    to_pubkey: Pubkey,
    lamports: int,
    blockhash,
) -> Signature:
    tx = Transaction(recent_blockhash=blockhash, fee_payer=keypair.pubkey()).add(
        transfer(
            TransferParams(
                from_pubkey=keypair.pubkey(),
                to_pubkey=to_pubkey,
                lamports=int(lamports),
            )
        )
    )
    response = await client.send_transaction(
        tx,
        keypair,
        opts=TxOpts(skip_preflight=False, preflight_commitment=payment_finality()),
    )
    return response.value


async def sweep_deposit_to_cold(payment_order_id: int) -> dict[str, Any]:
    access_db.init_db()
    if access_db.has_successful_sweep(payment_order_id):
        return {"status": "already_swept", "paymentOrderId": payment_order_id}

    order = access_db.get_order(payment_order_id)
    if not order:
        raise ValueError("payment order not found")
    if order["status"] not in {"confirmed", "swept"}:
        return {"status": "skipped", "reason": "order_not_confirmed"}

    cold_wallet = os.getenv("SOLANA_COLD_WALLET_PUBLIC_KEY", "").strip()
    if not cold_wallet:
        raise AccessConfigError("SOLANA_COLD_WALLET_PUBLIC_KEY is required")

    secret_key = decrypt_secret_key(order["encrypted_deposit_secret_key"])
    keypair = _load_keypair(secret_key)
    cold_pubkey = Pubkey.from_string(cold_wallet)
    min_balance = env_int("SWEEP_MIN_BALANCE_LAMPORTS", 5000)
    max_rounds = 3
    final_result: dict[str, Any] = {"status": "pending"}

    async with AsyncClient(solana_rpc_url()) as client:
        for _round in range(max_rounds):
            if access_db.has_successful_sweep(payment_order_id):
                return {"status": "already_swept", "paymentOrderId": payment_order_id}

            balance_before = await get_deposit_balance_lamports(
                order["deposit_public_key"],
                client=client,
                commitment=payment_finality(),
            )
            if balance_before == 0:
                access_db.create_sweep(
                    payment_order_id=payment_order_id,
                    deposit_public_key=order["deposit_public_key"],
                    cold_wallet_public_key=cold_wallet,
                    balance_before_lamports=0,
                    fee_lamports=0,
                    amount_sent_lamports=0,
                    balance_after_lamports=0,
                    sweep_signature=None,
                    status="swept",
                )
                final_result = {"status": "swept", "amountSentLamports": 0, "balanceAfterLamports": 0}
                break

            if balance_before <= min_balance:
                access_db.create_sweep(
                    payment_order_id=payment_order_id,
                    deposit_public_key=order["deposit_public_key"],
                    cold_wallet_public_key=cold_wallet,
                    balance_before_lamports=balance_before,
                    fee_lamports=0,
                    amount_sent_lamports=0,
                    balance_after_lamports=balance_before,
                    sweep_signature=None,
                    status="dust_unspendable",
                    error="balance at or below SWEEP_MIN_BALANCE_LAMPORTS",
                )
                final_result = {"status": "dust_unspendable", "balanceAfterLamports": balance_before}
                break

            blockhash = (await client.get_latest_blockhash(commitment=Commitment(payment_finality()))).value.blockhash
            fee_lamports = await estimate_transfer_fee_lamports(
                client,
                from_pubkey=keypair.pubkey(),
                to_pubkey=cold_pubkey,
                blockhash=blockhash,
            )
            amount_to_send = calculate_sweep_amount(balance_before, fee_lamports)
            if amount_to_send <= 0:
                access_db.create_sweep(
                    payment_order_id=payment_order_id,
                    deposit_public_key=order["deposit_public_key"],
                    cold_wallet_public_key=cold_wallet,
                    balance_before_lamports=balance_before,
                    fee_lamports=fee_lamports,
                    amount_sent_lamports=0,
                    balance_after_lamports=balance_before,
                    sweep_signature=None,
                    status="dust_unspendable",
                    error="balance cannot cover estimated transaction fee",
                )
                final_result = {"status": "dust_unspendable", "balanceAfterLamports": balance_before}
                break

            signature = await send_transfer_lamports(
                client,
                keypair=keypair,
                to_pubkey=cold_pubkey,
                lamports=amount_to_send,
                blockhash=blockhash,
            )
            await _confirm_signature(client, signature)
            balance_after = await get_deposit_balance_lamports(
                order["deposit_public_key"],
                client=client,
                commitment=payment_finality(),
            )
            status = "swept" if balance_after == 0 else "dust_unspendable"
            error = None
            if balance_after > 0 and balance_after > fee_lamports:
                access_db.create_sweep(
                    payment_order_id=payment_order_id,
                    deposit_public_key=order["deposit_public_key"],
                    cold_wallet_public_key=cold_wallet,
                    balance_before_lamports=balance_before,
                    fee_lamports=fee_lamports,
                    amount_sent_lamports=amount_to_send,
                    balance_after_lamports=balance_after,
                    sweep_signature=str(signature),
                    status="pending",
                    error="balance remained after sweep; retrying",
                )
                continue
            if balance_after > 0:
                error = "remaining balance is not enough to cover another transfer fee"

            access_db.create_sweep(
                payment_order_id=payment_order_id,
                deposit_public_key=order["deposit_public_key"],
                cold_wallet_public_key=cold_wallet,
                balance_before_lamports=balance_before,
                fee_lamports=fee_lamports,
                amount_sent_lamports=amount_to_send,
                balance_after_lamports=balance_after,
                sweep_signature=str(signature),
                status=status,
                error=error,
            )
            log.info(
                "sweep status=%s order_id=%s deposit=%s balance_before=%s balance_after=%s signature=%s",
                status,
                payment_order_id,
                order["deposit_public_key"],
                balance_before,
                balance_after,
                str(signature),
            )
            final_result = {
                "status": status,
                "signature": str(signature),
                "amountSentLamports": amount_to_send,
                "balanceAfterLamports": balance_after,
            }
            break

    if final_result.get("status") == "swept":
        access_db.execute(
            "UPDATE payment_orders SET status = 'swept', updated_at = ? WHERE id = ?",
            (isoformat(utcnow()), payment_order_id),
        )
    return final_result


async def poll_unswept_deposits(*, run_forever: bool = False) -> dict[str, int]:
    totals = {"checked": 0, "swept": 0, "dust": 0, "failed": 0, "skipped": 0}
    while True:
        access_db.init_db()
        if not env_bool("SWEEP_ENABLED", True):
            if not run_forever:
                return totals
            await asyncio.sleep(sweep_poll_interval_seconds())
            continue

        orders = access_db.confirmed_unswept_orders()
        for order in orders:
            totals["checked"] += 1
            confirmed_at = parse_datetime(order["confirmed_at"])
            if confirmed_at and utcnow() < confirmed_at + timedelta(seconds=env_int("SWEEP_AFTER_SECONDS", 60)):
                totals["skipped"] += 1
                continue
            try:
                result = await sweep_deposit_to_cold(int(order["id"]))
                if result["status"] == "swept":
                    totals["swept"] += 1
                elif result["status"] == "dust_unspendable":
                    totals["dust"] += 1
                elif result["status"] == "already_swept":
                    totals["skipped"] += 1
                else:
                    totals["failed"] += 1
            except Exception as exc:
                totals["failed"] += 1
                access_db.create_sweep(
                    payment_order_id=int(order["id"]),
                    deposit_public_key=order["deposit_public_key"],
                    cold_wallet_public_key=os.getenv("SOLANA_COLD_WALLET_PUBLIC_KEY", ""),
                    balance_before_lamports=0,
                    fee_lamports=0,
                    amount_sent_lamports=0,
                    balance_after_lamports=None,
                    sweep_signature=None,
                    status="failed",
                    error=safe_error(exc),
                )
                log.warning(
                    "sweep failed order_id=%s deposit=%s error=%s",
                    order["id"],
                    order["deposit_public_key"],
                    safe_error(exc),
                )

        if not run_forever:
            return totals
        await asyncio.sleep(sweep_poll_interval_seconds())
