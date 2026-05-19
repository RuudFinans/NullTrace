"""
utils.wallet – deposit-poller · withdraw-poller · sweep · send_sol · pris-helper
"""

from __future__ import annotations
import logging
logging.basicConfig(level=logging.INFO)
import os, asyncio, time, json, hmac, hashlib
import threading
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

import aiohttp
from solders.keypair      import Keypair
from solders.pubkey       import Pubkey
from solana.rpc.async_api import AsyncClient
from solana.rpc.types     import Commitment
from solana.transaction   import Transaction
from solders.system_program import TransferParams, transfer
from solana.exceptions    import SolanaRpcException

from .. import socketio
from ..database import db_session
from ..models    import Deposit, User, Withdrawal

# NYTT: affiliate/rollover helpers
from .affiliate import (
    AFFILIATE_BONUS_PCT,
    skim_to_affiliate_wallet,
)
from .rollover import create_rollover_bucket

try:
    # optional imports – nye modeller
    from ..models import (
        AffiliateCode, AffiliateSelection, AffiliatePayout, BonusTierPayout
    )
except Exception:
    AffiliateCode = AffiliateSelection = AffiliatePayout = BonusTierPayout = None

try:
    from app.gdrive_backup import export_deposits_and_keys
except ImportError:
    from ..gdrive_backup import export_deposits_and_keys

# ───────── CONFIG ────────────────────────────────────────────
USE_DEVNET       = os.getenv("SOL_USE_DEVNET", "1") == "1"
RPC_DEV = os.getenv("SOLANA_RPC_DEV", "https://api.devnet.solana.com")
RPC_MAIN = os.getenv("SOLANA_RPC_MAIN", "https://api.mainnet-beta.solana.com")
SOLANA_RPC = RPC_DEV if USE_DEVNET else RPC_MAIN
print("▶ Bruker MAINNET" if not USE_DEVNET else "▶ Bruker DEVNET")
print("▶ SOLANA_RPC =", SOLANA_RPC)

COLD_STORAGE_PUB = os.getenv("COLD_STORAGE_PUB")            # må være satt i .env
HOT_PRIV_HEX     = os.getenv("HOT_PRIV_HEX")                # 128 hex-tegn (64 bytes)
print("▶ HOT_PRIV_HEX len =", len(HOT_PRIV_HEX) if HOT_PRIV_HEX else 0)

LAMPORT          = 1_000_000_000
SWEEP_AFTER_SEC  = int(os.getenv("SWEEP_AFTER_SEC",  "60"))
SWEEP_POLL_SECONDS = int(os.getenv("SWEEP_POLL_SECONDS", "60"))
PENDING_TTL_SEC  = int(os.getenv("PENDING_TTL_SEC", "700"))
WITHDRAW_FEE_PCT = float(os.getenv("WITHDRAW_FEE_PCT", "2.5"))  # prosent, eks. 2.5

# NYTT: deposit bonus tiers (%), 0 = av
DEPOSITBONUS25 = float(os.getenv("DEPOSITBONUS25", "0") or 0)
DEPOSITBONUS50 = float(os.getenv("DEPOSITBONUS50", "0") or 0)
DEPOSITBONUS100 = float(os.getenv("DEPOSITBONUS100", "0") or 0)

# dump-mapper
dump_dir = Path(__file__).resolve().parent.parent / "krypt"
dump_dir.mkdir(parents=True, exist_ok=True)
DEPOSIT_PENDING_FILE    = dump_dir / "depositpending.json"
DEPOSIT_CONFIRMED_FILE  = dump_dir / "depositconfirmed.json"
WITHDRAW_PENDING_FILE   = dump_dir / "withdrawpending.json"
WITHDRAW_CONFIRMED_FILE = dump_dir / "withdrawconfirmed.json"
SWEEP_LOG_FILE          = dump_dir / "sweeps.json"
AFFILIATE_SKIM_FILE     = dump_dir / "affiliate_skim.json"   # NY

FEE_MARGIN = 1000000        # 0.00001 SOL, mer enn nok på devnet/mainnet

def run_gdrive_backup_bg():
    def _runner():
        try:
            export_deposits_and_keys()
        except Exception as e:
            logging.error("[gdrive-backup ERROR] %s", e)
    threading.Thread(target=_runner, daemon=True).start()

# ───────── helper-funksjoner ─────────────────────────────────
def _load_keypair(hexstr:str)->Keypair:
    b = bytes.fromhex(hexstr)
    if len(b)==32: return Keypair.from_seed(b)
    if len(b)==64: return Keypair.from_bytes(b)
    raise ValueError("private key må være 32 eller 64 bytes")

async def _confirm_with_retry(client, sig_obj, tries=5, delay=0.5)->bool:
    """bekreft tx-signatur med eksponentiell back-off"""
    for _ in range(tries):
        try:
            await client.confirm_transaction(sig_obj, commitment="confirmed"); return True
        except SolanaRpcException as e:
            if "429" not in str(e): raise
        await asyncio.sleep(delay); delay*=2
    return False

def _load(p:Path)->list[dict]:              return json.loads(p.read_text()) if p.exists() else []
def _write(p:Path, arr:list[dict])->None:    p.write_text(json.dumps(arr, indent=2))
def _append(p:Path, rec:dict)->None:         a=_load(p); a.append(rec); _write(p,a)

# pris-cache
_PRICE={"ts":0.0,"usd":125.0}
async def sol_price_usd() -> float:
    try:
        if time.time() - _PRICE["ts"] < 60:
            return _PRICE["usd"]
        async with aiohttp.ClientSession() as s:
            resp = await s.get(
                "https://api.coingecko.com/api/v3/simple/price",
                params={"ids": "solana", "vs_currencies": "usd"},
                timeout=10
            )
            d = await resp.json()
        price = float(d.get("solana", {}).get("usd", 0))
        if price > 0:
            _PRICE.update(ts=time.time(), usd=price)
            return price
        else:
            logging.warning("CoinGecko returned no SOL price, fallback to cached")
            return _PRICE["usd"]
    except Exception as e:
        logging.error("ERROR fetching SOL price from CoinGecko: %s", e)
        return _PRICE["usd"]  # fallback!

lamports_to_usd=lambda l: l/LAMPORT*_PRICE["usd"]



async def _price_refresher():
    await asyncio.sleep(2)
    while True:
        try:
            v = await sol_price_usd()  # updates _PRICE in-place
            # broadcast to all clients
            socketio.emit("price_update", {"usd": _PRICE["usd"], "ts": _PRICE["ts"]}, broadcast=True)
        except Exception as e:
            logging.warning("[price_refresher] update failed: %s", e)
        await asyncio.sleep(62)


# ───────── create deposit / withdrawal ──────────────────────
def new_deposit_address(uid: int) -> str:
    kp = Keypair(); now = datetime.now(timezone.utc)
    with db_session() as db:
        db.add(Deposit(user_id=uid, pubkey=str(kp.pubkey()),
                       priv_hex=bytes(kp).hex(), status="PENDING", created_utc=now))
        name = db.get(User, uid).username
    _append(DEPOSIT_PENDING_FILE, {
        "username": name, "pubkey": str(kp.pubkey()),
        "priv_hex": bytes(kp).hex(), "status": "PENDING", "lamports": None,
        "created_utc": now.isoformat(), "confirmed_utc": None
    })
    run_gdrive_backup_bg()
    return str(kp.pubkey())

def new_withdrawal(db, uid: int, dest: str, lam: int) -> int:
    from datetime import datetime, timezone
    import traceback

    logging.info("=" * 50)
    logging.info(f"[new_withdrawal] CALLED! uid={uid} dest={dest[:8]}... lam={lam}")
    now = datetime.now(timezone.utc)

    try:
        own_deposits = db.query(Deposit).filter(Deposit.user_id == uid).all()
        if any(dep.pubkey == dest for dep in own_deposits):
            raise Exception("Withdrawal to your own deposit address is not allowed.")

        hot_pubkey = _load_keypair(HOT_PRIV_HEX).pubkey()
        if dest == str(hot_pubkey):
            raise Exception("Withdrawal to the main site wallet is not allowed.")

        # ---------- fee ----------
        fee_lam  = int(lam * WITHDRAW_FEE_PCT / 100)
        send_lam = lam - fee_lam
        if send_lam <= 0:
            raise Exception("Withdrawal amount too low after fee.")

        w = Withdrawal(
            user_id=uid,
            dest_pubkey=dest,
            lamports=send_lam,
            status="PENDING",
            created_utc=now
        )
        db.add(w); db.flush()

        user = db.get(User, uid)
        name = user.username if user else "<UKJENT>"

        _append(WITHDRAW_PENDING_FILE, {
            "id": w.id,
            "username": name,
            "dest_pubkey": dest,
            "lamports": send_lam,
            "created_utc": now.isoformat(),
            "status": "PENDING",
            "tx_sig": None,
            "confirmed_utc": None
        })

        run_gdrive_backup_bg()
        return w.id

    except Exception as e:
        logging.error("[new_withdrawal] ERROR: %s", e)
        import traceback; traceback.print_exc()
        raise

# ───────── sweep-poller (uendret) ─────────
async def poll_unswept_balances() -> None:
    await asyncio.sleep(10)
    while True:
        with db_session() as db:
            deposits = db.query(Deposit.id, Deposit.priv_hex, Deposit.pubkey, Deposit.lamports).all()
        for dep_id, priv_hex, pubkey, lamports in deposits:
            try:
                async def check_and_sweep():
                    async with AsyncClient(SOLANA_RPC) as c:
                        bal = (await c.get_balance(Pubkey.from_string(pubkey), commitment=Commitment("processed"))).value
                        rent_exempt = (await c.get_minimum_balance_for_rent_exemption(0)).value
                        min_left = rent_exempt + 10_000
                        if bal > min_left:
                            logging.info(f"[poll_unswept_balances] Sweeper dep_id={dep_id}, bal={bal}, rent+fee={min_left}")
                            await sweep_to_cold(0, priv_hex)
                        else:
                            logging.info(f"[poll_unswept_balances] Ikke nok for sweep dep_id={dep_id}, bal={bal}, rent+fee={min_left}")
                asyncio.create_task(check_and_sweep())
            except Exception as e:
                logging.error("[poll_unswept_balances] ERROR: %s", e)
        await asyncio.sleep(SWEEP_POLL_SECONDS)

# ───────── sweep én deposit-wallet ──────────────────────────
async def sweep_to_cold(_: int, priv_hex: str) -> None:
    import traceback
    await asyncio.sleep(SWEEP_AFTER_SEC)
    try:
        kp = _load_keypair(priv_hex)
        async with AsyncClient(SOLANA_RPC) as c:
            bal = (await c.get_balance(kp.pubkey(), commitment=Commitment("processed"))).value
            rent_exempt = (await c.get_minimum_balance_for_rent_exemption(0)).value
            FEE_MARGIN = 10_000
            min_left = rent_exempt + FEE_MARGIN
            if bal <= min_left:
                logging.info(f"[sweep_to_cold] Ikke nok saldo til sweep (bal={bal}, rent+fee={min_left})")
                return
            send_amt = bal - min_left
            if send_amt <= 0:
                return
            bh = (await c.get_latest_blockhash()).value.blockhash
            tx = Transaction(recent_blockhash=bh).add(
                transfer(TransferParams(
                    from_pubkey=kp.pubkey(),
                    to_pubkey=Pubkey.from_string(COLD_STORAGE_PUB),
                    lamports=send_amt
                ))
            )
            sig_obj = (await c.send_transaction(tx, kp)).value
            sig = str(sig_obj)
            ok = await _confirm_with_retry(c, sig_obj)
            _append(SWEEP_LOG_FILE, {
                "ts": datetime.now(timezone.utc).isoformat(),
                "src": str(kp.pubkey()),
                "lamports": send_amt,
                "left": min_left,
                "sig": sig,
                "confirmed": ok
            })
            try:
                export_deposits_and_keys()
            except Exception as e:
                logging.error("[gdrive-backup sweep ERROR] %s", e)
                traceback.print_exc()
    except Exception as e:
        logging.error("[sweep-error] %s", e)
        traceback.print_exc()

# ───────── deposit-poller (ENDRET) ──────────────────────────
async def poll_pending_deposits(app) -> None:
    await asyncio.sleep(2)
    async with AsyncClient(SOLANA_RPC) as client:
        while True:
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=PENDING_TTL_SEC)
            with db_session() as db:
                # Merk EXPIRED deposits
                for d in db.query(Deposit).filter(Deposit.status=="PENDING",
                                                  Deposit.created_utc < cutoff):
                    d.status = "EXPIRED"
                pendings = db.query(Deposit).filter_by(status="PENDING").all()

            for dep in pendings:
                pubkey = Pubkey.from_string(dep.pubkey)
                bal = (await client.get_balance(pubkey, commitment=Commitment("processed"))).value
                if bal <= 0:
                    continue

                rent_exempt = (await client.get_minimum_balance_for_rent_exemption(0)).value

                with db_session() as db:
                    d = db.get(Deposit, dep.id)
                    u = db.get(User, d.user_id)

                    # Første måling: kreditér alt over rent-exempt
                    if d.lamports is None:
                        delta = bal - rent_exempt
                        if delta <= 0:
                            d.lamports = bal
                            continue
                    else:
                        delta = bal - d.lamports
                        if delta <= 0:
                            d.lamports = bal
                            continue

                    # --------- BONUS & AFFILIATE BEREGNING ---------
                    usd_val = lamports_to_usd(delta)

                    # campaign-tier
                    tier_pct = 0.0
                    tier_label = ""
                    if 25 <= usd_val < 50 and DEPOSITBONUS25 > 0:
                        tier_pct = DEPOSITBONUS25; tier_label = "25"
                    elif 50 <= usd_val < 100 and DEPOSITBONUS50 > 0:
                        tier_pct = DEPOSITBONUS50; tier_label = "50"
                    elif usd_val >= 100 and DEPOSITBONUS100 > 0:
                        tier_pct = DEPOSITBONUS100; tier_label = "100"
                    tier_bonus = int((delta * tier_pct) // 100)

                    # affiliate – finn referrer hvis valgt
                    aff_depositor_bonus = 0
                    aff_referrer_cut = 0
                    referrer_user_id = None

                    try:
                        if AffiliateSelection and AffiliateCode:
                            sel = db.query(AffiliateSelection).filter_by(user_id=u.id).first()
                            if sel:
                                code = db.query(AffiliateCode).get(sel.code_id)
                                if code and code.user_id != u.id:
                                    referrer_user_id = code.user_id
                                    aff_depositor_bonus = int((delta * AFFILIATE_BONUS_PCT) // 100)
                                    aff_referrer_cut    = int((delta * AFFILIATE_BONUS_PCT) // 100)
                    except Exception as e:
                        logging.warning(f"[deposit-poller] affiliate lookup failed: {e}")

                    # --------- KREDITERING ---------
                    u.balance_lamports += (delta + aff_depositor_bonus + tier_bonus)
                    d.lamports = bal
                    if d.status != "CONFIRMED":
                        d.status = "CONFIRMED"
                        d.confirmed_utc = datetime.now(timezone.utc)

                    # --------- LOGGING I NYE TABELLER ---------
                    try:
                        if aff_depositor_bonus or aff_referrer_cut:
                            ap = AffiliatePayout(
                                depositor_user_id=u.id,
                                referrer_user_id=referrer_user_id,
                                deposit_id=d.id,
                                lamports_base_delta=delta,
                                pct=float(AFFILIATE_BONUS_PCT),
                                depositor_bonus_lamports=aff_depositor_bonus,
                                referrer_bonus_lamports=aff_referrer_cut,
                                created_utc=datetime.now(timezone.utc)
                            )
                            db.add(ap)
                            db.flush()

                        if tier_bonus:
                            bp = BonusTierPayout(
                                user_id=u.id,
                                deposit_id=d.id,
                                lamports_base_delta=delta,
                                usd_value_used=float(usd_val),
                                tier=tier_label or "",
                                pct=float(tier_pct),
                                bonus_lamports=tier_bonus,
                                created_utc=datetime.now(timezone.utc)
                            )
                            db.add(bp)
                    except Exception as e:
                        logging.warning(f"[deposit-poller] bonus/affiliate log fail: {e}")

                    # --------- ROLLOVER-BUCKET ---------
                    try:
                        bonus_sum = aff_depositor_bonus + tier_bonus
                        create_rollover_bucket(
                            user_id=u.id,
                            deposit_id=d.id,
                            base_delta_lamports=delta,
                            bonus_lamports_sum=bonus_sum,
                            base_mode=None,   # ta fra env
                            multiplier=None   # ta fra env
                        )
                    except Exception as e:
                        logging.warning(f"[deposit-poller] rollover bucket create failed: {e}")

                # --------- SOCKET-OPPDATERING ---------
                with app.app_context():
                    try:
                        socketio.emit("deposit_confirmed",
                            {"lamports": delta, "usd": lamports_to_usd(delta),
                             "new_total": u.balance_lamports}, room=f"user{u.id}")
                    except Exception:
                        pass

                # --------- AFFILIATE SKIM ON-CHAIN ---------
                if aff_referrer_cut > 0 and referrer_user_id:
                    try:
                        sig, sent = await skim_to_affiliate_wallet(dep.priv_hex, aff_referrer_cut)
                        _append(AFFILIATE_SKIM_FILE, {
                            "ts": datetime.now(timezone.utc).isoformat(),
                            "deposit_id": dep.id,
                            "depositor_user_id": u.id,
                            "referrer_user_id": referrer_user_id,
                            "requested_lamports": aff_referrer_cut,
                            "sent_lamports": sent,
                            "tx_sig": sig
                        })
                        # oppdater siste AffiliatePayout med skim-info
                        with db_session() as db:
                            try:
                                ap = (db.query(AffiliatePayout)
                                      .filter(AffiliatePayout.deposit_id == dep.id,
                                              AffiliatePayout.depositor_user_id == u.id)
                                      .order_by(AffiliatePayout.id.desc())
                                      .first())
                                if ap:
                                    ap.skim_tx_sig = sig
                                    ap.skim_sent_lamports = int(sent or 0)
                                    ap.skim_status = "CONFIRMED" if sig else "FAILED"
                            except Exception as e:
                                logging.warning(f"[deposit-poller] update AffiliatePayout skim: {e}")
                    except Exception as e:
                        logging.error(f"[deposit-poller] affiliate skim failed: {e}")

                # --------- sweep om nødvendig ---------
                min_left = rent_exempt + 10_000
                if bal > min_left:
                    asyncio.create_task(sweep_to_cold(bal, dep.priv_hex))

            # oppdater dumpfiler
            pend, conf = [], []
            with db_session() as db:
                for d in db.query(Deposit).all():
                    row = {"username": db.get(User, d.user_id).username, "pubkey": d.pubkey,
                           "status": d.status, "lamports": d.lamports,
                           "created_utc": d.created_utc.isoformat(),
                           "confirmed_utc": d.confirmed_utc.isoformat() if d.confirmed_utc else None}
                    (pend if d.status == "PENDING" else conf).append(row)
            _write(DEPOSIT_PENDING_FILE, pend)
            _write(DEPOSIT_CONFIRMED_FILE, conf)
            await asyncio.sleep(10)

# ───────── withdraw-poller (uendret) ──────────────────────────────────
async def poll_pending_withdrawals(app)->None:
    await asyncio.sleep(5)
    hot_kp=_load_keypair(HOT_PRIV_HEX)
    async with AsyncClient(SOLANA_RPC) as client:
        while True:
            with db_session() as db:
                pendings=db.query(Withdrawal).filter_by(status="PENDING").all()
            for w in pendings:
                try:
                    tx=Transaction(recent_blockhash=(await client.get_latest_blockhash()).value.blockhash)\
                        .add(transfer(TransferParams(from_pubkey=hot_kp.pubkey(),
                                                     to_pubkey=Pubkey.from_string(w.dest_pubkey),
                                                     lamports=w.lamports)))
                    sig_obj=(await client.send_transaction(tx,hot_kp)).value
                    sig=str(sig_obj)
                    ok=await _confirm_with_retry(client,sig_obj)
                    status="CONFIRMED" if ok else "SUBMITTED"
                except Exception:
                    app.logger.exception(f"[withdraw-poller] error id={w.id}")
                    status="SUBMITTED"; sig=None
                conf=datetime.now(timezone.utc)
                with db_session() as db:
                    rec=db.get(Withdrawal,w.id)
                    rec.status=status; rec.tx_sig=sig; rec.confirmed_utc=conf

                pend,conf_list=[],[]
                with db_session() as db:
                    for x in db.query(Withdrawal).all():
                        row={"id":x.id,"username":db.get(User,x.user_id).username,
                             "dest_pubkey":x.dest_pubkey,"lamports":x.lamports,
                             "created_utc":x.created_utc.isoformat(),"status":x.status,
                             "tx_sig":x.tx_sig,
                             "confirmed_utc":x.confirmed_utc.isoformat() if x.confirmed_utc else None}
                        (pend if x.status=="PENDING" else conf_list).append(row)
                _write(WITHDRAW_PENDING_FILE,pend); _write(WITHDRAW_CONFIRMED_FILE,conf_list)

                with app.app_context():
                    socketio.emit("withdraw_update",
                        {"id":w.id,"status":status,"lamports":w.lamports,
                         "usd":lamports_to_usd(w.lamports),"tx_sig":sig,
                         "created_utc":w.created_utc.isoformat(),
                         "confirmed_utc":conf.isoformat()}, room=f"user{w.user_id}")
            await asyncio.sleep(15)

# ───────── send_sol helper ──────────────────────────────────
def send_sol(to_pub:str, lamports:int)->None:
    if not HOT_PRIV_HEX:
        logging.info(f"[send_sol] stub send {lamports/LAMPORT:.4f} SOL -> {to_pub}")
        return
    async def _send():
        try:
            kp=_load_keypair(HOT_PRIV_HEX)
            async with AsyncClient(SOLANA_RPC) as client:
                tx=Transaction(recent_blockhash=(await client.get_latest_blockhash()).value.blockhash)\
                    .add(transfer(TransferParams(from_pubkey=kp.pubkey(),
                                                 to_pubkey=Pubkey.from_string(to_pub),
                                                 lamports=lamports)))
                sig_obj=(await client.send_transaction(tx,kp)).value
                await _confirm_with_retry(client,sig_obj)
        except Exception as exc:
            logging.error("[send_sol-error] %s", exc)
    asyncio.create_task(_send())
