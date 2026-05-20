from __future__ import annotations

import argparse
import asyncio
import logging

from . import access_db, wallet


logging.basicConfig(level=logging.INFO)


async def main() -> None:
    parser = argparse.ArgumentParser(description="NullTrace payment maintenance worker")
    parser.add_argument("task", choices=("payment-watch", "sweep", "all"))
    args = parser.parse_args()
    access_db.init_db()
    if args.task == "payment-watch":
        await wallet.poll_pending_payments(run_forever=True)
    elif args.task == "sweep":
        await wallet.poll_unswept_deposits(run_forever=True)
    else:
        await asyncio.gather(
            wallet.poll_pending_payments(run_forever=True),
            wallet.poll_unswept_deposits(run_forever=True),
        )


if __name__ == "__main__":
    asyncio.run(main())
