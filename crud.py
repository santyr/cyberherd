from typing import List

from lnbits.helpers import urlsafe_short_hash

from . import db
from .models import Target


async def get_targets(source_wallet: str) -> List[Target]:
    rows = await db.fetchall(
        "SELECT * FROM cyberherd.targets WHERE source = ?", (source_wallet,)
    )
    return [Target(**row) for row in rows]


async def set_targets(source_wallet: str, targets: List[Target]):
    async with db.connect() as conn:
        await conn.execute(
            "DELETE FROM cyberherd.targets WHERE source = ?", (source_wallet,)
        )
        for target in targets:
            await conn.execute( #TODO: change to cyberherd
                """
                INSERT INTO cyberherd.targets
                  (id, source, wallet, percent, alias)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    urlsafe_short_hash(),
                    source_wallet,
                    target.wallet,
                    target.percent,
                    target.alias,
                ),
            )
