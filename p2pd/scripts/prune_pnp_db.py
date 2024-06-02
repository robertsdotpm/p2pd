import time
from p2pd import *

async def prune_pnp_db():
    serv = await start_pnp_server(PNP_PORT + 10)
    db_con = await aiomysql.connect(
        user=serv.db_user, 
        password=serv.db_pass,
        db=serv.db_name
    )

    async with db_con.cursor() as cur:
        updated = time.time()
        await verified_pruning(db_con, cur, serv, updated)

    db_con.close()
    await serv.close()

async_test(prune_pnp_db)