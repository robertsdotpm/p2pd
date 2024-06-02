from p2pd import *

async def run_pnp_server():
    await start_pnp_server(PNP_PORT)

    # Sleep forever.
    while 1:
        await asyncio.sleep(1)

async_test(run_pnp_server)

