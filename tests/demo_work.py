from p2pd import *

async def main():
    nic = await Interface()
    out = await get_n_stun_clients(
        af=IP6,
        n=USE_MAP_NO,
        interface=nic,
        proto=TCP,
        conf=PUNCH_CONF,
    )

    print(out)



asyncio.run(main())