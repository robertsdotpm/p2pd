from decimal import Decimal as Dec
from p2pd.test_init import *
from p2pd.utils import async_test
from p2pd.nat import *
from p2pd.p2p_node import *
from p2pd.stun_client import STUNClient

if __name__ == "__main__":
    async def test_p2p_node():
        # Output the nodes p2p address.
        netifaces = await init_p2pd()
        node = await start_p2p_node(node_id=b"p2pd_test_node", ifs=P2PD_IFS, netifaces=netifaces)
        print(node.addr_bytes)

        # Prevent process from exiting.
        while 1:
            await asyncio.sleep(1)

    async_test(test_p2p_node)

"""
rm -rf program.log; while true; do python3 main.py; sleep 1; done
"""