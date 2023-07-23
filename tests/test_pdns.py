import uuid
from p2pd.test_init import *
from p2pd.p2p_node import *
from p2pd.interface import *
from p2pd.pdns import *

asyncio.set_event_loop_policy(SelectorEventPolicy())
class TestPDNS(unittest.IsolatedAsyncioTestCase):
    async def test_pdns(self):
        # Constants for test.
        registrar_id = "000webhost"
        test_name = str(uuid.uuid4())
        iface = await Interface().start_local()

        # Looping allows for testing both store and update.
        for _ in range(0, 2):
            # Simulate updating a PDNS value.
            test_value = str(uuid.uuid4())

            # Check store / update works.
            node = P2PNode(if_list=[iface])
            out = await node.register(name=test_name, value=test_value, registrar_id=registrar_id)
            assert(out)

            # Check loading value works.
            pdns = PDNS(test_name, registrar_id)
            out = await pdns.res(iface.route())
            assert(out == test_value)

if __name__ == '__main__':
    main()