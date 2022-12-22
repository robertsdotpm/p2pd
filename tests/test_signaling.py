from p2pd.test_init import *
from p2pd.signaling import SignalMock
from p2pd.utils import rand_plain, to_s

class TestSignaling(unittest.IsolatedAsyncioTestCase):
    async def test_signaling(self):
        # Channel that the test node subs to.
        await init_p2pd()
        dest_id = "p2pd_test_node"
        msg = "test msg to send"
        f = asyncio.Future()

        # Receive a message from our MQTT channel (node ID.)
        async def proc_msg(msg):
            f.set_result(to_s(msg))

        # Start the MQTT client.
        node_id = node_name(b"node_c")
        client = SignalMock(node_id, proc_msg)
        await client.start()

        # Use basic echo protocol to test signaling works.
        await client.echo(msg, node_id)
        out = await asyncio.wait_for(
            f,
            4
        )

        # Check results and cleanup.
        self.assertTrue(msg in out)
        await client.close()

if __name__ == '__main__':
    main()