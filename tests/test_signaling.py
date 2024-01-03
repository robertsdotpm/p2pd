from p2pd.test_init import *
from p2pd.settings import *
from p2pd.signaling import SignalMock
from p2pd.utils import rand_plain, to_s

class TestSignaling(unittest.IsolatedAsyncioTestCase):
    async def test_node_signaling(self):
        if not P2PD_TEST_INFRASTRUCTURE:
            return

        # Channel that the test node subs to.
        i = await Interface().start_local()
        dest_id = "p2pd_test_node"
        msg = "msggg"
        f = asyncio.Future()

        # Receive a message from our MQTT channel (node ID.)
        async def proc_msg(msg, signal_pipe):
            f.set_result(to_s(msg))

        # Start the MQTT client.
        node_id = node_name(b"node_c", i)
        client = None
        for i in range(0, 3):
            client = SignalMock(node_id, proc_msg, mqtt_server=MQTT_SERVERS[i])
            await client.start()

            # Use basic echo protocol to test signaling works.
            await client.echo(msg, dest_id)

            try:
                out = await asyncio.wait_for(
                    f,
                    8
                )
                break
            except Exception:
                what_exception()
                continue

        # Check client set.
        if client is None:
            raise Exception("Couldn't connect to an mqtt server.")


        # Check results and cleanup.
        self.assertTrue(msg in out)
        await client.close()

if __name__ == '__main__':
    main()