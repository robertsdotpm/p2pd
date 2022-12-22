import multiprocessing
from p2pd.test_init import *
from p2pd.base_stream import *
from p2pd.turn_defs import *
from p2pd.turn_client import *

asyncio.set_event_loop_policy(SelectorEventPolicy())
class TestTurn(unittest.IsolatedAsyncioTestCase):
    async def test_turn(self):
        #print(sys.modules.keys())
        # Network interface details.
        await init_p2pd()
        log(">>> test_turn")
        n = 0
        i = await Interface().start_local()
        af = i.supported()[0]
        r = await i.route(af).bind()

        # Address of a TURN server.
        dest = await Address(
            TURN_SERVERS[n]["host"],
            TURN_SERVERS[n]["port"]
        ).res(r)

        # Implement the TURN protocol for UDP send / recv.
        client = TURNClient(
            turn_addr=dest,
            turn_user=TURN_SERVERS[n]["user"],
            turn_pw=TURN_SERVERS[n]["pass"],
            turn_realm=TURN_SERVERS[n]["realm"],
            route=r
        )

        # Wait for authentication and relay address allocation.
        await async_wrap_errors(
            client.start()
        )

        await asyncio.sleep(8)

        # The external address of ourself seen by the TURN server.
        client_tup = await client.client_tup_future

        # The relay address used to reach our peer at the TURN server.
        relay_tup = await client.relay_tup_future

        # Interested in any messages to queue.
        client.subscribe(SUB_ALL)

        # Send a message to our relay address.
        msg = b"test msg to send."
        await client.send(msg, relay_tup)

        # Attempt to read the message back.
        out = await client.recv(SUB_ALL, 4)
        self.assertEqual(msg, out)

        # Test refresh.
        client.lifetime = 0
        await async_retry(
            lambda: client.refresh_allocation(), count=3, timeout=5
        )
        self.assertTrue(client.lifetime)

        # Permission refresh.
        await client.accept_peer(client_tup, relay_tup)

        # Cleanup the client.
        await client.close()

if __name__ == '__main__':
    main()