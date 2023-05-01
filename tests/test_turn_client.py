import multiprocessing
from p2pd.test_init import *
from p2pd.base_stream import *
from p2pd.turn_defs import *
from p2pd.turn_client import *
from p2pd.http_client_lib import *

asyncio.set_event_loop_policy(SelectorEventPolicy())
class TestTurn(unittest.IsolatedAsyncioTestCase):
    async def test_turn(self):
        #print(sys.modules.keys())
        # Network interface details.
        log(">>> test_turn")
        n = 0
        netifaces = await init_p2pd()
        i = await Interface(netifaces=netifaces).start_local()
        af = i.supported()[0]
        r = await i.route(af).bind()

        # Address of a TURN server.
        dest = await Address(
            TURN_SERVERS[n]["host"],
            TURN_SERVERS[n]["port"],
            r
        ).res()

        # Implement the TURN protocol for UDP send / recv.
        client = TURNClient(
            turn_addr=dest,
            turn_user=TURN_SERVERS[n]["user"],
            turn_pw=TURN_SERVERS[n]["pass"],
            turn_realm=TURN_SERVERS[n]["realm"],
            route=r
        )

        # Enable blank UDP headers.
        client.toggle_blank_rudp_headers(True)

        # Wait for authentication and relay address allocation.
        await async_wrap_errors(
            client.start(),
            timeout=10
        )

        # The external address of ourself seen by the TURN server.
        client_tup = await client.client_tup_future

        # The relay address used to reach our peer at the TURN server.
        relay_tup = await client.relay_tup_future

        if P2PD_TEST_INFRASTRUCTURE:
            # Will be used to send packets from.
            dest_p2pd = await Address(
                "p2pd.net",
                20000,
                r
            ).res()

            # Whitelist rest API.
            p2pd_tup = dest_p2pd.tup
            await client.accept_peer(p2pd_tup, p2pd_tup)

            # Interested in any messages to queue.
            client.subscribe(SUB_ALL)

            #await client.accept_peer(client_tup, relay_tup)
            #await client.accept_peer(relay_tup, relay_tup)
            """
            m = TurnMessage(msg_type=TurnMessageMethod.SendResponse, msg_code=TurnMessageCode.Request)
            m.write_attr(
                TurnAttribute.Data,
                b"test message to send."
            )
            buf, _ = TurnMessage.unpack(m.encode())
            buf.write_credential(client.turn_user, client.realm, client.nonce)
            buf.write_hmac(client.key)
            """


            # Attempt to get a reply at our relay address.
            # Do it up to 3 times due to UDP being unreliable.
            got_reply = False
            for i in range(0, 3):
                http_route = copy.deepcopy(r)
                await http_route.bind()
                rest_path = f"/hello/udp/{relay_tup[0]}/{relay_tup[1]}/{dest_p2pd.tup[0]}/63248"
                _, resp = await http_req(http_route, dest_p2pd, rest_path)

                # Attempt to read the message back.
                out = await client.recv(SUB_ALL, 2)
                if out == b"hello":
                    got_reply = True
                    break

            # Make sure we got a valid reply.
            self.assertTrue(got_reply)
        
        # Test refresh.
        client.lifetime = 0
        await async_retry(
            lambda: client.refresh_allocation(), count=3, timeout=5
        )
        self.assertTrue(client.lifetime)

        # Cleanup the client.
        await client.close()

if __name__ == '__main__':
    main()