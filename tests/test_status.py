from p2pd import *

class TestStatus(unittest.IsolatedAsyncioTestCase):

    async def test_stun_client(self):
        nic = await Interface("wlx00c0cab5760d")
        out = await get_stun_clients(IP6, 1, nic, TCP)
        print(out)

        return

        dest = ("stunserver2024.stunprotocol.org", 3478)
        client = STUNClient(IP6, dest, nic, proto=TCP)
        out = await client.get_mapping()
        print(out)

    async def test_pnp_client(self):
        nic = await Interface()
        af = nic.supported()[0]
        sys_clock = await SysClock(nic,clock_skew=Dec(0))
        #sys_clock = await SysClock(nic)

        serv = PNP_SERVERS[af][0]

        node_extra = P2PNodeExtra()
        node_extra.listen_port = NODE_PORT
        sk = node_extra.load_signing_key()
        client = PNPClient(
            sk=sk,
            dest=(serv["ip"], serv["port"]),
            dest_pk=h_to_b(serv["pk"]),
            nic=nic,
            sys_clock=sys_clock,
        )

        """
        print(client)

        out = await client.fetch("test3")
        print(serv["ip"])
        print(out)
        print(out.value)

        # Test host res works

        out = await client.push("test3", "change")
        print(out.value)
        print(out.updated)

        return
        """

        nick = Nickname(
            sk=sk,
            ifs=[nic],
            sys_clock=sys_clock,
        )

        await nick.start()

        out = await nick.fetch("test3.peer")
        print(out)
        print(out.value)

        await nick.push("test3.peer", "change33")

        out = await nick.fetch("test3.peer")
        print(out)
        print(out.value)

        
