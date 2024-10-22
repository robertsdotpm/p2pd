from p2pd import *

"""
{'mode': 1, 'host': 'stun2.p2pd.net', 'primary': {'ip': '88.99.211.211', 'port': 34780}, 'secondary': {'ip': "88.99.211.216", 'port': 34790}}
{'mode': 1, 'host': 'stun2.p2pd.net', 'primary': {'ip': '2a01:4f8:10a:3ce0::2', 'port': 34780}, 'secondary': {'ip': "2a01:4f8:10a:3ce0::3", 'port': 34790}}

ovh1_stun = ("2607:5300:60:80b0::1", 34780) TCP
ovh1_stun = ("2607:5300:60:80b0::1", 34780) UDP
ovh1_stun = ("158.69.27.176", 34780) UDP
ovh1_stun = ("158.69.27.176", 34780) TCP
ovh1_turn = ("158.69.27.176", 3478) leave realm and user pw blank / default
ovh1_mqtt = "158.69.27.176", 1883)
ovh1_mqtt = ("2607:5300:60:80b0::1", 1883)
echod on 7 for 158.69.27.176 / 2607:5300:60:80b0::1 tcp udp

---------------

hetzner1_mqtt = ("2a01:4f8:10a:3ce0::2", 1883)
hetzner1_mqtt = ("88.99.211.211", 1883)
hetzner1_turn = ("88.99.211.211", 3478) leave realm and user pw blank / default

88.99.211.211		static.211.211.99.88.clients.your-server.de	 Yes  No	200	2000	20
	88.99.211.216	
    
   2a01:4f8:10a:3ce0::2 / 3 / 64

./stunserver --family 4 --protocol tcp --primaryport 34780 --altport 34790 --mode full &
./stunserver --family 6 --protocol tcp --primaryport 34780 --altport 34790 --mode full &
./stunserver --family 6 --protocol udp --primaryport 34780 --altport 34790 --mode full &
./stunserver --family 4 --protocol udp --primaryport 34780 --altport 34790 --mode full &
echod on 7 for all ips tcp and udp (88.99.211.216 for ipv4)

"""

async def f_proto(payload, client):
    print(payload)
    print(client)

class TestStatus(unittest.IsolatedAsyncioTestCase):
    async def test_mqtt_server(self):
        dest = ("88.99.211.211", 1883)
        client = await SignalMock("peerid", f_proto, dest).start()
        await client.send_msg("test msg", "peerid")
        await asyncio.sleep(4)
        await client.close()

    async def test_turn_client(self):
        # TURN server config.
        dest = ("88.99.211.211", 3478)
        auth = ("", "")

        # Each interface has a different external IP.
        # Imagine these are two different computers.
        a_nic = await Interface("enp0s25")
        b_nic = await Interface("wlx00c0cab5760d")

        # Start TURN clients.
        a_client = await TURNClient(IP4, dest, a_nic, auth, realm=None)
        b_client = await TURNClient(IP4, dest, b_nic, auth, realm=None)

        # In practice you will have to exchange these tups via your protocol.
        # I use MQTT for doing that. See diagram steps (1)(3).
        a_addr, a_relay = await a_client.get_tups()
        b_addr, b_relay = await b_client.get_tups()

        # White list peers for sending to relay address.
        # See diagram steps (2)(4).
        await a_client.accept_peer(b_addr, b_relay)
        await b_client.accept_peer(a_addr, a_relay)

        # Send a message to Bob at their relay address.
        # See middle of TURN relay diagram.
        buf = b"hello bob"
        for _ in range(0, 3):
            await a_client.send(buf)
        
        # Get msg from Alice from the TURN server.
        # See middle of TURN relay diagram.
        msg = await b_client.recv()
        assert(msg == buf)

        # Tell server to close resources for our client.
        await a_client.close()
        await b_client.close()

    async def test_stun_client(self):
        nic = await Interface("wlx00c0cab5760d")
        #out = await get_stun_clients(IP6, 1, nic, TCP)
        #print(out)

        af = IP4
        proto = UDP
        ovh1_stun = ("88.99.211.216", 34780)

        dest = ovh1_stun
        client = STUNClient(af, dest, nic, proto=proto)
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

        
