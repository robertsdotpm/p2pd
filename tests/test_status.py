from p2pd import *
from ecdsa import SigningKey, SECP256k1
import hashlib

NIC_NAME = "wlx00c0cab5760d"

class TestStatus(unittest.IsolatedAsyncioTestCase):
    async def test_address(self):
        nic = await Interface(NIC_NAME)
        hosts = ["www.google.com", "www.example.com", "p2pd.net"]
        tups = {}
        for af in nic.supported():
            for host in hosts:
                addr = await Address(host, 80, nic)
                tup = addr.select_ip(af).tup
                if tup in tups:
                    print(f"dns / addr {af} {host} duplicate tup {tup}")
                    print(f"dns may be broken")
                    continue
                else:
                    print(f"dns / addr {af} {host} -> {tup} resolve success")
                    tups[tup] = 1

    async def test_clock_skew(self):
        nic = await Interface(NIC_NAME)
        clock = await SysClock(nic)
        if not len(clock.data_points):
            print(f"clock skew failed to get data points")
        elif len(clock.data_points) < clock.min_data:
            print(f"clock skew failed to get min data points")
        else:
            print(f"clock skew succeeded")

    async def test_mqtt_client(self):
        msg = "test msg"
        peerid = to_s(rand_plain(10))
        nic = await Interface(NIC_NAME)
        for af in nic.supported():
            for index in [-1, -2]:
                serv_info = MQTT_SERVERS[index]
                dest = (serv_info[af], serv_info["port"])
                found_msg = []

                def closure(ret):
                    async def f_proto(payload, client):
                        if to_s(payload) == to_s(msg):
                            found_msg.append(True)

                    return f_proto

                f_proto = closure(found_msg)
                client = await SignalMock(peerid, f_proto, dest).start()
                await client.send_msg(msg, peerid)
                await asyncio.sleep(2)

                if not len(found_msg):
                    print(f"mqtt {af} {dest} broken")
                else:
                    print(f"mqtt {af} {dest} works")

                await client.close()

    async def test_turn_client(self):
        afs = [IP4] # Only really tested with IP4 unfortunately.
        # Need another con with ipv6 for myself.

        hosts = ["turn1.p2pd.net", "turn2.p2pd.net"]
        for host in hosts:
            for af in afs:
                # TURN server config.
                dest = (host, 3478)
                auth = ("", "")

                # Each interface has a different external IP.
                # Imagine these are two different computers.
                a_nic = await Interface("enp0s25")
                b_nic = await Interface("wlx00c0cab5760d")

                # Start TURN clients.
                a_client = await TURNClient(af, dest, a_nic, auth, realm=None)
                b_client = await TURNClient(af, dest, b_nic, auth, realm=None)

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
                if msg == buf:
                    print(f"turn {af} {dest} works")
                else:
                    print(f"turn {af} {dest} failed")

                # Tell server to close resources for our client.
                await a_client.close()
                await b_client.close()

    async def test_stun_client(self):
        hosts = ["stun1.p2pd.net", "stun2.p2pd.net"]
        nic = await Interface("wlx00c0cab5760d")
        for af in nic.supported():
            for proto in [UDP, TCP]:
                for host in hosts:
                    dest = (host, 34780)
                    client = STUNClient(af, dest, nic, proto=proto)
                    out = await client.get_mapping()
                    if out is None:
                        print(f"stun {af} {dest} {proto} failed")
                    else:
                        print(f"stun {af} {dest} {proto} works")

    async def test_pnp_client(self):
        hosts = [0, 1]
        nic = await Interface(NIC_NAME)
        sys_clock = await SysClock(nic, clock_skew=Dec(0))

        # Pub key crap -- used for signing PNP messages.
        # Pub key will be used as a static name for testing too.
        node_extra = P2PNodeExtra()
        node_extra.listen_port = NODE_PORT
        sk = node_extra.load_signing_key()

        # Try all IPs and AFs.
        name = sk.verifying_key.to_string("compressed")
        name = hashlib.sha256(name).hexdigest()[:25]
        for af in nic.supported():
            for host in hosts:
                serv = PNP_SERVERS[af][host]
                dest = (serv["ip"], serv["port"])
                client = PNPClient(
                    sk=sk,
                    dest=dest,
                    dest_pk=h_to_b(serv["pk"]),
                    nic=nic,
                    sys_clock=sys_clock,
                )

                val = rand_plain(10)
                out = await client.push(name, val)
                out = await client.fetch(name)
                
                
                if out.value != val:
                    print(f"pnp {af} {dest} failed")
                else:
                    print(f"pnp {af} {dest} success")

                out = await client.delete(name)
                out = await client.fetch(name)
                print(out.value)



    async def test_nickname(self):
        print(PNP_SERVERS)
        nic = await Interface(NIC_NAME)
        sys_clock = await SysClock(nic, clock_skew=Dec(0))
        print(nic)

        # Pub key crap -- used for signing PNP messages.
        # Pub key will be used as a static name for testing too.
        node_extra = P2PNodeExtra()
        node_extra.listen_port = NODE_PORT
        sk = node_extra.load_signing_key()
        print(sk)

        # Load nickname client.
        nick = await Nickname(
            sk=sk,
            ifs=[nic],
            sys_clock=sys_clock,
        )

        # Test push works.
        val = rand_plain(10)
        name = sk.verifying_key.to_string("compressed")
        name = hashlib.sha256(name).hexdigest()[:25]
        fqn_name = name + ".peer"
        fqn = await nick.push(name, val)
        if fqn != fqn_name:
            print(f"register {name} tld failed = {fqn}")
        else:
            print(f"register {name} tld success = .peer")

        # Test pull works.
        out = await nick.fetch(fqn_name)
        if out.value != val:
            print(f"register store failed")
        else:
            print(f"register store success")

    async def test_encryption(self):
        # Pub key crap -- used for signing PNP messages.
        # Pub key will be used as a static name for testing too.
        node_extra = P2PNodeExtra()
        node_extra.listen_port = NODE_PORT
        sk = node_extra.load_signing_key()

        dest_sk = ecdsa.SigningKey.generate(curve=SECP256k1)
        dest_vk = dest_sk.verifying_key.to_string("compressed")

        buf = b"A cat is fine too."
        out = encrypt(dest_vk, buf)
        out = decrypt(dest_sk, out)
        if out != buf:
            print(f"Encryption is broken.")
        else:
            print(f"Encryption works")

    async def test_start_node_server(self):

        conf = dict_child({
            "reuse_addr": False,
            "enable_upnp": False,
            "sig_pipe_no": 3,
        }, NET_CONF)

        n = await P2PNode(conf=conf)
        print(n.ifs)
        print(n.addr_bytes)
        print(n.listen_port)
        await n.close()