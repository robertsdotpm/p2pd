from p2pd import *
from ecdsa import SigningKey, SECP256k1
import hashlib

NIC_NAME = ""

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
                    print(fstr("dns / addr {0} {1} duplicate tup {2}", (af, host, tup,)))
                    print(fstr("dns may be broken"))
                    continue
                else:
                    print(fstr("dns / addr {0} {1} -> {2} resolve success", (af, host, tup,)))
                    tups[tup] = 1

    async def test_clock_skew(self):
        nic = await Interface(NIC_NAME)
        clock = await SysClock(nic)
        if not len(clock.data_points):
            print(fstr("clock skew failed to get data points"))
        elif len(clock.data_points) < clock.min_data:
            print(fstr("clock skew failed to get min data points"))
        else:
            print(fstr("clock skew succeeded"))

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
                    print(fstr("mqtt {0} {1} broken", (af, dest,)))
                else:
                    print(fstr("mqtt {0} {1} works", (af, dest,)))

                await client.close()

    async def test_turn_client_multi(self):
        return
        afs = [IP4] # Only really tested with IP4 unfortunately.
        # Need another con with ipv6 for myself.
        hosts = ["turn1.p2pd.net", "turn2.p2pd.net"]
        
        """
        af = IP4
        
        a_nic = await Interface()
        

        # TURN server config.
        dest = (hosts[0], 3478)
        auth = ("", "")
                

        # Start TURN clients.
        a_client = await TURNClient(af, dest, a_nic, auth, realm=None)

        # In practice you will have to exchange these tups via your protocol.
        # I use MQTT for doing that. See diagram steps (1)(3).
        a_addr, a_relay = await a_client.get_tups()
        print(a_addr, a_relay)
        return
        """
                    
                    
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
                    print(fstr("turn {0} {1} works", (af, dest,)))
                else:
                    print(fstr("turn {0} {1} failed", (af, dest,)))

                # Tell server to close resources for our client.
                await a_client.close()
                await b_client.close()


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
                nic = await Interface()

                # Start TURN clients.
                client = await TURNClient(af, dest, nic, auth, realm=None)
                if client is None:
                    print(fstr("turn {0} broken", (host,)))
                    continue

                # In practice you will have to exchange these tups via your protocol.
                # I use MQTT for doing that. See diagram steps (1)(3).
                a_addr, a_relay = await client.get_tups()
                if a_addr is None or a_relay is None:
                    print(fstr("turn {0} broken", (host,)))
                    continue
                
                # Tell server to close resources for our client.
                await client.close()
                print(fstr("turn {0} works", (host,)))

    async def test_stun_client(self):
        hosts = ["stun1.p2pd.net", "stun2.p2pd.net"]
        nic = await Interface(NIC_NAME)
        for af in nic.supported():
            for proto in [UDP, TCP]:
                for host in hosts:
                    dest = (host, 34780)
                    client = STUNClient(af, dest, nic, proto=proto)
                    out = await client.get_mapping()
                    if out is None:
                        print(fstr("stun {0} {1} {2} failed", (af, dest, proto,)))
                    else:
                        print(fstr("stun {0} {1} {2} works", (af, dest, proto,)))

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
                    print(fstr("pnp {0} {1} failed", (af, dest,)))
                else:
                    print(fstr("pnp {0} {1} success", (af, dest,)))

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
            print(fstr("register {0} tld failed = {1}", (name, fqn,)))
        else:
            print(fstr("register {0} tld success = .peer", (name,)))

        # Test pull works.
        out = await nick.fetch(fqn_name)
        if out.value != val:
            print(fstr("register store failed"))
        else:
            print(fstr("register store success"))

        await nick.delete(fqn_name)

        # Test pull works.
        try:
            out = await nick.fetch(fqn_name)
            print(fstr("delete name failure"))
        except:
            print(fstr("delete name success"))


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
            print(fstr("Encryption is broken."))
        else:
            print(fstr("Encryption works"))

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
        
if __name__ == '__main__':
    main()