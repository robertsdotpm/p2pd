from p2pd import *

# NOTE: changed sub so this is currently broken
class TestP2PDServer(unittest.IsolatedAsyncioTestCase):
    async def test_p2pd_server(self):
        # Start the P2PD server.
        af = IP4
        i = await Interface().start()
        nic_ip = i.route(af).nic()
        r = await i.route(af).bind(ips=nic_ip, port=P2PD_PORT)
        server = await start_p2pd_server(
            r,
            ifs=[i], 
            enable_upnp=False
        )

        conf = dict_child({
            # N seconds before a registering recv timeout.
            "recv_timeout": 100,

            # Only applies to TCP.
            "con_timeout": 100,
        }, NET_CONF)


        # Make server implement a custom ping protocol extension.
        async def proto_extension(msg, client_tup, pipe):
            if b"PING" in msg:
                await pipe.send(b"PONG")
        server.node.add_msg_cb(proto_extension)

        # Server address.
        dest = (nic_ip, P2PD_PORT)

        # List of API end points to check.
        en = lambda x: to_s(urlencode(x))
        sub = en("[hH]e[l]+o")
        c = "con_name"
        urls = [
            # Some stat stuff.
            "/version",
            "/ifs",

            # Open new con.
            "/p2p/open/" + c + "/self",
            "/p2p/con/" + c,

            # Test basic text API stuff.
            "/p2p/sub/" + c + "/msg_p/" + sub,
            "/p2p/send/" + c + "/" + en("ECHO Hello, world!"),
            "/p2p/recv/" + c + "/msg_p/" + sub + "/timeout/2",

            # Test connection close works.
            "/p2p/close/" + c
        ]

        # Just load a bunch of URLs and check for errors.
        # Not the best unit test but over it.
        for url in urls:
            # Convert HTTP response to JSON.
            r = i.route(af)
            print(url)

            _, resp = await http_req(
                route=r, dest=dest, path=url,
                do_close=True,
                conf=conf

            )


            out = resp.out()
            j = json.loads(out)

            # IE: no error set.
            assert(j["error"] == 0)

        # Make a new con.
        c2 = "pipe_test"
        r = i.route(af)
        await http_req(r, dest, "/p2p/open/" + c2 + "/self", do_close=True)

        # Request a new pipe to a named p2p con.
        # This is a cool feature.
        r = i.route(af)
        p, out = await http_req(r, dest, "/p2p/pipe/" + c2, do_close=0)
        msg = b"this is a test"
        await p.send(b"ECHO " + msg)
        got = await p.recv(SUB_ALL, timeout=3)
        assert(msg in got)

        # Test custom protocol extension works.
        await p.send(b"PING")
        out = await p.recv()
        assert(b"PONG" in out)
        await p.close()

        # TODO: Test binary stuff.

        # Cleanup.
        await server.close()


if __name__ == '__main__':
    main()

"""
To do the pipe tests i need to be able to
send http requests on my own pipes
"""