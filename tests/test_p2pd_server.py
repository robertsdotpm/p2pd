from p2pd import *


class TestP2PDServer(unittest.IsolatedAsyncioTestCase):
    async def test_p2pd_server(self):
        # Start the P2PD server.
        i = await Interface().start()
        r = await i.route().bind()
        server = await start_p2pd_server([i], r, port=P2PD_PORT, do_loop=False, do_init=False, enable_upnp=False)

        # Make server implement a custom ping protocol extension.
        async def proto_extension(msg, client_tup, pipe):
            if b"PING" in msg:
                await pipe.send(b"PONG")
        server.node.add_msg_cb(proto_extension)

        # Server address.
        dest = await Address(r.nic(), P2PD_PORT, r).res()

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
            r = i.route()
            _, resp = await http_req(
                route=r, dest=dest, path=url,
                do_close=True
            )
            out = resp.out()
            j = json.loads(out)

            # IE: no error set.
            assert(j["error"] == 0)

        # Make a new con.
        c2 = "pipe_test"
        r = i.route()
        await http_req(r, dest, "/p2p/open/" + c2 + "/self", do_close=True)

        # Request a new pipe to a named p2p con.
        # This is a cool feature.
        r = i.route()
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