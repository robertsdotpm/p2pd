from p2pd import *


class TestRUDP(unittest.IsolatedAsyncioTestCase):
    async def test_rudp(self):
        i = await Interface()
        af = i.supported()[0]
        port = 40000
        r = await i.route(af).bind(port)
        dest_tup = (r.nic(), port)
        dest = dest_tup
        pipe = (await pipe_open(
            route=r,
            proto=RUDP,
            dest=dest
        )).subscribe(SUB_ALL)


        msg = b"test meow"
        task, event = await pipe.stream.ack_send(msg, dest_tup)
        await asyncio.wait_for(
            event.wait(),
            2
        )
        out = await pipe.recv(SUB_ALL)
        self.assertEqual(out, msg)
        await pipe.close()

    async def test_is_unique(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        b = PipeEvents(sock=s)
        d = b"ayy lmao"
        c = ("127.0.0.1", 1337)
        r = b.is_unique_msg(
            pipe=None,
            data=d,
            client_tup=c
        )

        self.assertTrue(r)
        s.close()



if __name__ == '__main__':
    main()