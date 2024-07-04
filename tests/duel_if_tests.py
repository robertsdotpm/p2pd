from p2pd import *
import multiprocessing

"""
They should be on different Internet connections so
there are at least different IP4 routes. This is
needed to test remote TCP punch and to test TURN.
For TURN -- most servers run Coturn which disallows
self-relays (makes sense.) While self-punch to an
external address makes no sense from a routing
perspective (though the code supports self-route.)
"""
IF_ALICE_NAME = "enp0s25"
IF_BOB_NAME = "wlx00c0cab5760d"

async def get_node(if_name, node_port=NODE_PORT):
    iface = await Interface(if_name)
    sys_clock = SysClock(Dec("-0.02839018452552057081653225806"))
    node = P2PNode([iface], port=node_port)

    pe = await get_pp_executors()
    qm = multiprocessing.Manager()
    node.setup_multiproc(pe, qm)
    node.setup_coordination(sys_clock)
    node.setup_tcp_punching()

    return await node.dev()

class TestNodes():
    async def __aenter__(self):
        self.pipe_id = rand_plain(15)
        self.alice = await get_node(IF_ALICE_NAME)
        self.bob = await get_node(IF_BOB_NAME, NODE_PORT + 1)
        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        await self.alice.close()
        await self.bob.close()

class DuelIFTests(unittest.IsolatedAsyncioTestCase):
    async def test_direct_connect(self):
        async with TestNodes() as nodes:
            pipe = await direct_connect(
                nodes.pipe_id,
                nodes.bob.addr_bytes,
                nodes.alice,
            )
            assert(pipe is not None)
            await pipe.close()

    async def test_reverse_connect(self):
        async with TestNodes() as nodes:
            pp = P2PPipe(nodes.alice)

            print("before addr infos")
            msg = await for_addr_infos(
                nodes.pipe_id,
                nodes.alice.addr_bytes,
                nodes.bob.addr_bytes,
                pp.reverse_connect,
            )

            print(msg)
            buf = msg.pack()
            coro = nodes.bob.sig_proto_handlers.proto(buf)
            assert(coro is not None)

            out = await coro
            print(out)

            # Setup the id stuff.

if __name__ == '__main__':
    main()