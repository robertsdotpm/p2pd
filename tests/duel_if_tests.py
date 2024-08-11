"""
It probably has a bug with the context manager.
I don't have time to fix it so just write a simple function
that runs the tests and call with the async_test.
"""

from p2pd import *
import multiprocessing

TEST_P2P_PIPE_CONF = {
    "addr_types": [EXT_BIND, NIC_BIND],
    "return_msg": True,
}

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

async def get_node(if_name, node_port=NODE_PORT, sig_pipe_no=SIGNAL_PIPE_NO):
    delta = delta_info(NA_DELTA, 0)
    nat = nat_info(OPEN_INTERNET, delta)
    iface = await Interface(if_name)
    iface.set_nat(nat)
    sys_clock = SysClock(Dec("-0.02839018452552057081653225806"))
    conf = copy.deepcopy(NODE_CONF)
    conf["sig_pipe_no"] = sig_pipe_no
    node = P2PNode([iface], port=node_port, conf=conf)

    pe = await get_pp_executors()
    qm = multiprocessing.Manager()
    node.setup_multiproc(pe, qm)
    node.setup_coordination(sys_clock)
    node.setup_tcp_punching()

    return await node.dev()

class TestNodes():
    def __init__(self, same_if=False, addr_types=[EXT_BIND, NIC_BIND], return_msg=True, sig_pipe_no=SIGNAL_PIPE_NO):
        self.same_if = same_if
        self.addr_types = addr_types
        self.return_msg = return_msg
        self.sig_pipe_no = sig_pipe_no

    async def __aenter__(self):
        # Setup node on specific interfaces.
        if self.same_if:
            self.alice = await get_node(
                IF_ALICE_NAME,
                sig_pipe_no=self.sig_pipe_no,
            )

            self.bob = await get_node(
                IF_ALICE_NAME,
                NODE_PORT + 1,
                sig_pipe_no=self.sig_pipe_no,
            )
        else:
            self.alice = await get_node(
                IF_ALICE_NAME,
                sig_pipe_no=self.sig_pipe_no,
            )

            self.bob = await get_node(
                IF_BOB_NAME,
                NODE_PORT + 1,
                sig_pipe_no=self.sig_pipe_no,
            )

        # Build p2p con pipe config.
        conf = {
            "addr_types": self.addr_types,
            "return_msg": self.return_msg,
        }

        # Set pipe conf.
        self.pp_alice = self.alice.p2p_pipe(
            self.bob.addr_bytes,
            conf=conf
        )
        self.alice.sig_proto_handlers.conf = conf
        self.bob.sig_proto_handlers.conf = conf

        # Short reference var.
        self.pipe_id = self.pp_alice.pipe_id

        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        await self.alice.close()
        await self.bob.close()

async def test_dir_direct_con_lan_ext():
    params = {
        "return_msg": True,
        "sig_pipe_no": 0,
        "addr_types": [NIC_BIND, EXT_BIND],
    }

    async with TestNodes(**params) as nodes:
        pipe = await nodes.pp_alice.connect(
            strategies=[P2P_DIRECT]
        )
        print(pipe)
        assert(pipe is not None)
        await pipe.close()

async def test_dir_direct_con_fail_lan():
    params = {
        "return_msg": True,
        "sig_pipe_no": 1,
        "addr_types": [SIM_FAIL, NIC_BIND],
    }

    async with TestNodes(**params) as nodes:
        pipe = await nodes.pp_alice.connect(
            strategies=[P2P_DIRECT]
        )
        print(pipe)
        assert(pipe is not None)
        await pipe.close()


async def test_node_start():
    """
    node = await get_node(
        IF_ALICE_NAME,
        node_port=NODE_PORT + 1
    )


    node = await get_node(
        IF_BOB_NAME
    )
    """


    async with TestNodes() as nodes:
        #print(nodes.alice.p2p_addr)
        pass
    

async def test_direct_connect():

    async with TestNodes() as nodes:
        pipe = await nodes.pp_alice.connect(
            strategies=[P2P_DIRECT]
        )
        assert(pipe is not None)
        await pipe.close()

async def test_reverse_connect():
    async with TestNodes() as nodes:
        msg = (await nodes.pp_alice.connect(
            strategies=[P2P_REVERSE]
        )).pack()

        await nodes.bob.sig_proto_handlers.proto(msg)
        
        pipe = await nodes.alice.pipes[nodes.pipe_id]
        assert(pipe is not None)
        await pipe.close()

async def test_turn():
    async with TestNodes() as nodes:
        msg = (await nodes.pp_alice.connect(
            strategies=[P2P_RELAY]
        )).pack()

        print("msg1")
        print(msg)

        return

        msg = (await nodes.bob.sig_proto_handlers.proto(msg)).pack()
        print("msg2")
        print(msg)
        
        print(nodes.alice.turn_clients)

        msg = await nodes.alice.sig_proto_handlers.proto(msg)



        pipe_id = nodes.pipe_id
        alice_turn = await nodes.alice.pipes[pipe_id]
        bob_turn = await nodes.bob.pipes[pipe_id]


        assert(alice_turn is not None)
        assert(bob_turn is not None)
        await alice_turn.close()
        await bob_turn.close()

async def test_tcp_punch():
    async with TestNodes(addr_types=[NIC_BIND, EXT_BIND]) as nodes:
        punch_req_msg = await nodes.pp_alice.connect(
            strategies=[P2P_PUNCH]
        )

        print(punch_req_msg.pack())




        # Get punch meeting details.
        resp = await nodes.bob.sig_proto_handlers.proto(
            punch_req_msg.pack()
        )

        print(resp)

        pipe_id = nodes.pipe_id

        print(nodes.bob.pipes)
        print(nodes.alice.pipes)

        
        print("Bob pipes")

        pipe_id = nodes.pipe_id


        bob_hole = await nodes.bob.pipes[pipe_id]
        alice_hole = await nodes.alice.pipes[pipe_id]
            

        print(f"alice hole = {alice_hole}")
        print(f"bob hole = {bob_hole}")

        # Get punch mode code needs to be updated
        # Or rewritten maybe replaced with work behind.

async def test_reverse_connect_with_sig():
    async with TestNodes(return_msg=False) as nodes:
        print(nodes.alice.signal_pipes)
        await nodes.pp_alice.connect(
            strategies=[P2P_REVERSE]
        )


        pipe = await nodes.alice.pipes[nodes.pipe_id]
        assert(pipe is not None)
        await pipe.close()

async def test_turn_with_sig():
    async with TestNodes(return_msg=False) as nodes:
        alice_hole = await nodes.pp_alice.connect(
            strategies=[P2P_RELAY]
        )

        print(f"alice hole = {alice_hole}")

async def test_tcp_punch_with_sig():
    async with TestNodes(return_msg=False) as nodes:
        alice_hole = await nodes.pp_alice.connect(
            strategies=[P2P_PUNCH]
        )

        print(f"alice hole = {alice_hole}")

async def duel_if_tests():
    try:
        #await test_node_start()
        await test_dir_direct_con_fail_lan()
        #await test_dir_direct_con()
        #await test_turn_with_sig()
    except:
        log_exception()

if __name__ == '__main__':
    async_test(duel_if_tests)