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

def patch_msg_dispatcher(src_pp, src_node, dest_node):
    async def patch():
        try:
            print("in patch")
            msg = await src_pp.msg_queue.get()
            if msg is None:
                src_pp.msg_dispatcher_done.set()
                print("one con finished")
                return
            
            print(msg)
            
            try:
                await dest_node.sig_proto_handlers.proto(
                    msg.pack()
                )
            except asyncio.CancelledError:
                raise Exception("cancelled")
            except:
                what_exception()

            src_pp.msg_dispatcher_task = asyncio.ensure_future(
                src_pp.msg_dispatcher()
            )
        except:
            what_exception()
            if not src_pp.msg_dispatcher_done.is_set():
                src_pp.msg_dispatcher_done.set()
            return

    return patch

def patch_p2p_pipe(src_pp):
    def patch(dest_bytes, reply=None, conf=P2P_PIPE_CONF):
        src_pp.reply = reply
        src_pp.conf = conf
        return src_pp
    
    return patch

def patch_p2p_stats(strategies, src_pp):
    strat_len = len(src_pp.func_table)
    for strategy in strategies:
        if strategy > strat_len: # how many current stats.
            offset = (strategy - strat_len) - 1
            func_info = src_pp.func_table[offset]
            func = func_info[0]

            async def failure(self, af, src_info, dest_info, iface, addr_type):
                # Func runs as usual making any state changes.
                await func(
                    af,
                    src_info,
                    dest_info,
                    iface,
                    addr_type
                )

                # But always fails.
                return None
            
            code = f"src_pp.{func.__name__} = failure"
            print(code)
            eval(code)

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

    return node

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

        # Start the nodes.
        await self.alice.dev()
        await self.bob.dev()

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
        self.pp_bob = self.bob.p2p_pipe(
            self.alice.addr_bytes,
            conf=conf
        )
        self.alice.sig_proto_handlers.conf = conf
        self.bob.sig_proto_handlers.conf = conf

        # Send directly to each other.
        if self.return_msg:
            self.pp_alice.msg_dispatcher = patch_msg_dispatcher(
                self.pp_alice,
                self.alice,
                self.bob,
            )

            self.pp_bob.msg_dispatcher = patch_msg_dispatcher(
                self.pp_bob,
                self.bob,
                self.alice,
            )

            # Return the same pp pipe with patched msg handler.
            self.bob.p2p_pipe = patch_p2p_pipe(self.pp_bob)
            self.alice.p2p_pipe = patch_p2p_pipe(self.pp_alice)
            print("patches applied")

        # Short reference var.
        self.pipe_id = self.pp_alice.pipe_id
        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        print("aexit")
        await self.alice.close()
        await self.bob.close()
        print("nodes closed")

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
        assert(await check_pipe(pipe))
        await pipe.close()

async def test_dir_direct_con_ext_fail_lan_suc():
    params = {
        "return_msg": True,
        "sig_pipe_no": 0,
        "addr_types": [EXT_FAIL, NIC_BIND],
    }

    async with TestNodes(**params) as nodes:
        pipe = await nodes.pp_alice.connect(
            strategies=[P2P_DIRECT]
        )
        print(pipe)
        assert(pipe is not None)
        assert(await check_pipe(pipe))
        await pipe.close()

async def test_reverse_direct_lan():
    params = {
        "return_msg": True,
        "sig_pipe_no": 0,
        "addr_types": [NIC_BIND],
    }

    async with TestNodes(**params) as nodes:
        pipe = await nodes.pp_alice.connect(
            strategies=[P2P_REVERSE]
        )
        print(pipe)
        assert(pipe is not None)
        assert(await check_pipe(pipe))
        await pipe.close()

async def test_turn_direct():
    params = {
        "return_msg": True,
        "sig_pipe_no": 0,
        "addr_types": [EXT_BIND],
    }

    async with TestNodes(**params) as nodes:
        pipe = await nodes.pp_alice.connect(
            strategies=[P2P_RELAY]
        )

        print(pipe)
        assert(pipe is not None)
        assert(await check_pipe(pipe))
        await pipe.close()

async def test_tcp_punch_direct_ext_lan():
    params = {
        "return_msg": True,
        "sig_pipe_no": 0,
        "addr_types": [EXT_BIND, NIC_BIND],
    }

    async with TestNodes(**params) as nodes:
        pipe = await nodes.pp_alice.connect(
            strategies=[P2P_PUNCH]
        )

        print(pipe)
        assert(pipe is not None)
        assert(await check_pipe(pipe))
        await pipe.close()

# Last one doesnt result in sides using same addr type.
async def test_tcp_punch_direct_lan_fail_ext_suc():
    params = {
        "return_msg": True,
        "sig_pipe_no": 0,
        "addr_types": [NIC_FAIL, EXT_BIND],
    }

    async with TestNodes(**params) as nodes:
        pipe = await nodes.pp_alice.connect(
            strategies=[P2P_PUNCH]
        )

        print(pipe)
        assert(pipe is not None)
        assert(await check_pipe(pipe))
        await pipe.close()

async def test_dir_reverse_fail_direct():
    params = {
        "return_msg": True,
        "sig_pipe_no": 0,
        "addr_types": [NIC_BIND],
    }

    strats = [P2P_REVERSE, P2P_DIRECT]
    async with TestNodes(**params) as nodes:
        #patch_p2p_stats(strats, nodes.pp_alice)
        pipe = await nodes.pp_alice.connect(
            strategies=strats
        )

        print(pipe)
        assert(pipe is not None)
        assert(await check_pipe(pipe))
        await pipe.close()
        print("pipe closed")


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

async def duel_if_tests():
    try:
        #await test_node_start()

        # Works.
        #await test_dir_direct_con_lan_ext()

        # Works.
        #await test_dir_direct_con_fail_lan()

        # Works.
        #await test_reverse_direct_lan()

        # Works.
        #await test_turn_direct()

        # Works.
        #await test_tcp_punch_direct_ext_lan()

        # Works
        #await test_tcp_punch_direct_lan_fail_ext_suc()

        await test_dir_reverse_fail_direct()


        # Multiple methods now with failures inbetween.
        # 

        #await test_dir_direct_con()
        #await test_turn_with_sig()
    except:
        log_exception()

if __name__ == '__main__':
    async_test(duel_if_tests)