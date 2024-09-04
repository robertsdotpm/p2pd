"""
return_msg False = use signal pipes
"""

from p2pd import *
import warnings
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

def patch_msg_dispatcher(src_pp, src_node, dest_node):
    async def patch():
        try:
            x = await src_node.sig_msg_queue.get()
            if x is None:
                return
            else:
                msg, _ = x

            # Encrypt the message if the public key is known.
            buf = b"\0" + msg.pack()
            dest_node_id = msg.routing.dest["node_id"]
            # or ... integrity portion...
            if dest_node_id in src_node.auth:
                buf = b"\1" + encrypt(
                    src_node.auth[dest_node_id]["vk"],
                    msg.pack(),
                )
            
            # UTF-8 messes up binary data in MQTT.
            buf = to_h(buf)
            print(buf)
            try:
                await dest_node.sig_proto_handlers.proto(
                    buf
                )
            except asyncio.CancelledError:
                raise Exception("cancelled")
            except:
                log_exception()

            src_node.sig_msg_dispatcher_task = asyncio.ensure_future(
                src_node.sig_msg_dispatcher()
            )
        except:
            log_exception()
            return

    return patch

def patch_p2p_pipe(src_pp):
    def patch(dest_bytes):
        src_pp.reply = None
        return src_pp
    
    return patch

"""
This patches an associated technique function
to always return a failure result. But it will
still run the technique function so that the same
state impacts are done and you can check to see if
the code really can handle a real failure or not.
"""
def patch_p2p_stats(strategies, src_pp):
    is_patched = False
    strat_len = len(src_pp.func_table)
    for strategy in strategies:
        # Indicates not to fail it so continue.
        if strategy <= strat_len:
            continue

        # Workout func table offset from strategy enum.
        offset = (strategy - strat_len)

        # Func info from table.
        func_info = src_pp.func_table[offset]

        # Regular function to execute.
        func_p = func_info[0]

        # Patched function bellow to sim failure.
        def closure(func, timeout):
            async def failure(af, pipe_id, src_info, dest_info, iface, addr_type, reply):
                # May return a success pipe.
                pipe = await asyncio.wait_for(
                    # Just pass all params on to func.
                    func(
                        af,
                        pipe_id,
                        src_info,
                        dest_info,
                        iface,
                        addr_type,
                        reply,
                    ),

                    # Timeout for specific func.
                    timeout
                )

                # Handle cleanup if needed.
                if isinstance(pipe, PipeEvents):
                    await pipe.close()
                
                # But always fails.
                return None
            
            return failure
        
        # Overwrite the func pointer to failure closure.
        src_pp.func_table[offset][0] = closure(func_p, func_info[1])
        is_patched = True

    return is_patched

async def get_node(ifs=[], node_port=NODE_PORT, sig_pipe_no=SIGNAL_PIPE_NO):
    conf = copy.deepcopy(NODE_CONF)
    conf["sig_pipe_no"] = sig_pipe_no
    node = P2PNode(ifs, port=node_port, conf=conf)
    return node

class TestNodes():
    def __init__(self, same_if=False, addr_types=[EXT_BIND, NIC_BIND], return_msg=True, sig_pipe_no=SIGNAL_PIPE_NO, ifs=[], multi_ifs=False):
        self.multi_ifs = multi_ifs
        self.ifs = ifs
        self.same_if = same_if
        if len(ifs) <= 1:
            self.same_if = True
            self.multi_ifs = False

        self.addr_types = addr_types
        self.return_msg = return_msg
        self.sig_pipe_no = sig_pipe_no

        # If sig pipes are needed ensure they're enabled.
        if not self.return_msg:
            if not self.sig_pipe_no:
                self.sig_pipe_no = 2

    async def __aenter__(self):
        # Load the default nic.
        if not len(self.ifs):
            nic = await Interface()
            await nic.load_nat()
            self.ifs = [nic]

        # Setup node on specific interfaces.
        if self.same_if:
            self.alice = await get_node(
                [self.ifs[0]],
                sig_pipe_no=self.sig_pipe_no,
            )

            self.bob = await get_node(
                [self.ifs[0]],
                NODE_PORT + 1,
                sig_pipe_no=self.sig_pipe_no,
            )
        else:
            if self.multi_ifs:
                alice_ifs = self.ifs
                bob_ifs = self.ifs
            else:
                alice_ifs = [self.ifs[0]]
                bob_ifs = [self.ifs[0]]
                if len(self.ifs) >= 2:
                    bob_ifs = [self.ifs[1]]

            self.alice = await get_node(
                alice_ifs,
                sig_pipe_no=self.sig_pipe_no,
            )

            self.bob = await get_node(
                bob_ifs,
                NODE_PORT + 1,
                sig_pipe_no=self.sig_pipe_no,
            )

        # Build p2p con pipe config.
        self.pp_conf = {
            "addr_types": self.addr_types,
            "return_msg": self.return_msg,
        }

        alice_start_sig = self.alice.start_sig_msg_dispatcher
        bob_start_sig = self.bob.start_sig_msg_dispatcher
        self.alice.start_sig_msg_dispatcher = lambda: None
        self.bob.start_sig_msg_dispatcher = lambda: None
        

        # Start the nodes.
        nic = self.alice.ifs[0]
        sys_clock = SysClock(nic, Dec("-0.02839018452552057081653225806"))
        await self.alice.start(sys_clock)
        await self.bob.start(sys_clock)

        # Set pipe conf.
        self.pp_alice = self.alice.p2p_pipe(
            self.bob.addr_bytes
        )
        self.pp_bob = self.bob.p2p_pipe(
            self.alice.addr_bytes
        )
        self.alice.sig_proto_handlers.conf = self.pp_conf
        self.bob.sig_proto_handlers.conf = self.pp_conf

        # Send directly to each other.
        if self.return_msg:
            self.alice.sig_msg_dispatcher = patch_msg_dispatcher(
                self.pp_alice,
                self.alice,
                self.bob,
            )

            self.bob.sig_msg_dispatcher = patch_msg_dispatcher(
                self.pp_bob,
                self.bob,
                self.alice,
            )

        # Return the same pp pipe with patched msg handler.
        # Currently commented to test new pipe behavior.
        # self.bob.p2p_pipe = patch_p2p_pipe(self.pp_bob)
        # self.alice.p2p_pipe = patch_p2p_pipe(self.pp_alice)

        alice_start_sig()
        bob_start_sig()

        # Short reference var.
        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        print("aexit")
        await self.alice.close()
        await self.bob.close()
        print("nodes closed")

async def p2p_check_strats(params):
    strats = [P2P_DIRECT, P2P_REVERSE, P2P_RELAY, P2P_PUNCH]
    strats = [P2P_RELAY]
    async with TestNodes(**params) as nodes:
        for strat in strats:
            pipe = await nodes.alice.connect(
                nodes.bob.addr_bytes,
                strategies=[strat],
                conf=nodes.pp_conf,
            )

            if params["same_if"] == False:
                assert(pipe is not None)
                assert(await check_pipe(pipe))

            if strat in [P2P_PUNCH]:
                if pipe is None:
                    log(f"opt test self {strat} failed")

            if pipe is not None:
                await pipe.close()

    # Give time to close.
    await asyncio.sleep(2)

asyncio.set_event_loop_policy(SelectorEventPolicy())
class TestP2P(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore")

    async def test_p2p_multi_node_ifs(self):
        if_names = await list_interfaces()
        ifs = await load_interfaces(if_names)
        if len(ifs) <= 1:
            print("skipping multi if tests -- only one if")
            return

        params = {
            "return_msg": False,
            "addr_types": [EXT_BIND, NIC_BIND],
            "ifs": ifs,
            "same_if": False if len(ifs) >= 2 else True,
            "multi_ifs": True,
        }

        await p2p_check_strats(params)

    async def test_p2p_register_connect(self):
        name = input("name: ")
        params = {
            "return_msg": True,
            "addr_types": [EXT_BIND, NIC_BIND],
            "same_if": True,
        }

        use_strats = [P2P_DIRECT]
        async with TestNodes(**params) as nodes:
            name = await nodes.bob.nickname(name)
            pipe = await nodes.alice.connect(
                name,
                strategies=use_strats,
                conf=nodes.pp_conf,
            )

            assert(pipe is not None)
            assert(await check_pipe(pipe))
            await pipe.close()

    async def test_p2p_successive_failure(self):
        params = {
            "return_msg": True,
            "addr_types": [EXT_BIND, NIC_BIND],
            "same_if": True,
        }

        patch_strats = [PUNCH_FAIL, RELAY_FAIL, REVERSE_FAIL, P2P_DIRECT]
        use_strats = [P2P_PUNCH, P2P_RELAY, P2P_REVERSE, P2P_DIRECT]
        async with TestNodes(**params) as nodes:
            is_patched = patch_p2p_stats(patch_strats, nodes.pp_alice)
            def get_p2p_pipe(d):
                p = P2PPipe(d, nodes.alice)
                patch_p2p_stats(patch_strats, p)
                return p
            
            # This is more realistic because the clients make a new
            # P2PPipe for each proto method message.
            nodes.alice.p2p_pipe = get_p2p_pipe
            #nodes.alice.p2p_pipe = lambda d: P2PPipe(d, nodes.alice)
            nodes.bob.p2p_pipe = lambda d: P2PPipe(d, nodes.bob)
            #patch_p2p_stats(patch_strats, nodes.pp_bob)

            pipe = await nodes.alice.connect(
                nodes.bob.addr_bytes,
                strategies=use_strats,
                conf=nodes.pp_conf,
            )

            assert(pipe is not None)
            assert(await check_pipe(pipe))
            await pipe.close()

    async def test_p2p_strats(self):
        if_names = await list_interfaces()
        ifs = await load_interfaces(if_names)
        params = {
            "return_msg": False,
            "addr_types": [EXT_BIND, NIC_BIND],
            "ifs": ifs,
            "same_if": False if len(ifs) >= 2 else True
        }

        await p2p_check_strats(params)

if __name__ == '__main__':
    main()
