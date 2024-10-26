"""
return_msg False = use signal pipes
"""

from p2pd import *

import sys
import os
import signal
try:
    import aiomonitor
    from aiohttp import web
except:
    pass

TEST_NODE_NO = 2
TEST_P2P_PIPE_CONF = {
    "addr_types": [EXT_BIND, NIC_BIND],
    "sig_pipe_no": 0,
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
            #print(f"sig msg queue x = {x}")
            if x is None:
                return
            else:
                msg, vk, _ = x

            # Encrypt the message if the public key is known.
            buf = b"\1" + encrypt(
                dest_node.vk.to_string("compressed"),
                msg.pack(),
            )
            
            # UTF-8 messes up binary data in MQTT.
            buf = to_h(buf)
            #print(buf)
            try:
                await dest_node.sig_proto_handlers.proto(
                    buf
                )
            except asyncio.CancelledError:
                raise Exception("cancelled")
            except:
                log_exception()

            src_node.sig_msg_dispatcher_task = create_task(
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

async def add_echo_support(msg, client_tup, pipe):
    if b"ECHO" == msg[:4]:
        await pipe.send(msg[4:], client_tup)

async def get_node(ifs=[], node_port=NODE_PORT, sig_pipe_no=SIGNAL_PIPE_NO):
    conf = copy.deepcopy(NODE_CONF)
    conf["sig_pipe_no"] = sig_pipe_no
    conf["enable_upnp"] = False
    node = P2PNode(ifs, port=node_port, conf=conf)
    node.add_msg_cb(add_echo_support)
    return node

class TestNodes():
    def __init__(self, same_if=False, addr_types=[EXT_BIND, NIC_BIND], sig_pipe_no=0, ifs=[], multi_ifs=False):
        self.multi_ifs = multi_ifs
        self.ifs = ifs
        self.same_if = same_if
        if len(ifs) <= 1:
            self.same_if = True
            self.multi_ifs = False

        self.addr_types = addr_types
        self.sig_pipe_no = sig_pipe_no
        self.close_path = True

    def stop_controller(self, signal, frame):
        os._exit(0)

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

            self.bob = self.alice
            if TEST_NODE_NO > 1:
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
            self.bob = self.alice

            if TEST_NODE_NO > 1:
                self.bob = await get_node(
                    bob_ifs,
                    NODE_PORT + 1,
                    sig_pipe_no=self.sig_pipe_no,
                )

        

        # Build p2p con pipe config.
        self.pp_conf = {
            "addr_types": self.addr_types,
            "sig_pipe_no": self.sig_pipe_no,
        }

        alice_start_sig = self.alice.start_sig_msg_dispatcher
        self.alice.start_sig_msg_dispatcher = lambda: None

        if TEST_NODE_NO > 1:
            bob_start_sig = self.bob.start_sig_msg_dispatcher
            self.bob.start_sig_msg_dispatcher = lambda: None
            
        

        # Start the nodes.
        nic = self.alice.ifs[0]
        sys_clock = SysClock(nic)
        await sys_clock.start()
        tasks = [
            self.alice.start(sys_clock),
        ]
        if TEST_NODE_NO > 1:
            tasks.append(self.bob.start(sys_clock))

        await asyncio.gather(*tasks)

        # Set pipe conf.
        dest_bytes = self.alice.addr_bytes
        if TEST_NODE_NO > 1:
            dest_bytes = self.bob.addr_bytes

        self.pp_alice = self.alice.p2p_pipe(
            dest_bytes
        )

        self.alice.sig_proto_handlers.conf = self.pp_conf

        if TEST_NODE_NO > 1:
            self.bob.sig_proto_handlers.conf = self.pp_conf
            self.pp_bob = self.bob.p2p_pipe(
                self.alice.addr_bytes
            )

        # Send directly to each other.
        if not self.sig_pipe_no:
            self.alice.sig_msg_dispatcher = patch_msg_dispatcher(
                self.pp_alice,
                self.alice,
                self.bob,
            )

            if TEST_NODE_NO > 1:
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

        if TEST_NODE_NO > 1:
            bob_start_sig()

        # Short reference var.
        signal.signal(signal.SIGINT, self.stop_controller)
        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        if not self.close_path:
            return
        
        await async_wrap_errors(self.alice.close())
        if TEST_NODE_NO > 1:
            await async_wrap_errors(self.bob.close())

async def p2p_check_strats(params, strats):
    async with TestNodes(**params) as nodes:



        #print(nodes.alice.p2p_addr)
        #print()
        if TEST_NODE_NO > 1:
            #print(nodes.bob.p2p_addr)
            pass

        for strat in strats:
            pipe = await nodes.alice.connect(
                nodes.bob.addr_bytes,
                strategies=[strat],
                conf=nodes.pp_conf,
            )


            if pipe is not None:
                assert(await check_pipe(pipe))
            else:
                print(f"pipe is None. {strat} failed")

            if strat in [P2P_PUNCH]:
                if pipe is None:
                    log(f"opt test self {strat} failed")

            if pipe is not None:
                await pipe.close()

    # Give time to close.
    await asyncio.sleep(2)

asyncio.set_event_loop_policy(SelectorEventPolicy())

async def test_p2p_multi_node_ifs():
    if_names = await list_interfaces()
    ifs = await load_interfaces(if_names)
    if len(ifs) <= 1:
        print("skipping multi if tests -- only one if")
        return

    params = {
        "sig_pipe_no": 2,
        "addr_types": [EXT_BIND, NIC_BIND],
        "ifs": ifs,
        "same_if": False if len(ifs) >= 2 else True,
        "multi_ifs": True,
    }

    strats = [P2P_DIRECT, P2P_RELAY, P2P_REVERSE, P2P_PUNCH]
    #strats = [P2P_PUNCH]
    await p2p_check_strats(params, strats)

async def test_p2p_register_connect():
    if_names = await list_interfaces()
    ifs = await load_interfaces(if_names)
    name = input("name: ")
    params = {
        "sig_pipe_no": 0,
        "addr_types": [EXT_BIND, NIC_BIND],
        "ifs": ifs,
        "same_if": False,
        "multi_ifs": True,
    }

    # Start of node id is none. ???

    """
    deterministically choose sig pipe offsets based on node id
    or at least use the same that were chosen
    increase to 3 sig pipes
    finish status tests
    """
    

    use_strats = [P2P_PUNCH]
    async with TestNodes(**params) as nodes:
        """
        name = await nodes.alice.nickname(name)
        while 1:
            await asyncio.sleep(1)
        """
        

        pipe = await nodes.bob.connect(
            name,
            strategies=use_strats,
            conf=nodes.pp_conf,
        )

        print(pipe)
        print(pipe.sock)
        #assert(pipe is not None)
        assert(await check_pipe(pipe))
        while 1:
            await asyncio.sleep(1)
        await pipe.close()

async def test_p2p_successive_failure():
    if_names = await list_interfaces()
    ifs = await load_interfaces(if_names)
    params = {
        "sig_pipe_no": 0,
        "addr_types": [EXT_BIND, NIC_BIND],
        "ifs": ifs,
        "same_if": False if len(ifs) >= 2 else True,
        "multi_ifs": True,
    }

    patch_strats = [PUNCH_FAIL]
    use_strats = [P2P_PUNCH]
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

async def test_p2p_strats():
    if_names = await list_interfaces()
    ifs = await load_interfaces(if_names)
    params = {
        "sig_pipe_no": 2,
        "addr_types": [EXT_BIND, NIC_BIND],
        "ifs": ifs,
        "same_if": True,
        "multi_ifs": False,
    }

    strats = [P2P_RELAY]

    await p2p_check_strats(params, strats)

async def test_bug_fix():
    # temporarily cache this for testing like 5 min expiry?
    if_names = await list_interfaces()
    ifs = await load_interfaces(if_names)
    #print(ifs)
    #print(ifs[0].netifaces)
    #return
    params = {
        "sig_pipe_no": 0,
        "addr_types": [EXT_BIND, NIC_BIND],
        "ifs": ifs,
        "same_if": False,
        "multi_ifs": True,
    }

    use_strats = [P2P_RELAY]
    async with TestNodes(**params) as nodes:
        
        print(nodes.alice.vk.to_string("compressed"))
        print(nodes.bob.vk.to_string("compressed"))

        print(nodes.alice.addr_bytes)
        print(nodes.bob.addr_bytes)

        print()
        print(nodes.pp_alice.dest)
        print(nodes.pp_bob.dest)

        for strat in use_strats:


            pipe = await nodes.alice.connect(
                nodes.bob.addr_bytes,
                strategies=[strat],
                conf=nodes.pp_conf,
            )

            print("Got pipe ")
            print(pipe)

            await check_pipe(pipe)

        while 1:
            await asyncio.sleep(1)

        assert(pipe)
        return

    strats = [P2P_PUNCH]
    strats = [P2P_DIRECT, P2P_REVERSE, P2P_RELAY, P2P_PUNCH]
    #strats = [P2P_PUNCH]
    await p2p_check_strats(params, strats)

async def monitor_coroutines(coro):
    # init monitor just before run_app
    loop = asyncio.get_running_loop()
    with aiomonitor.start_monitor(loop, hook_task_factory=True):
        await coro

if __name__ == '__main__':
    choices = [
        ["test_p2p_register_connect", test_p2p_register_connect],
        ["test_p2p_successive_failure", test_p2p_successive_failure],
        ["test_p2p_strats", test_p2p_strats],
        ["test_bug_fix", test_bug_fix],
        ["test_p2p_multi_node_ifs", test_p2p_multi_node_ifs],
    ]

    def show_choices():
        for i, choice in enumerate(choices):
            print(f"{i} = {choice[0]}")

    # http://localhost:20102/
    while 1:
        show_choices()
        choice = input("Select choice: ")
        index = int(choice)
        func = choices[index][1]
        asyncio.run(func())

        continue
        try:
            asyncio.run(monitor_coroutines(func()))
        except:
            asyncio.run(func())


