from p2pd.test_init import *

import warnings
import socket
import multiprocessing
from decimal import Decimal as Dec
from p2pd.utils import *
from p2pd.p2p_addr import is_p2p_addr_us
from p2pd.p2p_node import *
from p2pd.p2p_utils import *
from p2pd.p2p_pipe import *
from p2pd.interface import *

asyncio.set_event_loop_policy(SelectorEventPolicy())
async def test_setup(netifaces=None, ifs=None):
    # Suppress socket unclosed warnings.
    if not hasattr(test_setup, "netifaces"):
        if netifaces is None:
            test_setup.netifaces = await init_p2pd()
        else:
            test_setup.netifaces = netifaces
        warnings.filterwarnings('ignore', message="unclosed", category=ResourceWarning)

    # Static setup because it's fast.
    if not hasattr(test_setup, "ifs"):
        if socket.gethostname() == "p2pd.net":
            test_setup.ifs = P2PD_IFS
        else:
            # Load a list of interfaces to use for the tests.
            test_setup.ifs = await load_interfaces(netifaces=test_setup.netifaces)

    # Load clock skew for test machine.
    if not hasattr(test_setup, "clock_skew"):
        test_setup.clock_skew = (await SysClock(test_setup.ifs[0]).start()).clock_skew

    # Load process pool executors.
    pp_executors = await get_pp_executors(workers=2)

    # Main node used for testing p2p functionality.
    node_a_ifs = [ifs[0]] if ifs is not None else test_setup.ifs
    node_a = await start_p2p_node(
        node_id=node_name(b"node_a", node_a_ifs[0]),

        # Get brand new unassigned listen port.
        # Avoid TIME_WAIT buggy sockets from port reuse.
        port=0,
        ifs=node_a_ifs,
        clock_skew=test_setup.clock_skew,
        pp_executors=pp_executors,
        enable_upnp=False
    )

    # Test local punching algorithm.
    node_b_ifs = [ifs[1  % len(ifs)]] if ifs is not None else test_setup.ifs
    node_b = await start_p2p_node(
        node_id=node_name(b"node_b", node_b_ifs[0]),

        # Get brand new unassigned listen port.
        # Avoid TIME_WAIT buggy sockets from port reuse.
        port=0,
        ifs=node_b_ifs,
        clock_skew=test_setup.clock_skew,
        pp_executors=pp_executors,
        enable_upnp=False
    )

    print(f"Node a = {node_a.p2p_addr}")
    print(f"Node b = {node_b.p2p_addr}")
    return node_a, node_b

async def test_cleanup(node_a, node_b):
    await node_a.close()
    await node_b.close()

class TestP2PPipe(unittest.IsolatedAsyncioTestCase):
    # Self connect won't work due to Coturn changes.
    async def test_self_turn_connect(self):
        return
        log(">>> test_self_turn_connect")
        node_a, node_b = await test_setup()
        pipe, _ = await node_a.connect(
            node_b.address(),
            strategies=[P2P_RELAY]
        )

        self.assertTrue(pipe is not None)
        dest_tup = await pipe.relay_tup_future
        pipe_okay = await check_pipe(pipe, dest_tup=dest_tup)
        self.assertTrue(pipe_okay)
        await pipe.close()
        await test_cleanup(node_a, node_b)

    async def test_multiple_strats(self):
        # Test reverse connect.
        log(">>> test_multiple_strats")
        node_a, node_b = await test_setup()

        # Replace node b's port with an invalid one.
        node_b_addr = node_b.address()
        node_b_server = node_b.servers[0][2]
        node_b_port = str(node_b_server.sock.getsockname()[1])
        node_b_addr.replace(to_b(node_b_port), b"68000")

        # Connect using different strategies.
        pipe, _ = await node_a.connect(
            node_b_addr,
            strategies=[
                # Direct will fail.
                P2P_DIRECT,
                
                # Reverse should succeed.
                P2P_REVERSE
            ]
        )
        self.assertTrue(pipe is not None)

        # Test pipe is valid.
        pipe_okay = await check_pipe(pipe)
        self.assertTrue(pipe_okay)
        await pipe.close()
        await test_cleanup(node_a, node_b)

    async def test_self_reverse_connect(self):
        # Test reverse connect.
        log(">>> test_self_reverse_connect")
        node_a, node_b = await test_setup()
        pipe, _ = await node_a.connect(
            node_b.address(),
            strategies=[P2P_REVERSE]
        )
        self.assertTrue(pipe is not None)

        # Test pipe is valid.
        pipe_okay = await check_pipe(pipe)
        self.assertTrue(pipe_okay)
        await pipe.close()
        await test_cleanup(node_a, node_b)

    async def test_self_direct_connect(self):
        # Test reverse connect.
        log(">>> test_self_direct_connect")
        node_a, node_b = await test_setup()
        pipe, _ = await node_a.connect(
            node_b.address(),
            strategies=[P2P_DIRECT]
        )
        self.assertTrue(pipe is not None)

        # Test pipe is valid.
        pipe_okay = await check_pipe(pipe)
        self.assertTrue(pipe_okay)
        await pipe.close()
        await test_cleanup(node_a, node_b)

    async def test_remote_direct_connect(self):
        if not P2PD_TEST_INFRASTRUCTURE:
            return

        # Test direct connect
        log(">>> test_remote_direct_connect")
        node_a, node_b = await test_setup()
        pipe, _ = await node_a.connect(
            P2PD_NET_ADDR_BYTES,
            strategies=[P2P_DIRECT]
        )
        self.assertTrue(pipe is not None)

        # Test pipe is valid.
        pipe_okay = await check_pipe(pipe)
        self.assertTrue(pipe_okay)
        await pipe.close()
        await test_cleanup(node_a, node_b)

    async def test_self_punch(self):
        # Test p2p punch to self.
        # This also tests local punching as the same code is used.
        log(">>> test_self_punch")
        node_a, node_b = await test_setup()
        pipe, _ = await node_a.connect(
            node_b.address(),
            strategies=[P2P_PUNCH]
        )

        # Test pipe is valid.
        pipe_okay = await check_pipe(pipe)
        if not pipe_okay:
            print("Test self punch with networking failed.")
            print("Test is optional but mentioning it.")

        if pipe is not None:
            await pipe.close()
        await test_cleanup(node_a, node_b)

    async def test_remote_reverse_connect(self):
        if not P2PD_TEST_INFRASTRUCTURE:
            return

        # Test reverse connect.
        log(">>> test_remote_reverse_connect")
        node_a, node_b = await test_setup()
        found_open = False
        for interface in node_a.if_list:
            if interface.nat["type"] == OPEN_INTERNET:
                pipe, _ = await node_a.connect(
                    P2PD_NET_ADDR_BYTES,
                    strategies=[P2P_REVERSE]
                )
                self.assertTrue(pipe is not None)

                # Test pipe is valid.
                pipe_okay = await check_pipe(pipe)
                self.assertTrue(pipe_okay)
                await pipe.close()
                found_open = True
                break

        if not found_open:
            print("> Skipping reverse connect test")
            print("> NAT type is not open.\r\n")

        await test_cleanup(node_a, node_b)

    async def test_remote_punch_duel_ifs(self):
        # Load interface list.
        netifaces = await init_p2pd()
        ifs, af = await duel_if_setup(netifaces, load_nat=True)
        if af is None:
            return
        
        # Start nodes on different interfaces.
        node_a, node_b = await test_setup(netifaces, ifs)
        pipe, _ = await node_a.connect(
            node_b.address(),
            strategies=[P2P_PUNCH]
        )

        # Check if a connection was spawned.
        self.assertTrue(pipe is not None)
        pipe_okay = await check_pipe(pipe)
        self.assertTrue(pipe_okay is not None)

        # Cleanup        
        if pipe is not None:
            await pipe.close()
        await test_cleanup(node_a, node_b)

    async def test_remote_punch(self, netifaces=None, ifs=None, is_optional=False):
        if not P2PD_TEST_INFRASTRUCTURE and ifs is None:
            return

        # If P2PD_NET_ADDR_BYTES is not us then test punching to it.
        log(">>> test_remote_punch")
        node_a, node_b = await test_setup(netifaces, ifs)
        if not is_p2p_addr_us(P2PD_NET_ADDR_BYTES, node_a.if_list):
            # Connect to p2pd.net test server.
            pipe, _ = await node_a.connect(
                P2PD_NET_ADDR_BYTES,
                strategies=[P2P_PUNCH]
            )
            self.assertTrue(pipe is not None)

            # Test pipe is valid.
            pipe_okay = await check_pipe(pipe)
            if not pipe_okay and is_optional:
                log("remote punch failed but was optional.")
            else:
                self.assertTrue(pipe_okay)
            await pipe.close()
        else:
            print("> p2pd net addr is us. Skipping remote punch test.")

        await test_cleanup(node_a, node_b)

    async def test_remote_turn_connect(self):
        if not P2PD_TEST_INFRASTRUCTURE:
            return

        log(">>> test_remote_turn_connect")
        node_a, node_b = await test_setup()
        pipe, _ = await node_a.connect(
            P2PD_NET_ADDR_BYTES,
            strategies=[P2P_RELAY]
        )

        self.assertTrue(pipe is not None)

        # Get the relay address of the test peer.
        p2pd_ip = list(pipe.peers.keys())[0]
        dest_tup = pipe.get_relay_tup(p2pd_ip)

        # Use it to do the echo test on TURN client.
        # Use the peers relay address as the destination.
        pipe_okay = await check_pipe(pipe, dest_tup=dest_tup)
        self.assertTrue(pipe_okay)
        await pipe.close()
        await test_cleanup(node_a, node_b)

if __name__ == '__main__':
    main()

