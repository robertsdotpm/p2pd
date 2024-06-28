import asyncio
from concurrent.futures import ProcessPoolExecutor
from .p2p_node import *
from .address import Address
from .utils import *
from .net import *

def init_process_pool():
    # Make selector default event loop.
    # On Windows this changes it from proactor to selector.
    asyncio.set_event_loop_policy(SelectorEventPolicy())

    # Create new event loop in the process.
    loop = asyncio.get_event_loop()

    # Handle exceptions on close.
    loop.set_exception_handler(handle_exceptions)

async def get_pp_executors(workers=2):
    try:
        pp_executor = ProcessPoolExecutor(max_workers=workers)
    except Exception:
        """
        Not all platform have a working implementation of sem_open / semaphores.
        Android is one such platform. It does support multiprocessing but
        this semaphore feature is missing and will throw an error here.
        In this case -- log the error and revert to using a single event loop.
        """
        log_exception()
        return None
    
    loop = asyncio.get_event_loop()
    tasks = []
    for i in range(0, workers):
        tasks.append(loop.run_in_executor(
            pp_executor, init_process_pool
        ))
    await asyncio.gather(*tasks)
    return pp_executor

# delay with sys clock and get_pp_executors.
async def start_p2p_node(port=NODE_PORT, node_id=None, ifs=None, clock_skew=Dec(0), ip=None, pp_executors=False, enable_upnp=False, signal_offsets=None, netifaces=None):
    netifaces = netifaces or Interface.get_netifaces()
    if netifaces is None:
        netifaces = await init_p2pd()

    # Load NAT info for interface.
    ifs = ifs or await load_interfaces(netifaces=netifaces)
    assert(len(ifs))
    for interface in ifs:
        # Don't set NAT details if already set.
        if interface.resolved:
            continue

        # Prefer IP4 if available.
        af = IP4
        if af not in interface.supported():
            af = IP6

        # STUN is used to test the NAT.
        stun_client = STUNClient(
            interface,
            af
        )

        # Load NAT type and delta info.
        # On a server should be open.
        nat = await stun_client.get_nat_info()
        interface.set_nat(nat)

    if pp_executors is None:
        pp_executors = await get_pp_executors(workers=4)

    if clock_skew == Dec(0):
        sys_clock = await SysClock(ifs[0]).start()
    else:
        sys_clock = SysClock(ifs[0], clock_skew)

    # Log sys clock details.
    assert(sys_clock.clock_skew) # Must be set for meetings!
    log(f"> Start node. Clock skew = {sys_clock.clock_skew}")

    # Pass interface list to node.
    node = await async_wrap_errors(
        P2PNode(
            if_list=ifs,
            port=port,
            node_id=node_id,
            ip=ip,
            signal_offsets=signal_offsets,
            enable_upnp=enable_upnp
        ).start()
    )

    log("node success apparently.")

    # Configure node for TCP punching.
    if pp_executors is not None:
        mp_manager = multiprocessing.Manager()
    else:
        mp_manager = None

    node.setup_multiproc(pp_executors, mp_manager)
    node.setup_coordination(sys_clock)
    node.setup_tcp_punching()

    # Wait for MQTT sub.
    for offset in list(node.signal_pipes):
        await node.signal_pipes[offset].sub_ready.wait()

    return node

async def sort_if_info_by_best_nat(p2p_addr):
    # [af] = [[nat_type, if_info], ...]
    nat_pairs = {}

    # Check all valid addresses.
    for af in VALID_AFS:
        if not len(p2p_addr[af]):
            continue

        # Store subset of interface details.
        nat_pairs[af] = []

        # Loop over all the interface details by address family.
        for _, if_info in enumerate(p2p_addr[af]):
            # Save interface details we're interested in.
            nat_pairs[af].append([
                if_info["nat"]["type"],
                if_info
            ])

        # Sort the details list based on the first field (NAT type.)
        nat_pairs[af] = sorted(
            nat_pairs[af],
            key=lambda x: x[0]
            )

    return nat_pairs

class IFInfoIter():
    def __init__(self, af, src_addr, dest_addr):
        self.af = af
        self.src_addr = sort_if_info_by_best_nat(src_addr)
        self.dest_addr = sort_if_info_by_best_nat(dest_addr)
        cond_one = af not in self.src_addr
        cond_two = af not in self.dest_addr
        if cond_one or cond_two:
            self.dest_addr = self.src_addr = []

        self.dest_addr = dest_addr[af]
        self.src_addr = src_addr[af]
        self.our_offset = 0
        self.their_offset = 0

    def __iter__(self):
        return self

    def __next__(self):
        # Stop when they have no new entries.
        if self.their_offset >= len(self.dest_addr) - 1:
            raise StopIteration
        
        # Load addr info to use.
        src_info = self.src_addr[self.our_offset]
        dest_info = self.dest_addr[self.their_offset]

        # Don't increase our offset if no new entry.
        if self.our_offset < len(self.src_addr) - 1:
            self.our_offset += 1

        # Increase their offset.
        self.their_offset += 1

        # Return the addr info.
        return src_info, dest_info
        
