import asyncio
from concurrent.futures import ProcessPoolExecutor
from .p2p_node import *

def init_process_pool():
    # Make selector default event loop.
    # On Windows this changes it from proactor to selector.
    asyncio.set_event_loop_policy(SelectorEventPolicy())

    # Create new event loop in the process.
    loop = asyncio.get_event_loop()

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
async def start_p2p_node(port=NODE_PORT, node_id=None, ifs=None, clock_skew=Dec(0), ip=None, pp_executors=None, enable_upnp=False, signal_offsets=None, netifaces=None):
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
    node = await P2PNode(
        if_list=ifs,
        port=port,
        node_id=node_id,
        ip=ip,
        signal_offsets=signal_offsets,
        enable_upnp=enable_upnp
    ).start()

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

