import asyncio
from concurrent.futures import ProcessPoolExecutor
import hashlib
import socket
from .address import Address
from .utils import *
from .net import *
from .nat import *
from .turn_client import TURNClient
from .settings import *
from .p2p_addr import parse_peer_addr
from .signaling import SignalMock
from .interface import get_default_iface, get_mac_address

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

def sort_if_info_by_best_nat(p2p_addr):
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

        # Sort based on NAT enum (lower = better)
        nat_pairs[af] = sorted(
            nat_pairs[af],
            key=lambda x: x[0]
        )

    return nat_pairs

class IFInfoIter():
    def __init__(self, af, src_addr, dest_addr):
        self.our_offset = 0
        self.their_offset = 0
        self.af = af
        self.src_addr = sort_if_info_by_best_nat(src_addr)
        self.dest_addr = sort_if_info_by_best_nat(dest_addr)
        cond_one = not len(self.src_addr.get(af, []))
        cond_two = not len(self.dest_addr.get(af, [])   )
        if cond_one or cond_two:
            self.dest_addr = self.src_addr = []
            return

        self.dest_addr = dest_addr[af]
        self.src_addr = src_addr[af]

    def __iter__(self):
        return self

    def __next__(self):
        # Stop when they have no new entries.
        if self.their_offset > (len(self.dest_addr) - 1):
            raise StopIteration
        
        # Load addr info to use.
        src_info = self.src_addr[self.our_offset]
        dest_info = self.dest_addr[self.their_offset]

        # Don't increase our offset if no new entry.
        if self.our_offset < (len(self.src_addr) - 1):
            self.our_offset += 1

        # Increase their offset.
        self.their_offset += 1

        # Return the addr info.
        return src_info, dest_info
    
    def __len__(self):
        return len(self.dest_addr)
        
"""
If nodes are behind the same router they will have
the same external address. Using this address for
connections will fail because it will be the same
address as ourself. The solution here is to replace
that external address with a private, NIC address.
For this reason the P2P address format includes
a private address section that corrosponds to
the address passed to bind() for the nodes listen().
"""
def work_behind_same_router(src, dest):
    # Disable NAT behind router.
    # Or connecting to interfaces on same PC.
    delta = delta_info(NA_DELTA, 0)
    nat = nat_info(OPEN_INTERNET, delta)
    new_addr = copy.deepcopy(dest)

    # All interfaces on the same machine.
    same_pc = src["machine_id"] == dest["machine_id"]
    for af in VALID_AFS:
        for d_info in new_addr[af]:
            for s_info in src[af]:
                # This interface is on the same LAN.
                same_lan = d_info["ext"] == s_info["ext"]
                if same_pc or same_lan:
                    d_info["ext"] = d_info["nic"]
                    d_info["nat"] = nat

    return new_addr

async def get_turn_client(af, serv_id, interface, dest_peer=None, dest_relay=None):
    # TODO: index by id and not offset.
    turn_server = TURN_SERVERS[serv_id]

    # Resolve the TURN address.
    route = await interface.route(af).bind()
    turn_addr = await Address(
        turn_server["host"],
        turn_server["port"],
        route
    ).res()

    # Make a TURN client instance to whitelist them.
    turn_client = TURNClient(
        route=route,
        turn_addr=turn_addr,
        turn_user=turn_server["user"],
        turn_pw=turn_server["pass"],
        turn_realm=turn_server["realm"]
    )

    # Start the TURN client.
    try:
        await asyncio.wait_for(
            turn_client.start(),
            10
        )
    except asyncio.TimeoutError:
        log("Turn client start timeout in node.")
        return
    
    # Wait for our details.
    peer_tup  = await turn_client.client_tup_future
    relay_tup = await turn_client.relay_tup_future

    # Whitelist a peer if desired.
    if None not in [dest_peer, dest_relay]:
        await asyncio.wait_for(
            turn_client.accept_peer(
                dest_peer,
                dest_relay
            ),
            6
        )

    return peer_tup, relay_tup, turn_client


"""
The iterator filters the addr info for both
P2P addresses by the best NAT.
The first addr info used for both is thus the
best possible pairing. Further iterations aren't
likely to be any more successful so to keep things
simple only the first iteration is tried.

Note: that parse_peer_addr doesn't covert the input
if it detects its a dict so that pre-patched
addresses from messages can be parsed in.

proto: direct_connect(... msg.meta.src)

Is the only function that does this so far.
"""
async def for_addr_infos(pipe_id, src_bytes, dest_bytes, func, concurrent=False):
    # For concurrent tasks.
    tasks = []

    # Use an AF supported by both.
    p2p_dest = parse_peer_addr(dest_bytes)
    our_addr = parse_peer_addr(src_bytes)
    for af in VALID_AFS:
        # Iterates by shared AFs, filtered by best NAT pair.
        if_info_iter = IFInfoIter(af, our_addr, p2p_dest)
        if not len(if_info_iter):
            continue

        # Get interface offset that supports this af.
        for src_info, dest_info in if_info_iter:
            # Coroutine to run.
            coro = func(
                af,
                pipe_id,
                p2p_dest["node_id"],
                src_info,
                dest_info,
                dest_bytes,    
            )

            # Build a list of tasks if concurrent.
            if concurrent:
                tasks.append(coro)
            else:
                return await coro
            
    # Run multiple coroutines at once.
    if len(tasks):
        results = await asyncio.gather(*tasks)
        results = [r for r in results if r is not None]
        return results

async def direct_connect(pipe_id, dest_bytes, node):
    cons = await for_addr_infos(
        pipe_id,
        node.addr_bytes,
        dest_bytes,
        node.make_connection,
        concurrent=True
    )

    if not len(cons):
        return None

    if len(cons) > 1:
        for con in cons[1:]:
            await con.close()

    return cons[0]

async def new_peer_signal_pipe(p2p_dest, node):
    for offset in p2p_dest["signal"]:
        # Build a channel to relay signal messages to peer.
        mqtt_server = MQTT_SERVERS[offset]
        signal_pipe = SignalMock(
            peer_id=to_s(node.node_id),
            f_proto=node.signal_protocol,
            mqtt_server=mqtt_server
        )

        # If it fails unset the client.
        try:
            # If it's successful exit server offset attempts.
            await signal_pipe.start()
            node.signal_pipes[offset] = signal_pipe
            break
        except asyncio.TimeoutError:
            # Cleanup and make sure it's unset.
            await signal_pipe.close()

        return signal_pipe
    
async def fallback_machine_id(netifaces, app_id="p2pd"):
    host = socket.gethostname()
    if_name = get_default_iface(netifaces)
    mac = await get_mac_address(if_name, netifaces)
    buf = f"{app_id} {host} {if_name} {mac}"
    return to_s(hashlib.sha256(to_b(buf)).digest())