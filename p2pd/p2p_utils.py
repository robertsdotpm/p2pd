import asyncio
from concurrent.futures import ProcessPoolExecutor
import hashlib
import socket
from .settings import *
from .utils import *
from .address import Address
from .net import *
from .interface import get_default_iface, get_mac_address
from .interface import select_if_by_dest
from .turn_client import TURNClient
from .signaling import SignalMock

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

also addr compares arent the best idea since ifaces can have
multiple addresses. think on this more.
"""
def select_dest_ipr(same_pc, src_info, dest_info, addr_types, is_tcp_punch=False):
    # Shorten these for expressions.
    src_nid = src_info["netiface_index"]
    dest_nid = dest_info["netiface_index"]

    # Makes long conditions slightly more readable.
    same_lan = True # TODO
    same_if = src_nid == dest_nid
    same_if_on_host = same_pc and same_if
    different_ifs_on_host = same_pc and not same_if

    # There may be multiple compatible addresses per info.
    for addr_type in addr_types:
        # Prefer using remote addresses.
        if addr_type == EXT_BIND:
            # Will have only one listed external address.
            if same_if_on_host:
                continue

            # Behind same router -- this won't work.
            if src_info["ext"] == dest_info["ext"]:
                continue

            # Different reachable address.
            return dest_info["ext"]
        
        # Prefer using local addresses.
        if addr_type == NIC_BIND:
            # The server / client is the same IP
            # It needs to pick the same IF so its reachable.
            if is_tcp_punch:
                if different_ifs_on_host:
                    return sorted([
                        dest_info["nic"],
                        src_info["nic"]
                    ])[0]
                
            # Only if LAN or same machine.
            if not (same_pc or same_lan):
                continue

            # Otherwise the NIC IP is fine to use.
            return dest_info["nic"]

    # No compatible addresses. 
    return None

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
async def for_addr_infos(src, dest, func, timeout, cleanup, addr_types, pp, concurrent=False):
    found_valid_af_pair = False

    # For concurrent tasks.
    tasks = []

    # Use an AF supported by both.
    for af in VALID_AFS:
        # Iterates by shared AFs, filtered by best NAT pair.
        if_info_iter = IFInfoIter(af, src, dest)
        if not len(if_info_iter):
            continue
        else:
            found_valid_af_pair = True

        # Get interface offset that supports this af.
        for src_info, dest_info in if_info_iter:
            for addr_type in addr_types:
                # Select interface to use.
                if_index = src_info["if_index"]
                interface = pp.node.ifs[if_index]

                # Select a specific if index.
                if pp.reply is not None:
                    if pp.reply.routing.dest_index != if_index:
                        continue

                dest_info["ip"] = str(
                    select_dest_ipr(
                        pp.same_machine,
                        src_info,
                        dest_info,
                        [addr_type],
                        func == pp.tcp_hole_punch
                    )
                )

                interface = await select_if_by_dest(
                    af,
                    dest_info["ip"],
                    interface,
                    pp.node.ifs,
                )

                # Coroutine to run.
                coro = async_wrap_errors(
                    func(
                        af,
                        src_info,
                        dest_info,
                        interface,
                    ),
                    timeout
                )

                # Build a list of tasks if concurrent.
                if concurrent:
                    tasks.append(coro)
                else:
                    result = await coro
                    if result is not None:
                        return result
                    else:
                        if cleanup is not None:
                            await cleanup(
                                af,
                                src_info,
                                dest_info,
                                interface,
                            )
            
    # No compatible addresses found.
    if not found_valid_af_pair:
        error = \
        f"""
        Found no compat addresses between 
        {src["bytes"]} and
        {dest["bytes"]}
        """
        log(error)
        return
            
    # Run multiple coroutines at once.
    if len(tasks):
        results = await asyncio.gather(*tasks)
        results = [r for r in results if r is not None]
        return results

async def new_peer_signal_pipe(p2p_dest, node):
    for offset in p2p_dest["signal"]:
        # Build a channel to relay signal messages to peer.
        mqtt_server = MQTT_SERVERS[offset]
        signal_pipe = SignalMock(
            peer_id=to_s(node.node_id),
            f_proto=node.signal_protocol,
            mqtt_server=mqtt_server
        )

        print(signal_pipe)

        # If it fails unset the client.
        try:
            # If it's successful exit server offset attempts.
            await signal_pipe.start()
            node.signal_pipes[offset] = signal_pipe
        except asyncio.TimeoutError:
            print("sig pipe timeout")
            # Cleanup and make sure it's unset.
            await signal_pipe.close()
            continue

        return signal_pipe
    
async def fallback_machine_id(netifaces, app_id="p2pd"):
    host = socket.gethostname()
    if_name = get_default_iface(netifaces)
    mac = await get_mac_address(if_name, netifaces)
    buf = f"{app_id} {host} {if_name} {mac}"
    return to_s(hashlib.sha256(to_b(buf)).digest())

