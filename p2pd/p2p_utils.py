"""
On ancient versions of Windows (like Vista),
on older versions of Python (3.7 <= ?) there are socket bugs
that can crash the event loop without being able to catch
the exceptions. Trying to merge such patches into the project
for these rare edge cases isn't a productive use of time
(without much requests) -- instead, users should try upgrade
OS or Python versions if possible.
"""

import asyncio
from concurrent.futures import ProcessPoolExecutor
import hashlib
import os
import socket
from .settings import *
from .utils import *
from .address import Address
from .net import *
from .interface import get_default_iface, get_mac_address
from .interface import select_if_by_dest
from .turn_client import TURNClient
from .signaling import SignalMock

TRY_OVERLAP_EXTS = 1
TRY_NOT_TO_OVERLAP_EXTS = 2
CON_ID_MSG = b"P2P_CON_ID_EQ"

f_path_txt = lambda x: "local" if x == NIC_BIND else "external"

def init_process_pool():
    # Make selector default event loop.
    # On Windows this changes it from proactor to selector.
    asyncio.set_event_loop_policy(SelectorEventPolicy())

    # Create new event loop in the process.
    loop = asyncio.get_event_loop()

    # Handle exceptions on close.
    loop.set_exception_handler(handle_exceptions)

async def get_pp_executors(workers=None):
    workers = workers or min(32, os.cpu_count() + 4)
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
    
    return workers, pp_executor
    loop = asyncio.get_event_loop()
    tasks = []
    for i in range(0, workers):
        tasks.append(loop.run_in_executor(
            pp_executor, init_process_pool
        ))
    await asyncio.gather(*tasks)
    return pp_executor
 
"""
If nodes are behind the same router they will have
the same external address. Using this address for
connections will fail because it will be the same
address as ourself. The solution here is to replace
that external address with a private, NIC address.
For this reason the P2P address format includes
a private address section that corresponds to
the address passed to bind() for the nodes listen().

also addr compares arent the best idea since ifaces can have
multiple addresses. think on this more.
"""
def select_dest_ipr(af, same_pc, src_info, dest_info, addr_types, has_set_bind=True):
    # Shorten these for expressions.
    src_nid = src_info["netiface_index"]
    dest_nid = dest_info["netiface_index"]

    """
    Very simplified -- another external address could
    be routable for the same LAN. There must
    be a better way to do this.
    """
    if af == IP4:
        # Compares external v4 default route.
        same_lan = src_info["ext"] == dest_info["ext"]
    if af == IP6:
        # Compares the first n bits for typical v6 subnet.
        # Todo: need to know the subnet bits for this.
        same_lan = src_info["ext"] == dest_info["ext"]
        same_lan = 1

    # Try any local address for now.
    # Todo: write a better algorithm for this.
    same_lan = 1

    # Makes long conditions slightly more readable.
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
            """
            When reaching a server its bound to a specific
            interface and you choose that NIC to reach it.
            But TCP punching has no defined server. However,
            if they're not on the same NIC, on the same host,
            different NICs can't interact (maybe unless
            they're bridged.) Keep this edge-case here.
            """
            if not has_set_bind:
                # Choose the same NIC IP for both sides.
                # That chooses the same interface.
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

async def get_turn_client(af, serv_id, interface, dest_peer=None, dest_relay=None, msg_cb=None):
    # TODO: index by id and not offset.
    turn_server = TURN_SERVERS[serv_id]

    # The TURN address.
    turn_addr = (
        turn_server["host"],
        turn_server["port"],
    )

    # Make a TURN client instance to whitelist them.
    turn_client = TURNClient(
        af=af,
        dest=turn_addr,
        nic=interface,
        auth=(turn_server["user"], turn_server["pass"]),
        realm=turn_server["realm"],
        msg_cb=msg_cb,
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

async def get_first_working_turn_client(af, offsets, nic, msg_cb):
    for offset in offsets:
        try: 
            peer_tup, relay_tup, turn_client = await get_turn_client(
                af,
                offset,
                nic,
                msg_cb=msg_cb,
            )

            turn_client.serv_offset = offset
            return turn_client
        except:
            log_exception()
            continue

def sort_pairs_by_overlap(src_infos, dest_infos):
    overlap = []
    unique = []
    for src_info in src_infos:
        for dest_info in dest_infos:
            pair = [src_info, dest_info]
            if src_info["ext"] == dest_info["ext"]:
                overlap.append(pair)
            else:
                unique.append(pair)

    return overlap, unique

async def for_addr_infos(strat, func, timeout, cleanup, has_set_bind, max_pairs, reply, pp, conf):
    """
    Given info on a local interface, a remote interface,
    and a chosen connectivity technique, attempt to create
    a connection. Adapt the technique depending on whether
    addressing is suitably local or remote.
    """
    async def try_addr_infos(addr_type, src_info, dest_info):
        # Local addressing and/or remote.
        try:
            # Create a future for pending pipes.
            if reply is None:
                pipe_id = to_s(rand_plain(15))
            else:
                pipe_id = reply.meta.pipe_id

            # Allow awaiting by pipe_id.
            pp.node.pipe_future(pipe_id)

            # Select interface to use.
            if_index = src_info["if_index"]
            interface = pp.node.ifs[if_index]

            # Ensure our selected NIC is what the
            # remote peer wanted to use for the technique.
            if reply is not None:
                if reply.routing.dest_index != if_index:
                    return

            # Support testing addr type failures.
            # This is for test harnesses.
            if addr_type in [NIC_FAIL, EXT_FAIL]:
                use_addr_type = addr_type - 2
                do_fail = True
            else:
                use_addr_type = addr_type
                do_fail = False

            """
            Determine the best destination IP to use
            for the connectivity technique based on
            addressing and relationships between the
            two machines (deep networking specific.)
            """
            dest_info["ip"] = str(
                select_dest_ipr(
                    af,
                    pp.same_machine,
                    src_info,
                    dest_info,
                    [use_addr_type],

                    # can you make this case
                    # run for all
                    # try it
                    has_set_bind,
                )
            )

            # Need a destination address.
            # Possibly a different address type will work.
            if dest_info["ip"] == "None":
                return
            
            # Detailed logging details.
            path_txt = f_path_txt(addr_type)
            src_ip = src_info["nic"] if addr_type == NIC_BIND else src_info["ext"]
            msg = f"<{strat}> Trying {path_txt} {src_ip} -> "
            msg += f"{dest_info['ip']} on '{interface.name}'"
            Log.log_p2p(msg, pp.node.node_id[:8])

            """
            With all the correct interfaces and IPs
            chosen -- call the function that will run
            the technique to achieve connectivity.
            """
            result = await async_wrap_errors(
                func(
                    af,
                    pipe_id,
                    src_info,
                    dest_info,
                    interface,
                    addr_type,
                    reply,
                ),
                timeout
            )

            # Support testing failures for an addr type.
            if do_fail:
                result = None

            # Success result from function.
            if result is not None:
                return result
            
            """
            Some functions require cleanup on failure.
            Ensure that the state overtime remains clean.
            """
            if cleanup is not None:
                await cleanup(
                    af,
                    pipe_id,
                    src_info,
                    dest_info,
                    interface,
                    use_addr_type,
                    reply,
                )

            # Delete unused futures on failure.
            if pipe_id in pp.node.pipes:
                del pp.node.pipes[pipe_id]
        except:
            log_exception()

    # Use an AF supported by both.
    if reply is not None:
        conf["addr_families"] = [reply.meta.af]

    for addr_type in conf["addr_types"]:
        count = 1
        for af in conf["addr_families"]:
            if reply is not None:
                # Try select if info based on their chosen offset.
                src_info = pp.src[af][reply.routing.dest_index]
                dest_info = pp.dest[af][reply.meta.src_index]
                ret = await async_wrap_errors(
                    try_addr_infos(addr_type, src_info, dest_info)
                )

                return ret, addr_type

            # Get interface offset that supports this af.
            #for src_info, dest_info in if_info_iter:
            src_infos = list(pp.src[af].values())
            dest_infos = list(pp.dest[af].values())
            overlap, unique = sort_pairs_by_overlap(
                src_infos,
                dest_infos
            )

            # If external address is the same try unique pairs first.
            if addr_type == EXT_BIND:
                pair_order = unique + overlap

            # For local addresses you want to do the opposite.
            # So you're on the same LAN or NIC if on the same machine.
            if addr_type == NIC_BIND:
                pair_order = overlap + unique

            if not len(pair_order):
                log("pair order list is empty!")

            for src_info, dest_info in pair_order:
                # Only try up to N pairs per technique.
                # Technique-specific N to avoid lengthy delays.
                ret = await async_wrap_errors(
                    try_addr_infos(
                        addr_type,
                        src_info,
                        dest_info
                    )
                )

                # Success so return.
                if ret is not None:
                    return ret, addr_type
                    
                count += 1
                if count > max_pairs:
                    return None, None
                
                # Cleanup here?
                    
    # Failure.
    return None, None

async def new_peer_signal_pipe(offset, p2p_dest, node):
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
        return signal_pipe
    except asyncio.TimeoutError:
        # Cleanup and make sure it's unset.
        await signal_pipe.close()
    
async def fallback_machine_id(netifaces, app_id="p2pd"):
    host = socket.gethostname()
    if_name = get_default_iface(netifaces)
    mac = await get_mac_address(if_name, netifaces)
    buf = f"{app_id} {host} {if_name} {mac}"
    return to_s(hashlib.sha256(to_b(buf)).hexdigest())

