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

    # Store subset of interface details.
    nat_pairs = []

    # Loop over all the interface details by address family.
    for _, if_info in enumerate(p2p_addr):
        # Save interface details we're interested in.
        nat_pairs.append([
            if_info["nat"]["type"],
            if_info
        ])

    # Sort based on NAT enum (lower = better)
    nat_pairs = sorted(
        nat_pairs,
        key=lambda x: x[0]
        )

    return [x[1] for x in nat_pairs]
    return nat_pairs

"""
The position of the infos in their lists correspond to
the if_index. Hence, modifying the original object
is going to cause code that depends on offsets to fail.
The hack here is just to copy the src and leave the
parent obj unchanged. The code seems to work.
"""
def swap_if_infos_with_overlapping_exts(src, dest):
    bound = min(len(src), len(dest))
    for i in range(0, bound):
        if i + 1 >= bound:
            break

        if src[i]["ext"] == dest[i]["ext"]:
            src[i], src[i + 1] = src[i + 1], src[i]
            #dest[i], dest[i + 1] = dest[i + 1], dest[i]

    return dest

"""
The iterator filters the addr info for both
P2P addresses by the best NAT.

The first addr info used for both is thus the
best possible pairing. Further iterations aren't
likely to be any more successful so to keep things
simple only the first iteration is tried.
"""
class IFInfoIter():
    def __init__(self, af, src_addr, dest_addr):
        self.src_addr = list(src_addr[af].values())
        self.dest_addr = list(dest_addr[af].values())
        self.src_addr = sort_if_info_by_best_nat(self.src_addr)
        self.dest_addr = sort_if_info_by_best_nat(self.dest_addr)
        self.our_offset = 0
        self.their_offset = 0
        self.af = af
        cond_one = not len(self.src_addr)
        cond_two = not len(self.dest_addr)
        if cond_one or cond_two:
            self.dest_addr = self.src_addr = []
            return

        swap_if_infos_with_overlapping_exts(
            self.src_addr,
            self.dest_addr
        )
    
    def __iter__(self):
        return self

    def __next__(self):
        # No matched address types.
        if not len(self):
            raise StopIteration

        # Stop when they have no new entries.
        if self.their_offset >= len(self.dest_addr):
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

    # Resolve the TURN address.
    route = await interface.route(af).bind()
    try:
        turn_addr = (
            turn_server["host"],
            turn_server["port"],
        )
        turn_addr = Address(*turn_addr)
        await turn_addr.res(route)
        turn_addr = turn_addr.select_ip(af).tup
    except:
        turn_addr = (
            turn_server[af],
            turn_server["port"],
        )
        turn_addr = Address(*turn_addr)
        await turn_addr.res(route)
        turn_addr = turn_addr.select_ip(af).tup

    # Make a TURN client instance to whitelist them.
    turn_client = TURNClient(
        route=route,
        turn_addr=turn_addr,
        turn_user=turn_server["user"],
        turn_pw=turn_server["pass"],
        turn_realm=turn_server["realm"],
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

async def for_addr_infos(func, timeout, cleanup, has_set_bind, max_pairs, reply, pp, conf=None):
    """
    Given info on a local interface, a remote interface,
    and a chosen connectivity technique, attempt to create
    a connection. Adapt the technique depending on whether
    addressing is suitably local or remote.
    """
    async def try_addr_infos(src_info, dest_info):
        # Local addressing and/or remote.
        for addr_type in conf["addr_types"]:
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
                        print(" error our if index")
                        continue

                # Support testing addr type failures.
                # This is for test harnesses.
                if addr_type in [NIC_FAIL, EXT_FAIL]:
                    use_addr_type = addr_type - 2
                    do_fail = True
                    print(f"test fail {addr_type}")
                else:
                    use_addr_type = addr_type
                    do_fail = False

                print(f"Addr types = {use_addr_type} do fail = {do_fail}")

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
                    print(src_info)
                    print(dest_info)
                    print("invalid matched af")
                    continue

                print(dest_info["ip"])

                """
                There are rules that govern the reachability
                of a destination by a given interface. This
                function takes care of edge cases mostly
                to do with same-machine, multi-interfaces.
                """
                interface = await select_if_by_dest(
                    af,
                    dest_info["ip"],
                    interface,
                    pp.node.ifs,
                )
                print(f"if = {id(interface)}")
                print(f"netifaces = {interface.netifaces}")
                

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
                    print(f"result not none {result}")
                    return result
                
                msg = f"FAIL: {func} {use_addr_type} {result}"
                print(msg)
                
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
    count = 1
    #max_pairs = 1
    for af in VALID_AFS:
        if reply is not None:
            # Try select if info based on their chosen offset.
            src_info = pp.src[af][reply.routing.dest_index]
            dest_info = pp.dest[af][reply.meta.src_index]
            ret = await async_wrap_errors(
                try_addr_infos(src_info, dest_info)
            )

            return ret

        # Iterates by shared AFs
        # filtered by best NAT (non-overlapping WANS.)
        if_info_iter = IFInfoIter(af, pp.src, pp.dest)
        if not len(if_info_iter):
            continue

        # Get interface offset that supports this af.
        for src_info, dest_info in if_info_iter:
            # Only try up to N pairs per technique.
            # Technique-specific N to avoid lengthy delays.
            print(src_info)
            print(dest_info)
            print()
            ret = await async_wrap_errors(
                try_addr_infos(src_info, dest_info)
            )

            # Success so return.
            if ret is not None:
                return ret
                
            count += 1
            if count >= max_pairs:
                return None
            

            # Cleanup here?
                
    # Failure.
    return None

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
        print("sig pipe timeout")
        # Cleanup and make sure it's unset.
        await signal_pipe.close()
    
async def fallback_machine_id(netifaces, app_id="p2pd"):
    host = socket.gethostname()
    if_name = get_default_iface(netifaces)
    mac = await get_mac_address(if_name, netifaces)
    buf = f"{app_id} {host} {if_name} {mac}"
    return to_s(hashlib.sha256(to_b(buf)).digest())

