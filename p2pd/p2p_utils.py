import asyncio
from concurrent.futures import ProcessPoolExecutor
from .address import Address
from .utils import *
from .net import *
from .nat import *
from .turn_client import TURNClient
from .settings import *
from .p2p_addr import parse_peer_addr

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
a private address section that corrosponds to
the address passed to bind() for the nodes listen().
"""
def work_behind_same_router(src_addr, dest_addr):
    new_addr = copy.deepcopy(dest_addr)
    for af in VALID_AFS:
        for dest_info in new_addr[af]:
            for src_info in src_addr[af]:
                # Same external address as one of our own.
                if dest_info["ext"] == src_info["ext"]:
                    # Connect to its internal address instead.
                    dest_info["ext"] = dest_info["nic"]

                    # Disable NAT in LANs.
                    delta = delta_info(NA_DELTA, 0)
                    nat = nat_info(OPEN_INTERNET, delta)
                    dest_info["nat"] = nat

    return new_addr

# TODO: move this somewhere else.
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
"""
async def for_addr_infos(pipe_id, src_bytes, dest_bytes, func):
    # Use an AF supported by both.
    p2p_dest = parse_peer_addr(dest_bytes)
    our_addr = parse_peer_addr(src_bytes)
    for af in VALID_AFS:
        if_info_iter = IFInfoIter(af, our_addr, p2p_dest)
        if not len(if_info_iter):
            continue

        # Get interface offset that supports this af.
        for src_info, dest_info in if_info_iter:
            ret = await func(
                af,
                pipe_id,
                p2p_dest["node_id"],
                src_info,
                dest_info,
                dest_bytes,    
            )

            if ret is not None:
                return ret