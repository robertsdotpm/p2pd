import asyncio
from concurrent.futures import ProcessPoolExecutor
from .address import Address
from .utils import *
from .net import *
from .nat import *

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