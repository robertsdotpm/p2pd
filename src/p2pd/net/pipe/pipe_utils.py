import asyncio
from ..net_utils import *

def tup_to_sub(dest_tup):
    dest_tup = client_tup_norm(dest_tup)
    return (
        b"", # Any message.
        dest_tup
    )

def norm_client_tup(client_tup):
    ip = ip_norm(client_tup[0])
    return (ip, client_tup[1])

async def close_all_clients(tcp_clients, loop=None, timeout=1.0):
    if loop is None:
        loop = asyncio.get_event_loop()

    tasks = []    
    for client in tcp_clients:
        if client.transport is not None:
            client.transport.close()
            client.transport = None
            
        sock = client.sock
        if sock is None:
            continue

        # Await the OS-level socket closure with timeout
        tasks.append(asyncio.wait_for(loop.await_fd_close(sock), timeout=timeout))

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        # Optional: log exceptions
        for r in results:
            if isinstance(r, Exception):
                pass  # log or ignore

