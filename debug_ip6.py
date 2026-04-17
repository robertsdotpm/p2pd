"""Test: can a socket bound to global IPv6 sendto ::1?"""
import asyncio, socket
from aionetiface import *

async def test():
    nic = await Interface()
    if IP6 not in nic.supported():
        print('no ipv6'); return

    # Create a receiver on ::1
    r6lo = await nic.route(IP6).bind(ips='::1', port=0)
    recv_pipe = await Pipe(UDP, None, r6lo).connect()
    recv_addr = recv_pipe.sock.getsockname()
    print(f'Receiver bound to: {recv_addr}')

    # Create a sender bound to global IPv6
    r6 = await nic.route(IP6).bind()
    dest = await resolv_dest(IP6, ('::1', recv_addr[1]), nic)
    send_pipe = await Pipe(UDP, dest, r6).connect()
    print(f'Sender bound to: {send_pipe.sock.getsockname()}')

    recv_pipe.subscribe(SUB_ALL)
    await send_pipe.send(b'test', ('::1', recv_addr[1]))
    await asyncio.sleep(0.2)
    data = await recv_pipe.recv(timeout=1)
    if data:
        print(f'Receiver got: {data!r}')
    else:
        print('Receiver got nothing')

    await send_pipe.close(); await recv_pipe.close()

asyncio.run(test())
