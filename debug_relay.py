"""Debug relay path"""
import asyncio
from aionetiface import *
from p2pd.protocol.turn.turn_client import TURNClient
from tests.turn_server import TURNServer, TURN_TEST_PORT, TURN_TEST_USER, TURN_TEST_PASS, TURN_TEST_REALM

async def make_client(nic):
    c = TURNClient(
        af=IP4, dest=('127.0.0.1', TURN_TEST_PORT), nic=nic,
        auth=(to_s(TURN_TEST_USER), to_s(TURN_TEST_PASS)),
        realm=to_s(TURN_TEST_REALM),
    )
    await asyncio.wait_for(c.start(), 15)
    return c

async def test():
    nic = await Interface()
    server = TURNServer(nic)
    await server.start()
    
    ca = await make_client(nic)
    cb = await make_client(nic)
    print(f'ca relay: {await ca.relay_tup_future}')
    print(f'cb relay: {await cb.relay_tup_future}')
    
    tup_a = await ca.client_tup_future
    relay_a = await ca.relay_tup_future
    tup_b = await cb.client_tup_future
    relay_b = await cb.relay_tup_future
    
    print(f'tup_a={tup_a}, relay_a={relay_a}')
    print(f'tup_b={tup_b}, relay_b={relay_b}')
    
    await ca.accept_peer(tup_b, relay_b)
    await cb.accept_peer(tup_a, relay_a)
    print(f'ca.peers: {ca.peers}')
    print(f'cb.peers: {cb.peers}')
    
    # Check proto for stream
    print(f'ca.proto: {ca.proto}')
    print(f'ca.stream: {ca.stream}')
    print(f'ca.stream.handle type: {type(ca.stream.handle)}')
    
    # Now try to send
    print('Sending message...')
    await ca.send(b"hello", tup_b)
    await asyncio.sleep(0.5)
    
    # Check server relay socket received something
    print(f'Server allocations: {list(server.allocations.keys())}')
    
    # Try to recv on cb
    received = await cb.recv(timeout=3)
    print(f'Received on cb: {received}')
    
    await ca.close()
    await cb.close()
    await server.close()

asyncio.run(test())
