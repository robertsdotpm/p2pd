import asyncio
import p2pd.protocol.turn.turn_process as tp

orig_process_replies = tp.process_replies

async def verbose_process_replies(self):
    print('[PR] starting', flush=True)
    count = 0
    while self.state != 9:
        try:
            out = await self.turn_pipe.recv(timeout=1)
        except Exception as e:
            print(f'[PR] recv exception: {type(e).__name__}: {e}', flush=True)
            await asyncio.sleep(0.5)
            continue
        if out is None:
            count += 1
            print(f'[PR] timeout #{count}', flush=True)
            if count > 4:
                break
            continue
        print(f'[PR] got {len(out)} bytes', flush=True)
        # Now call original
        break
    print('[PR] done', flush=True)
    self.turn_client_stopped.set()
    
tp.process_replies = verbose_process_replies

from p2pd.protocol.turn.turn_client import TURNClient
from tests.turn_server import TURNServer, TURN_TEST_PORT
from aionetiface import Interface, IP4

async def test():
    nic = await Interface()
    server = TURNServer(nic)
    await server.start()
    print('server started', flush=True)
    
    client = TURNClient(
        af=IP4,
        dest=('127.0.0.1', TURN_TEST_PORT),
        nic=nic,
        auth=('testuser', 'testpass'),
        realm='test.local',
    )
    
    try:
        await asyncio.wait_for(client.start(), timeout=10)
        print('SUCCESS!', flush=True)
    except asyncio.TimeoutError:
        print('TIMEOUT', flush=True)
    except Exception as e:
        print(f'Exception: {type(e).__name__}: {e}', flush=True)
        import traceback
        traceback.print_exc()

asyncio.run(test())
