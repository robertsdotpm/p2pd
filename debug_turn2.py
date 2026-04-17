"""Debug TURN client startup - full trace"""
import asyncio
from unittest.mock import patch
from aionetiface import *
from p2pd.protocol.turn import turn_client as tc_module
from p2pd.protocol.turn import turn_process
from p2pd.protocol.turn.turn_process import (
    turn_parse_msg, turn_get_data_attr, process_attributes, is_auth_ready
)
from tests.turn_server import TURNServer, TURN_TEST_PORT

async def verbose_process_replies(self):
    print('[PR] starting', flush=True)
    while self.state != 9:
        try:
            out = await self.turn_pipe.recv(timeout=1)
        except Exception as e:
            print(f'[PR] recv exception: {type(e).__name__}: {e}', flush=True)
            await asyncio.sleep(0.5)
            continue
        if out is None:
            continue
        
        print(f'[PR] got {len(out)} bytes', flush=True)
        
        turn_msg, turn_method, turn_status = turn_parse_msg(memoryview(out))
        if turn_msg is None:
            print('[PR] parse failed', flush=True)
            continue
        
        print(f'[PR] method={bytes(turn_method).hex()} status={bytes(turn_status).hex()}', flush=True)
        
        msg_data, peer_tup = turn_get_data_attr(turn_msg, self.turn_pipe.route.af, self)
        if msg_data is not None and peer_tup is not None:
            print(f'[PR] data indication', flush=True)
            continue
        
        txid = turn_msg.txn_id
        found = txid in self.msgs
        print(f'[PR] txid in msgs: {found}', flush=True)
        if not found:
            continue
        
        try:
            error_code, error_msg = await process_attributes(self.turn_pipe.route.af, self, turn_msg)
            print(f'[PR] after process_attrs: auth_ready={is_auth_ready(self)}, auth_event={self.auth_event.is_set()}, realm={self.realm}, nonce={self.nonce is not None}, key={self.key is not None}', flush=True)
        except Exception as e:
            print(f'[PR] process_attributes error: {e}', flush=True)
            import traceback; traceback.print_exc()
            continue
        
        if bytes(turn_status) == bytes(STUNMsgCodes.ErrorResp):
            print(f'[PR] error resp: code={error_code}', flush=True)
        
        if bytes(turn_method) == bytes(STUNMsgTypes.Allocate):
            print(f'[PR] setting status future', flush=True)
            if not self.msgs[txid]["status"].done():
                self.msgs[txid]["status"].set_result(1)  # STATUS_SUCCESS
            
            if bytes(turn_status) == bytes(STUNMsgCodes.ErrorResp):
                print(f'[PR] scheduling signed allocate, state={self.state}', flush=True)
                if self.state != 2:  # TURN_TRY_ALLOCATE
                    self.state = 2
                    asyncio.create_task(turn_process.async_retry(
                        lambda: self.allocate_relay(sign=True), count=5
                    ))
            
            if bytes(turn_status) == bytes(STUNMsgCodes.SuccessResp):
                print(f'[PR] success allocate! setting auth_event', flush=True)
                self.auth_event.set()
        
        elif bytes(turn_method) == bytes(STUNMsgTypes.CreatePermission):
            print(f'[PR] CreatePermission success', flush=True)
            if not self.msgs[txid]["status"].done():
                self.msgs[txid]["status"].set_result(1)
        
        elif bytes(turn_method) == bytes(STUNMsgTypes.Refresh):
            print(f'[PR] Refresh success', flush=True)
            if not self.msgs[txid]["status"].done():
                self.msgs[txid]["status"].set_result(1)
    
    print('[PR] done', flush=True)
    self.turn_client_stopped.set()

async def test():
    nic = await Interface()
    server = TURNServer(nic)
    await server.start()
    print('server started', flush=True)
    
    from p2pd.protocol.turn.turn_client import TURNClient
    
    with patch.object(tc_module, 'process_replies', verbose_process_replies):
        client = TURNClient(
            af=IP4,
            dest=('127.0.0.1', TURN_TEST_PORT),
            nic=nic,
            auth=('testuser', 'testpass'),
            realm='test.local',
        )
        
        try:
            await asyncio.wait_for(client.start(), timeout=15)
            print('SUCCESS!', flush=True)
            print(f'relay_tup: {client.relay_tup}', flush=True)
            print(f'mapped: {client.mapped}', flush=True)
            await client.close()
        except asyncio.TimeoutError:
            print('TIMEOUT', flush=True)
            print(f'auth_event: {client.auth_event.is_set()}, relay_event: {client.relay_event.is_set()}')
            print(f'state: {client.state}')
            print(f'relay_tup: {client.relay_tup}')
            print(f'mapped: {client.mapped}')
        except Exception as e:
            print(f'Exception: {type(e).__name__}: {e}', flush=True)
            import traceback; traceback.print_exc()
    
    await server.close()

asyncio.run(test())
