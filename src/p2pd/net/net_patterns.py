import asyncio
from .net_defs import *

async def proto_recv(pipe):
    n = 1 if pipe.sock.type == TCP else 5
    for _ in range(0, n):
        try:
            return await pipe.recv()
        except Exception:
            continue

async def proto_send(pipe, buf):
    n = 1 if pipe.sock.type == TCP else 5
    for _ in range(0, n):
        try:
            await pipe.send(buf)
            await asyncio.sleep(0.1)
        except Exception:
            continue

async def send_recv_loop(dest, pipe, buf, sub=SUB_ALL):
    #retry = 3
    n = 1 if pipe.sock.type == TCP else 3
    for _ in range(0, n):
        try:
            await pipe.send(buf, dest)
            return await pipe.recv(
                sub=sub,
                timeout=pipe.conf["recv_timeout"]
            )
        except asyncio.TimeoutError:
            log_exception()
            continue
        except Exception:
            log_exception()