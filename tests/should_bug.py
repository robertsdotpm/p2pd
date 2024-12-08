import asyncio
import socket

def patch():
    """Patch selectors.SelectSelector to fix WinError 10038 in Windows

    Ref: https://bugs.python.org/issue33350
    """

    import select
    from selectors import SelectSelector

    def _select(self, r, w, _, timeout=None):
        try:
            r, w, x = select.select(r, w, w, timeout)
        except OSError as e:
            if hasattr(e, 'winerror') and e.winerror == 10038:
                # descriptors may already be closed
                return [], [], []
            raise
        else:
            return r, w + x, []

    SelectSelector._select = _select

class MyProtocol(asyncio.Protocol):

    def connection_made(self, transport):
        transport.write(b'123')   # just in case a write is needed

port = 6666

async def connect_and_recv(loop, sock):
    try:
        await loop.sock_connect(sock, ('127.0.0.1', port))
        while True:
            await loop.sock_recv(sock, 20)
    except asyncio.CancelledError:
        print("Cancelled")
        sock.close()


async def main(loop):
    server = await loop.create_server(MyProtocol, '127.0.0.1', port)
    sock = socket.socket()
    sock.setblocking(False)
    task = loop.create_task(connect_and_recv(loop, sock))
    await asyncio.sleep(0.1)
    task.cancel()
    await asyncio.sleep(0.1)

patch()
loop = asyncio.get_event_loop()
loop.run_until_complete(main(loop))