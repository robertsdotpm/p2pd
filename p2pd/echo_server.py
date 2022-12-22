from .daemon import *

class EchoServer(Daemon):
    def __init__(self):
        super().__init__()

    async def msg_cb(self, msg, client_tup, pipe):
        await pipe.send(msg, client_tup)

if __name__ == "__main__": # pragma: no cover
    print("See tests/test_daemon.py for code that uses this.")
