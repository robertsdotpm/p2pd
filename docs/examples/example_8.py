from p2pd import *

class EchoServer(Daemon):
    def __init__(self):
        super().__init__()
    
    async def msg_cb(self, msg, client_tup, pipe):
        await pipe.send(msg, client_tup)

async def example():
    i = await Interface()
    
    # Daemon instance.
    route = await i.route().bind(port=10126)
    echod = EchoServer()
    await echod.add_listener(
        TCP,
        route,
    )
    
    await echod.close()

if __name__ == '__main__':
    async_test(example)