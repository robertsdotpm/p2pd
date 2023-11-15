import asyncio
from .address import *
from .interface import *
from .base_stream import *

IRC_AF = IP6
IRC_HOST = "irc.darkmyst.org"
IRC_PORT = 6697
IRC_CONF = dict_child({
    "use_ssl": 1
}, NET_CONF)

class IRCDNS():
    def __init__(self):
        pass

    async def start(self, i):
        route = await i.route(IRC_AF).bind()
        dest = await Address(IRC_HOST, IRC_PORT, route)
        pipe = await pipe_open(TCP, route, dest, conf=IRC_CONF)
        print(pipe)
        print(pipe.sock)
        buf = await pipe.recv()
        print(buf)
        await pipe.close()
        return self

if __name__ == '__main__':
    async def test_irc_dns():
        i = await Interface().start()
        ircdns = await IRCDNS().start(i)
        pass

    async_test(test_irc_dns)