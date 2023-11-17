import asyncio
import re
from .address import *
from .interface import *
from .base_stream import *

IRC_AF = IP6
IRC_HOST = "irc.darkmyst.org"
IRC_PORT = 6697
IRC_CONF = dict_child({
    "use_ssl": 1
}, NET_CONF)

class IRCMsg():
    def __init__(self, prefix, cmd, param, suffix):
        self.prefix = prefix
        self.cmd = cmd
        self.param = param
        self.suffix = suffix

"""
TCP is stream-oriented and portions of IRC protocol messages
may be received. This code handles finding valid IRC messages and
truncating the recv buffer once extracted.
"""
def extract_irc_msgs(buf):
    # optional             optional
    # :prefix CMD param... :suffix ( :[^\r]+)?
    p = "(?:[:]([^ :]+?) )?([A-Z0-9]+) (?:([^\r\:]+?) ?)(?:[:]([^:\r]+))?\r\n"
    p = re.compile(p)

    # Loop over all protocol messages in buf.
    # Truncate buf as messages are extracted.
    msgs = []
    offset = None
    while 1:
        # No matches found yet.
        # Buffer contains a partial response or its empty.
        match = p.search(buf)
        if match is None:
            break

        # Extract matched message.
        msg = IRCMsg(*list(match.groups()))
        msgs.append(msg)

        # Get the offset of the match end.
        # Truncate buf as messages are extracted.
        offset = match.end()
        if offset < len(buf):
            buf = buf[offset + 1:]
        else:
            break

    return msgs, buf

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

    async def msg_cb(self):
        pass

if __name__ == '__main__':
    async def test_irc_dns():
        msg = """:server.example.com 001 nickname test :Welcome to the IRC server, nickname!\r\n
:server.example.com 376 nickname :End of MOTD\r\n
PRIVMSG #channel :Hello, this is a message!\r\n
"""
        out = extract_irc_msgs(msg)


        return
        i = await Interface().start()
        ircdns = await IRCDNS().start(i)
        pass

    async_test(test_irc_dns)