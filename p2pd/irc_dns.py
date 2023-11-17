import asyncio
import re
from .utils import *
from .address import *
from .interface import *
from .base_stream import *

IRC_AF = IP6
IRC_HOST = "irc.darkmyst.org"
IRC_PORT = 6697
IRC_CONF = dict_child({
    "use_ssl": 1
}, NET_CONF)

IRC_NICK = "client_dev_nick1"
IRC_USERNAME = "client_dev_user1"
IRC_REALNAME = "matthew"

class IRCMsg():
    def __init__(self, prefix=None, cmd=None, param=None, suffix=None):
        self.prefix = prefix
        self.cmd = cmd
        self.param = param
        self.suffix = suffix

    def pack(self):
        prefix = suffix = ""
        if self.prefix:
            prefix = f":{self.prefix} "
        
        if self.suffix:
            suffix = f" :{self.suffix}"

        return to_b(f"{prefix}{self.cmd} {self.param}{suffix}\r\n")

"""
TCP is stream-oriented and portions of IRC protocol messages
may be received. This code handles finding valid IRC messages and
truncating the recv buffer once extracted.
"""
def extract_irc_msgs(buf):
    #     optional                                       optional
    #     :prefix            CMD           param...      :suffix 
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
        print(list(match.groups()))
        msg = IRCMsg(*list(match.groups()))
        msgs.append(msg)

        # Get the offset of the match end.
        # Truncate buf as messages are extracted.
        offset = match.end()
        if offset < len(buf):
            buf = buf[offset:]
        else:
            buf = ""

    return msgs, buf

class IRCDNS():
    def __init__(self):
        self.recv_buf = ""
        self.get_motd = asyncio.Future()

    async def start(self, i):
        route = await i.route(IRC_AF).bind()
        dest = await Address(IRC_HOST, IRC_PORT, route)
        pipe = await pipe_open(
            TCP,
            route,
            dest,
            msg_cb=self.msg_cb,
            conf=IRC_CONF
        )

        nick_msg = IRCMsg(cmd="NICK", param=IRC_NICK)
        user_msg = IRCMsg(
            cmd="USER",
            param=f"{IRC_USERNAME} testhosname *",
            suffix=f"{IRC_REALNAME}"
        )

        await pipe.send(nick_msg.pack())
        await pipe.send(user_msg.pack())

        motd = await self.get_motd
        print(motd.param)
        print(motd.suffix)
        return self

    async def msg_cb(self, msg, client_tup, pipe):
        # Keep a buffer of potential protocol messages.
        # These may be partial in the case of TCP.
        print(msg)
        self.recv_buf += to_s(msg)
        msgs, new_buf = extract_irc_msgs(self.recv_buf)
        self.recv_buf = new_buf

        # Loop over the IRC protocol messages.
        # Process the minimal functions we understand.
        for msg in msgs:
            # Set message of the day.
            if msg.cmd == "001" and not self.get_motd.done():
                self.get_motd.set_result(msg)

        

if __name__ == '__main__':
    async def test_irc_dns():
        """
        msg = ":paralysis.tx.us.darkmyst.org NOTICE * :*** Looking up your hostname...\r\n:paralysis.tx.us.darkmyst.org NOTICE * :*** Couldn't look up your hostname\r\n"
        out = extract_irc_msgs(msg)
        print(out)
        for m in out[0]:
            print(m.pack())
        """
  

        i = await Interface().start()
        ircdns = await IRCDNS().start(i)
        pass

    async_test(test_irc_dns)