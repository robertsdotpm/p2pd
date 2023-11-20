"""
- Firewalls for IRC servers silently drop packets if you
make successive connections too closely.



I dont think I can test the code on my p2pd server as it
actually is running proxies.

not quite sure how to determine a success response for a nick?
maybe the right approach is to then try a operation that needs those perms?


['irc.libera.chat', 'irc.esper.net']
"irc.darkmyst.org"
'irc.oftc.net',
'irc.euirc.net', 'irc.xxxchatters.com', 'irc.swiftirc.net']

these results are now more than what i calculated. so maybe its not too bad.

a more advanced scanner that can account for the 30 min wait time for nick and chan
registration is likely to have more results
"""

import asyncio
import re
from .utils import *
from .address import *
from .interface import *
from .base_stream import *

IRC_AF = IP4
IRC_HOST = "irc.darkmyst.org" # irc.darkmyst.org
IRC_PORT = 6697
IRC_CONF = dict_child({
    "use_ssl": 1,
    "ssl_handshake": 8,
    "con_timeout": 4,
}, NET_CONF)

IRC_NICK = "client_dev_nick1" + to_s(rand_plain(6))
IRC_USERNAME = "client_dev_user1"
IRC_REALNAME = "matthew"
IRC_EMAIL = "test_irc" + to_s(rand_plain(8)) + "@p2pd.net"
IRC_PASS = to_s(file_get_contents("p2pd/irc_pass.txt"))
IRC_CHAN = f"#{to_s(rand_plain(8))}"

class IRCMsg():
    def __init__(self, prefix=None, cmd=None, param=None, suffix=None):
        self.prefix = prefix
        self.cmd = cmd
        self.param = param
        self.suffix = suffix

    def pack(self):
        param = prefix = suffix = ""
        if self.prefix:
            prefix = f":{self.prefix} "
        
        if self.suffix:
            suffix = f" :{self.suffix}"

        if self.param:
            param = self.param

        return to_b(f"{prefix}{self.cmd} {param}{suffix}\r\n")

"""
TCP is stream-oriented and portions of IRC protocol messages
may be received. This code handles finding valid IRC messages and
truncating the recv buffer once extracted.
"""
def extract_irc_msgs(buf):
    #     optional                                       optional
    #     :prefix            CMD           param...      :suffix 
    p = "(?:[:]([^ :]+?) )?([A-Z0-9]+) (?:([^\r\:]+?) ?)?(?:[:]([^\r]+))?\r\n"
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
            buf = buf[offset:]
        else:
            buf = ""

    return msgs, buf

class IRCDNS():
    def __init__(self, irc_server):
        self.con = None
        self.recv_buf = ""
        self.get_motd = asyncio.Future()
        self.register_status = asyncio.Future()
        self.irc_server = irc_server

    async def start(self, i):
        dest = await Address(self.irc_server, IRC_PORT, i.route(IRC_AF))
        nick_msg = IRCMsg(cmd="NICK", param=IRC_NICK)
        user_msg = IRCMsg(
            cmd="USER",
            param=f"{IRC_USERNAME} testhosname *",
            suffix=f"{IRC_REALNAME}"
        )

        route = await i.route(IRC_AF).bind()
        self.con = await pipe_open(
            TCP,
            route,
            dest,
            msg_cb=self.msg_cb,
            conf=IRC_CONF
        )

        # Send data and allow for time to receive them.
        nick_buf = nick_msg.pack()
        await self.con.send(nick_buf)   

        user_buf = user_msg.pack()
        await self.con.send(user_buf)
        await asyncio.sleep(0)

        # Wait for message of the day.
        await asyncio.wait_for(
            self.get_motd, 30
        )

        # Attempt to register the nick at the server.
        # See if the server requires confirmation.
        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="NickServ",
                suffix=f"REGISTER {IRC_PASS} {IRC_EMAIL}"
            ).pack()
        )
        await asyncio.sleep(2)


        # Join channel.
        await self.con.send(
            IRCMsg(
                cmd="JOIN",
                param=f"{IRC_CHAN}",
            ).pack()
        )

        # register channel.
        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="ChanServ",
                suffix=f"REGISTER {IRC_CHAN}"
            ).pack()
        )

        # register channel.
        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="ChanServ",
                suffix=f"REGISTER {IRC_CHAN} sdv234iwsk13g8q__wlsdf"
            ).pack()
        )

        # register channel.
        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="ChanServ",
                suffix=f"REGISTER {IRC_CHAN} sdv234iwsk13g8q__wlsdf desc"
            ).pack()
        )

        # Wait for message of the day.
        await asyncio.wait_for(
            self.register_status, 10
        )

        await self.con.send(IRCMsg(cmd="QUIT").pack())
        await self.con.close()
        return self.irc_server

    async def msg_cb(self, msg, client_tup, pipe):
        chan_msgs = [
            "registered under",
            "is now registered",
            "successfully registered",
        ]

        try:
            # Keep a buffer of potential protocol messages.
            # These may be partial in the case of TCP.
            self.recv_buf += to_s(msg)
            msgs, new_buf = extract_irc_msgs(self.recv_buf)
            self.recv_buf = new_buf

            # Loop over the IRC protocol messages.
            # Process the minimal functions we understand.
            for msg in msgs:
                # End of motd.
                if msg.cmd in ["376", "411"]:
                    self.get_motd.set_result(True)

                # Process ping.
                if msg.cmd == "PING":
                    pong = IRCMsg(
                        cmd="PONG",
                        suffix=msg.suffix,
                    )

                    await self.con.send(pong.pack())

                # Channel registered successfully.
                if isinstance(msg.suffix, str):
                    for chan_success in chan_msgs:
                        if chan_success in msg.suffix:
                            self.register_status.set_result(True)
        except:
            log_exception()

        

if __name__ == '__main__':
    IRC_SERVERS1 = [
        "irc.libera.chat",
        "irc.oftc.net",
        "irc.uni-erlangen.de",
        "irc.undernet.org",
        "irc.uworld.se",
        "irc.efnet.nl",
        "irc.freenode.net",
        "irc.quakenet.org",
        "irc.hackint.org",
        "irc.dal.net",
        "irc.chathispano.com",
        "irc.p2p-network.net",
        "irc.kampungchat.org",
        "irc.simosnap.com",
        "irc.hybridirc.com",
        "irc.explosionirc.net",
        "irc.gamesurge.net",
        "irc.snoonet.org",
        "irc.link-net.org",
        "irc.esper.net",
        "irc.abjects.net",
        "irc.synirc.net",
        "irc.europnet.org",
        "irc.konnectchatirc.net",
        "irc.oltreirc.eu",
        "irc.irchighway.net",
        "irc.irc-nerds.net",
        "irc.scenep2p.net",
        "irc.orixon.org",
        "irc.coders-irc.net",
        "irc.openjoke.org",
        "irc.digitalirc.org",
        "irc.darkscience.net",
        "irc.tilde.chat",
        "irc.geeknode.org",
        "irc.slashnet.org",
        "irc.sohbet.net",
        "irc.w3.org",
        "irc.IRCGate.it",
        "irc.chaat.fr",
        "irc.rootworld.net",
        "irc.darkfasel.net",
        "irc.freeunibg.eu",
        "irc.euirc.net",
        "irc.geekshed.net",
        "irc.globalirc.it",
        "irc.chatbg.info",
        "irc.furnet.org",
        "irc2.irccloud.com",
        "irc.xxxchatters.com",
        "irc.bol-chat.com",
        "irc.sorcery.net",
        "irc.dejatoons.net",
        "irc.technet.chat",
        "irc.kalbim.net",
        "irc.ptnet.org",
        "irc1.ptirc.org",
        "irc.skychatz.org",
        "irc.axon.pw",
        "irc.tamarou.com",
        "irc.mindforge.org",
        "irc.abandoned-irc.net",
        "irc.epiknet.org",
        "irc.allnetwork.org",
        "irc1.net-tchat.fr",
        "irc.swiftirc.net",
        "irc.afternet.org",
        "irc2.chattersnet.nl",
        "irc.allnightcafe.com",
        "irc.evilnet.org",
        "irc.rezosup.org",
        "irc.recycled-irc.net",
        "irc2.acc.umu.se",
        "irc.mibbit.net",
        "irc.pirc.pl",
        "irc.atrum.org"
    ]

    #IRC_SERVERS1 = ["irc.darkmyst.org"]

    async def test_irc_dns():
        """
        msg = ":ChanServ!services@services.xxxchatters.com NOTICE client_dev_nick1sZU8um :Channel \x02#qfATvV8F\x02 registered under your account: client_dev_nick1sZU8um\r\n:ChanServ!services@services.xxxchatters.com MODE #qfATvV8F +rq client_dev_nick1sZU8um\r\n"
        out = extract_irc_msgs(msg)
        print(out)
        print(out[0][0].suffix)

        
        return
        """


        i = await Interface().start()

        print("If start")
        print(i)

        
        tasks = []
        for server in IRC_SERVERS1:
            task = async_wrap_errors(IRCDNS(server).start(i))
            tasks.append(task)

        out = await asyncio.gather(*tasks)
        print(out)
        out = strip_none(out)
        print(out)
        return
        

        
        for server in IRC_SERVERS1:
            out = await async_wrap_errors(
                IRCDNS(server).start(i),
                timeout=20
            )
            print(out)


    async_test(test_irc_dns)