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
###['irc.ouch.chat', 'irc.spotchat.org', 'irc.scoutlink.net']

filtered:
['irc.oftc.net', 'irc.euirc.net', 'irc.xxxchatters.com', 'irc.swiftirc.net', 'irc.darkmyst.org']

['irc.chatjunkies.org', 'irc.dosers.net', 'irc.entropynet.net',  'irc.liberta.casa']

'irc.financialchat.com', 'irc.irc2.hu', 'irc.phat-net.de', 'irc.slacknet.org', 'irc.tweakers.net'

IP6:

['irc.oftc.net', 'irc.euirc.net', 'irc.swiftirc.net', 'irc.darkmyst.org', 'irc.entropynet.net', 'irc.liberta.casa', 'irc.phat-net.de', 'irc.slacknet.org', 'irc.tweakers.net']


make different lists for v4 and v6
sort by age

how will the algorithm work?

make a few tlds
    distribute a portion of the old servers between them (so that they are the majority) with the newer as a minority
    repeat until no servers remain 

UNUSED_IRC = [

    {
        'domain': 'irc.xxxchatters.com',
        'afs': [IP4],

        # 9 march 2007
        'creation': 1173358800
    },

    
    {
        'domain': 'irc.chatjunkies.org',
        'afs': [IP4],

        # 28 june 2002
        'creation': 1025186400
    },
    {
        'domain': 'irc.dosers.net',
        'afs': [IP4],

        # 20 may 2020
        'creation': 1590501600
    },
    {
        'domain': 'irc.financialchat.com',
        'afs': [IP4],

        # 1 aug 2002
        'creation': 1028210400
    },
    {
        'domain': 'irc.irc2.hu',
        'afs': [IP4],

        # 4 jan 2004
        'creation': 1073134800
    },
    {
        'domain': 'irc.liberta.casa',
        'afs': [IP4, IP6],

        # 7 feb 2020
        'creation': 1580994000
    },
]




SERVERS = [
]

14 servers to start with. not bad. this should work.

these results are about what i calculated. so maybe its not too bad.

a more advanced scanner that can account for the 30 min wait time for nick and chan
registration is likely to have more results

lookup:
1. fetch domain from all channels 2 of 3
2. use majority hash pub key found in records and discard others
3. use most recent update record

registration:
1. ensure name is unavailable on at least m servers 3 of 5
2. register the channels

username = p2pd + sha256(domain + usern + pw)[:12]
nick = p2pd + (domain + nick + pw)[:12]
email = p2pd_ + (domain + 'email' + pw)[:12] @p2pd.net
user_password = sh256(domain + pw)
chan_password = sha256(domain + name + pw)

handle ident requests

b':NickServ!NickServ@services.slacknet.org NOTICE n619b848 :This nickname is registered. Please choose a different nickname, or identify via \x02/msg NickServ identify <password>\x02.\r\n'
b':NickServ!NickServ@services.slacknet.org NOTICE n619b848 :\x02n619b848\x02 is already registered.\r\n'

"""

import asyncio
import re
from .utils import *
from .address import *
from .interface import *
from .base_stream import *

IRC_DNS_G1 = [
    {
        'domain': 'irc.slacknet.org',
        'afs': [IP4, IP6],

        # 20 aug 2000
        'creation': 966434400
    },
    {
        'domain': 'irc.phat-net.de',
        'afs': [IP4, IP6],

        # 6 nov 2000
        'creation': 975848400
    },
    {
        'domain': 'irc.tweakers.net',
        'afs': [IP4, IP6],

        # 30 apr 2002
        'creation': 1020088800
    },
    {
        'domain': 'irc.swiftirc.net',
        'afs': [IP4, IP6],

        # 10 march 2007
        'creation': 1173445200
    },
    {
        'domain': 'irc.liberta.casa',
        'afs': [IP4, IP6],

        # 7 feb 2020
        'creation': 1580994000
    },
]

IRC_DNS_G2 = [
    {
        'domain': 'irc.slacknet.org',
        'afs': [IP4, IP6],

        # 20 aug 2000
        'creation': 966434400
    },
    {
        'domain': 'irc.euirc.net',
        'afs': [IP4, IP6],


        # 19 sep 2000
        "creation": 969282000
    },
    {
        'domain': 'irc.oftc.net',
        'afs': [IP4, IP6],

        # 20 jul 2002
        "creation": 1027087200
    },
    {
        'domain': 'irc.darkmyst.org',
        'afs': [IP4, IP6],

        # 26 nov 2002
        'creation': 1038229200
    },
    {
        'domain': 'irc.entropynet.net',
        'afs': [IP4, IP6],

        # 11 sep 2011
        'creation': 1312984800
    },
]

IRC_DNS = {
    "p2pd": IRC_DNS_G1,
    "peer": IRC_DNS_G1,
    "ddns": IRC_DNS_G2,
    "node": IRC_DNS_G2,
}

# 3 of 5 servers must be working for registration to succeed.
IRC_REG_M = 3

IRC_AF = IP6
IRC_HOST = "irc.darkmyst.org" # irc.darkmyst.org
IRC_CONF = dict_child({
    "use_ssl": 1,
    "ssl_handshake": 8,
    "con_timeout": 4,
}, NET_CONF)

# Changeable, not fixed.
IRC_NICK = "client_dev_nick1" + to_s(rand_plain(8))

# Fixed, account for ident.
IRC_USERNAME = "client_dev_user1" + to_s(rand_plain(8))


IRC_EMAIL = "test_irc" + to_s(rand_plain(8)) + "@p2pd.net"
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

class IRCSession():
    def __init__(self, server_info, seed):
        self.con = None
        self.recv_buf = ""
        self.get_motd = asyncio.Future()
        self.register_status = asyncio.Future()
        self.server_info = server_info
        self.seed = seed

        # Derive details for IRC server.
        self.irc_server = self.server_info["domain"]
        self.username = "u" + sha256(self.irc_server + "user" + seed)[:7]
        self.user_pass = sha256(self.irc_server + "pass" + seed)
        self.nick = "n" + sha256(self.irc_server + "nick" + seed)[:7]
        self.email = "p2pd_" + sha256(self.irc_server + "email" + seed)[:12]
        self.email += "@p2pd.net"

        #self.chan_name = 
        #self.chan_pass = sha256(domain + chan_name + seed)


    async def start(self, i):
        # Destination of IRC server to connect to.
        # For simplicity all IRC servers support v4 and v6.
        dest = await Address(
            self.irc_server,
            6697,
            i.route()
        )

        # Connect to IRC server.
        route = await i.route().bind()
        self.con = await pipe_open(
            TCP,
            route,
            dest,
            msg_cb=self.msg_cb,
            conf=IRC_CONF
        )

        # Tell server user for the session.
        await self.con.send(
            IRCMsg(
                cmd="USER",
                param=f"{self.username} * {self.irc_server}",
                suffix="*"
            ).pack()
        )
        await self.con.send(
            IRCMsg(cmd="NICK", param=self.nick).pack()
        )

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
                suffix=f"REGISTER {self.user_pass} {self.email}"
            ).pack()
        )
        return

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
        print(msg)

        pos_chan_msgs = [
            "registered under",
            "is now registered",
            "successfully registered",
        ]

        neg_chan_msgs = [
            "not complete registration",
            "following link",
            "link expires",
            "address is not confirmed"
        ]

        try:
            # Keep a buffer of potential protocol messages.
            # These may be partial in the case of TCP.
            self.recv_buf += to_s(msg)
            msgs, new_buf = extract_irc_msgs(self.recv_buf)
            self.recv_buf = new_buf

            # Disable chan success in some cases.
            skip_register = False
            for msg in msgs:
                if isinstance(msg.suffix, str):
                    for chan_fail in neg_chan_msgs:
                        if chan_fail in msg.suffix:
                            skip_register = True
                            break

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

                # Process status message.
                if isinstance(msg.suffix, str):
                    # Login if account already exists.
                    if "nickname is registered" in msg.suffix:
                        await self.con.send(
                            IRCMsg(
                                cmd="PRIVMSG",
                                param="NickServ",
                                suffix=f"IDENTIFY {self.user_pass}"
                            ).pack()
                        )
                        
                    # Indicate channel was registered.
                    if skip_register == False:
                        for chan_success in pos_chan_msgs:
                            if chan_success in msg.suffix:
                                self.register_status.set_result(True)
        except Exception:
            log_exception()

        

if __name__ == '__main__':


    async def test_irc_dns():
        """
        msg = ":ChanServ!services@services.xxxchatters.com NOTICE client_dev_nick1sZU8um :Channel \x02#qfATvV8F\x02 registered under your account: client_dev_nick1sZU8um\r\n:ChanServ!services@services.xxxchatters.com MODE #qfATvV8F +rq client_dev_nick1sZU8um\r\n"
        out = extract_irc_msgs(msg)
        print(out)
        print(out[0][0].suffix)

        
        return
        """

        seed = "test_seed"
        i = await Interface().start()

        print("If start")
        print(i)

        irc_dns = IRCSession(IRC_DNS_G1[0], seed)
        await irc_dns.start(i)

        while 1:
            await asyncio.sleep(1)


        return



        
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