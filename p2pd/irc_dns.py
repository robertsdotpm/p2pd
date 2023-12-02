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

['irc.chatjunkies.org', 'irc.dosers.net', 
    'irc.entropynet.net',  
        - email required for chan


'irc.liberta.casa']
    - no channel cmd

'irc.financialchat.com', 'irc.irc2.hu', 'irc.phat-net.de', 
    'irc.slacknet.org',
        - manual chan creation
    
    'irc.tweakers.net'

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



get channels made by user [done]
    could mean not having to manage a bunch of bs in a db
check if a channel exists on a server [done]


chan ident as operator [done]
chan set topic [done]
    TOPIC #test_chan_name123 :test topic to set.
chan get topic title [done]
need to write tests to check that the software works for all servers [done]

make channel open to join [server only]



keep joined topics or session active after disconnect so whois works?
is this possible?

cross server load_chans = 
approach 1
    1. Keep a bot in the channel
        - botserv?
    2. Get list to view all channels
    3. Grep for username in channel list

approach 2
    could you add a 'mark' to yourself that lists chans
    could you use a 'memo' service to store offline messages?
        memoserv is fascinating. it gives registered users a message box.

approach 3:
    user profile portion?

todo: there was a false positive for slacknet.org. when you register a chan
it says that the staff reviews all chan reg requests. so that would need
to be added to the scanner

it would probably make sense to run all major ircds on p2pd.net
and write unit tests against it. ensure the software works for them.


some servers have syntax like register chan desc [done]
    so if you pass the chan password there its bad

probably now need a feature like: [done]
    get reg syntax

todo: get op is broken as not all do +o some do other flags [removed]
-- seems like an unnecesary check as nickserv ident is what u need?

chan setting those modes doesnt seem to work [done]
    -- check if that portion is being done properly or if
    -- the first just doesnt support it

some servers require users to register to join chans. this makes sense.
    - see if you can unset +r on the channel

seems you need to use SET mlock for ki flags?
    - some servers use SET for topic too
    

last server has no topic command? [false positive]
join messages instead? [no]

ping - pong is incorrectly implemented (maybe?)

support set topic. [done]
    - 3 servers remain for testing.

which servers support memo and botservices
    - supporting mechanisms for loading owned chans seems
    well worth it.

need to also check that get topic for a channel is possible for a 
different user (a non op) for the servers chosen.

add IPs for all the servers to bypass dns

reg > X available for it to work

# 3 of 5 servers must be working for registration to succeed.
IRC_REG_M = 3
load from len(servers) ...


add proper version details that tells operators more about the project and
that its not a botnet.

perhaps unit tests for basic protocol messages
extracted from the extract function?

how to limit abuse for ops?
    seems like if no one can join the channel is pruned?
"""

import asyncio
import re
from .base62 import encodebytes as b62encode
from .utils import *
from .address import *
from .interface import *
from .base_stream import *


IRC_PREFIX = "19"

IRC_SERVERS = [
    # Works.
    {
        'domain': 'irc.phat-net.de',
        'afs': [IP4, IP6],

        # 6 nov 2000
        'creation': 975848400,

        'nick_serv': ["password", "email"],

        "ip": {
            IP4: "116.203.29.246",
            IP6: "2a01:4f8:c2c:628::1"
        }
    },
    # Works.
    {
        'domain': 'irc.tweakers.net',
        'afs': [IP4, IP6],

        # 30 apr 2002
        'creation': 1020088800,

        'chan_serv': ["password", "description"],
        'nick_serv': ["password", "email"],

        "ip": {
            IP4: "213.239.154.35",
            IP6: "2001:9a8:0:e:1337::6667" # Top kek.
        }
    },
    {
        'domain': 'irc.swiftirc.net',
        'afs': [IP4, IP6],

        # 10 march 2007
        'creation': 1173445200,

        'nick_serv': ["password", "email"],
        #'set_topic': "set",

        "ip": {
            IP4: "159.65.55.232",
            IP6: "2604:a880:4:1d0::75:0" # Top kek.
        }
    },
    {
        'domain': 'irc.euirc.net',
        'afs': [IP4, IP6],

        # 19 sep 2000
        "creation": 969282000,
        'chan_serv': ["password", "description"],
        'nick_serv': ["password", "email"],
        'set_topic': "set",

        "ip": {
            IP4: "83.137.40.10",
            IP6: "2001:41d0:701:1000::9b"
        }
    },
    {
        'domain': 'irc.darkmyst.org',
        'afs': [IP4, IP6],

        # 26 nov 2002
        'creation': 1038229200,
        'nick_serv': ["password", "email"],

        "ip": {
            IP4: "23.239.26.75",
            IP6: "2604:a880:cad:d0::1d:e001"
        }
    },
]

IRC_VERSION = "Friendly P2PD user - see p2pd.net/irc"

IRC_CONF = dict_child({
    "use_ssl": 1,
    "ssl_handshake": 8,
    "con_timeout": 4,
}, NET_CONF)

# SHA256 digest in ascii truncated to a str limit.
# Used for deterministic passwords with good complexity.
def f_irc_pass(x):
    return to_s(
        b62encode(
            hashlib.sha256(
                to_b(x)
            ).digest()
        )
    )[:30]

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

def irc_extract_sender(sender):
    p = "([^!@]+)(?:!([^@]+))?(?:@([\s\S]+))?"
    parts = re.findall(p, sender)
    if len(parts):
        parts = parts[0]
        return {
            "nick": parts[0],
            "user": parts[1],
            "host": parts[2]
        }
    
    raise Exception("Sender portion invalid.")

class IRCMsg():
    def __init__(self, prefix="", cmd="", param="", suffix=""):
        self.prefix = prefix or ""
        self.cmd = cmd or ""
        self.param = param or ""
        self.suffix = suffix or ""

    def pack(self):
        param = prefix = suffix = ""
        if len(self.prefix):
            prefix = f":{self.prefix} "
        
        if len(self.suffix):
            suffix = f" :{self.suffix}"

        if len(self.param):
            param = self.param

        return to_b(f"{prefix}{self.cmd} {param}{suffix}\r\n")

class IRCChan:
    def __init__(self, chan_name, session):
        self.session = session
        self.chan_name = chan_name
        self.chan_pass = f_irc_pass(
            session.irc_server + 
            IRC_PREFIX +
            chan_name + 
            session.seed
        )

        self.set_topic_done = asyncio.Future()
        self.pending_topic = ""
        
    async def get_ops(self):
        session = self.session
        session.chan_ident[self.chan_name] = asyncio.Future()

        # Join channel.
        await session.con.send(
            IRCMsg(
                cmd="JOIN",
                param=f"{self.chan_name}",
            ).pack()
        )

        await session.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="ChanServ",
                suffix=f"OP {self.chan_name}"
            ).pack()
        )

        return await session.chan_ident[self.chan_name]
        
    async def set_topic(self, topic):
        self.pending_topic = topic
        session = self.session

        # Join channel.
        await session.con.send(
            IRCMsg(
                cmd="JOIN",
                param=f"{self.chan_name}",
            ).pack()
        )

        if 'set_topic' in session.server_info:
            if session.server_info['set_topic'] == 'set':
                await session.con.send(
                    IRCMsg(
                        cmd="PRIVMSG",
                        param="ChanServ",
                        suffix=f"SET {self.chan_name} TOPIC {topic}"
                    ).pack()
                )
        else:
            await session.con.send(
                IRCMsg(
                    cmd="PRIVMSG",
                    param="ChanServ",
                    suffix=f"TOPIC {self.chan_name} {topic}"
                ).pack()
            )

        await self.set_topic_done
        self.set_topic_done = asyncio.Future()
        return self

class IRCSession():
    def __init__(self, server_info, seed):
        self.con = None
        self.recv_buf = ""
        self.get_motd = asyncio.Future()
        self.login_status = asyncio.Future()
        self.chans_loaded = asyncio.Future()
        self.chan_topics = {}
        self.chan_ident = {}
        self.chan_set_topic = {}
        self.chan_get_topic = {}
        self.chan_registered = {}
        self.chan_infos = {}
        self.server_info = server_info
        self.seed = seed

        # All IRC channels registered to this username.
        self.chans = {}

        # Derive details for IRC server.
        self.irc_server = self.server_info["domain"]
        self.username = "u" + sha256(self.irc_server + IRC_PREFIX + "user" + seed)[:7]
        self.user_pass = f_irc_pass(self.irc_server + IRC_PREFIX + "pass" + seed)
        self.nick = "n" + sha256(self.irc_server + IRC_PREFIX + "nick" + seed)[:7]
        self.email = "p2pd_" + sha256(self.irc_server + IRC_PREFIX + "email" + seed)[:12]
        self.email += "@p2pd.net"

    async def start(self, i):
        # Choose a supported AF.
        af = i.supported()[0]

        # Destination of IRC server to connect to.
        # For simplicity all IRC servers support v4 and v6.
        dest = await Address(
            self.server_info["ip"][af],
            6697,
            i.route(af)
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
        print("get motd done")

        # Trigger register if needed.
        await self.register_user()
        print("register user done")

        # Wait for login success.
        # Some servers scan for open proxies for a while.
        await asyncio.wait_for(
            self.login_status, 15
        )
        print("get login status done.")

        await self.con.send(
            IRCMsg(
                cmd="HELP",
            ).pack()
        )

        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="ChanServ",
                suffix=f"set"
            ).pack()
        )

        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="ChanServ",
                suffix=f"help set"
            ).pack()
        )

        # Load pre-existing owned channels.
        #await self.load_owned_chans()

        return self
    
    async def close(self):
        await self.con.send(IRCMsg(cmd="QUIT").pack())
        await self.con.close()

    async def get_chan_reg_syntax(self):
        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="ChanServ",
                suffix=f"REGISTER"
            ).pack()
        )

    async def get_chan_topic(self, chan_name):
        # Return cached result.
        if chan_name in self.chan_topics:
            return await self.chan_topics[chan_name]
        
        # Setup topic future.
        self.chan_topics[chan_name] = asyncio.Future()

        # First join the channel.
        await self.con.send(
            IRCMsg(
                cmd="JOIN",
                param=f"{chan_name}",
            ).pack()
        )

        # Request the channels topic.
        await self.con.send(
            IRCMsg(
                cmd="TOPIC",
                param=f"{chan_name}",
            ).pack()
        )

        # Wait for channel topic.
        return await self.chan_topics[chan_name]
    
    async def register_user(self):
        # Build register command.
        suffix = f"REGISTER"
        for param in self.server_info["nick_serv"]:
            if param == "password":
                suffix += f" {self.user_pass}"
            if param == "email":
                suffix += f" {self.email}"

        # Attempt to register the nick at the server.
        # See if the server requires confirmation.
        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="NickServ",
                suffix=suffix
            ).pack()
        )
        return self

    async def is_chan_registered(self, chan_name):
        self.chan_infos[chan_name] = asyncio.Future()
        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="ChanServ",
                suffix=f"INFO {chan_name}"
            ).pack()
        )

        return await self.chan_infos[chan_name]
        
    async def register_channel(self, chan_name, chan_desc="desc"):
        if chan_name in self.chan_registered:
            return True
    
        # Used to indicate success.
        self.chan_registered[chan_name] = asyncio.Future()
        irc_chan = IRCChan(chan_name, self)

        # Join channel.
        await self.con.send(
            IRCMsg(
                cmd="JOIN",
                param=f"{chan_name}",
            ).pack()
        )

        # Build register command syntax.
        suffix = f"REGISTER {chan_name}"
        if "chan_serv" in self.server_info:
            for param in self.server_info["chan_serv"]:
                if param == "password":
                    suffix += f" {irc_chan.chan_pass}"
                if param == "description":
                    suffix += f" {chan_desc}"

        # register channel.
        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="ChanServ",
                suffix=suffix
            ).pack()
        )

        # Attempt to enable topic retention.
        # So the channel topic remains after the last user leaves.
        self.chans[chan_name] = irc_chan
        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="ChanServ",
                suffix=f"SET {chan_name} KEEPTOPIC ON"
            ).pack()
        )

        """
        Todo: The servers do tell you what nodes they support in
        the join message so you could subtract what modes they
        will error on and send it all as one message. But that's
        a lot of work for such an optimization.
        """
        # Mute conversation in the channel.
        await asyncio.sleep(0.1)
        await self.con.send(
            IRCMsg(
                cmd="MODE",
                param=f"{chan_name} +m",
            ).pack()
        )

        # -k remove password
        # -i no invite only
        for mode in "ki":
            # Avoid flooding the server.
            await asyncio.sleep(0.1)

            # IRC applies modes all or nothing.
            # Try to get the 'most open' channel.
            await self.con.send(
                IRCMsg(
                    cmd="MODE",
                    param=f"{chan_name} -{mode}",
                ).pack()
            )

        return True
    
    async def load_owned_chans(self):
        await self.con.send(
            IRCMsg(
                cmd="WHOIS",
                param=f"{self.nick}",
            ).pack()
        )

        return await self.chans_loaded

        return
        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="ChanServ",
                suffix=f"LIST {self.nick}!{self.username}@*"
            ).pack()
        )

    async def msg_cb(self, msg, client_tup, pipe):
        print(msg)

        pos_login_msgs = [
            "now logged in as",
            "now identified for",
            "with the password",
            "you are now recognized",
            "Nickname [^\s]* registered"
        ]

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

        nick_pos = [
            "remember this for later",
            "nickname is registered",
            "ickname \S* is already",
            #"is reserved by a different account"
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
                for chan_fail in neg_chan_msgs:
                    if chan_fail in msg.suffix:
                        skip_register = True
                        break

            # Loop over the IRC protocol messages.
            # Process the minimal functions we understand.
            for msg in msgs:
                print(f"Got {msg.pack()}")

                # Respond to CTCP version requests.
                if msg.suffix == "\x01VERSION\x01":
                    sender = irc_extract_sender(msg.prefix)
                    await self.con.send(
                        IRCMsg(
                            cmd="PRIVMSG",
                            param=sender["nick"],
                            suffix=f"\x01VERSION {IRC_VERSION}\x01"
                        ).pack()
                    )

                # Nickname already reserved so login.
                if msg.cmd == "433":
                    await self.con.send(
                        IRCMsg(
                            cmd="PRIVMSG",
                            param="NickServ",
                            suffix=f"IDENTIFY {self.user_pass}"
                        ).pack()
                    )

                # End of motd.
                if msg.cmd in ["376", "411"]:
                    self.get_motd.set_result(True)

                # Login success.
                if msg.cmd == "900":
                    self.login_status.set_result(True)

                # Got a channels topic.
                if msg.cmd == "332":
                    _, chan_part = msg.param.split()
                    if chan_part in self.chan_topics:
                        self.chan_topics[chan_part].set_result(msg.suffix)

                # Process ping.
                if msg.cmd == "PING":
                    pong = IRCMsg(
                        cmd="PONG",
                        param=msg.param,
                        suffix=msg.suffix,
                    )

                    await self.con.send(pong.pack())

                # Handle outstanding channel operations.
                for chan in d_keys(self.chans):
                    # Process chan oper success.
                    if msg.cmd == "MODE":
                        op_success = f"{chan} +o {self.nick}".lower()
                        if op_success in msg.param.lower():
                            if chan in self.chan_ident:
                                self.chan_ident[chan].set_result(True)

                    # Indicate topic set successfully.
                    if msg.cmd == "TOPIC":
                        if chan in msg.param:
                            self.chans[chan].set_topic_done.set_result(msg.suffix or True)

                # Channels loaded.
                if "End of /WHOIS list" in msg.suffix:
                    self.chans_loaded.set_result(True)

                # Load channel info.
                if msg.cmd == "319":
                    chans = msg.suffix.replace("@", "")
                    chans = chans.split()
                    for chan in chans:
                        irc_chan = IRCChan(chan, self)
                        self.chans[chan] = irc_chan

                # Login ident success or account register.
                for success_msg in pos_login_msgs:
                    if len(re.findall(success_msg, msg.suffix)):
                        print("login success")
                        self.login_status.set_result(True)
                

                # Login if account already exists.
                for nick_success in nick_pos:
                    if len(re.findall(nick_success, msg.suffix)):
                        print("sending identify. 2")
                        await self.con.send(
                            IRCMsg(
                                cmd="PRIVMSG",
                                param="NickServ",
                                suffix=f"IDENTIFY {self.user_pass}"
                            ).pack()
                        )

                # Response for a channel INFO request.
                for chan_name in d_keys(self.chan_infos):
                    # Channel is not registered.
                    p = "annel \S*" + re.escape(chan_name) + "\S* ((isn)|(is not))"
                    if len(re.findall(p, msg.suffix)):
                        self.chan_infos[chan_name].set_result(False)

                    # Channel is registered.
                    p = "mation ((for)|(on)) [^#]*" + re.escape(chan_name)
                    if len(re.findall(p, msg.suffix)):
                        self.chan_infos[chan_name].set_result(True)
                    p = "annel \S*" + re.escape(chan_name) + "\S* is reg"
                    if len(re.findall(p, msg.suffix)):
                        self.chan_infos[chan_name].set_result(True)

                    """
                    # Channel registered.
                    for chan_name in self.chan_registered:
                        if chan_name not in self.suffix:
                            continue

                        for chan_success in pos_chan_msgs:
                            if chan_success not in msg.suffix:
                                continue

                            self.chan_registered[chan_name].set_result(True)
                    """
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

        chan_topic = "this_is_test_chan_topic"
        chan_name = "#test_chan_name323" + IRC_PREFIX
        server_list = IRC_SERVERS

        seed = "test_seed"
        i = await Interface().start()



        print("If start")
        print(i)

        for offset, s in enumerate(server_list[1:]):
            print(f"testing {s} : {offset}")

            irc_dns = IRCSession(s, seed)

            try:
                await irc_dns.start(i)
                print("start success")
            except:
                print(f"start failed for {s}")
                what_exception()

            #await irc_dns.get_chan_reg_syntax()
            #await asyncio.sleep(10)
            #exit()

            # Test chan create.
            print("trying to check if chan is registered.")
            ret = await irc_dns.is_chan_registered(chan_name)
            if ret:
                print(f"{chan_name} registered, not registering")

                # 'load' chan instead.
                irc_chan = IRCChan(chan_name, irc_dns)
                irc_dns.chans[chan_name] = irc_chan
                print(irc_chan.chan_pass) # S:1f(.9i{e@3$Fkxq^f{JW,>sVQi?Q\
            else:
                print(f"{chan_name} not registered, attempting to...")
                await irc_dns.register_channel(chan_name)
                ret = await irc_dns.is_chan_registered(chan_name)
                if ret:
                    print("success")
                else:
                    print("failure")
                    exit()

            # Test set topic.
            chan_topic = to_s(rand_plain(8))
            #await irc_dns.chans[chan_name].get_ops()
            #print("get ops done")
            await irc_dns.chans[chan_name].set_topic(chan_topic)
            print("set topic done")

            # Potential race condition between getting new chan.
            await asyncio.sleep(4)

            outside_user = IRCSession(s, seed + "2")
            try:
                await outside_user.start(i)
                print("start success")
            except:
                print(f"start failed for outside user")
                what_exception()

            out = await outside_user.get_chan_topic(chan_name)
            if out != chan_topic:
                print(f"got {out} for chan topic and not {chan_topic}")
                exit()
            else:
                print("success")

            

            # Cleanup.
            await outside_user.close()
            await irc_dns.close()
            input("Press enter to test next server.")
            input()
            


        return


        """
        await irc_dns.con.send(
            IRCMsg(
                cmd="LIST",
                param="*"
            ).pack()

        )

        while 1:
            await asyncio.sleep(1)
        """


        #print(await irc_dns.register_channel("#test_chan_name123"))
        #await asyncio.sleep(2)
        #print(await irc_dns.register_channel("#test_chan_name222"))

        chan_name = "#test_chan_name123"
        irc_chan = IRCChan(chan_name, irc_dns)
        irc_dns.chans[chan_name] = irc_chan

        print(irc_dns.chans)
        await irc_dns.chans[chan_name].get_ops()
        print("got ops")

        o = await irc_dns.chans[chan_name].set_topic("test topic to set.")
        print(o)
        print("topic set")

        chan_topic = await irc_dns.get_chan_topic(chan_name)
        print("got chan topic = ")
        print(chan_topic)

        await irc_dns.close()
        return

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