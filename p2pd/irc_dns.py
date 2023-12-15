"""
- Firewalls for IRC servers silently drop packets if you
make successive connections too closely.
- When registration of channel names is done a user must first join
the channel. The problem is: the number someone joins a channel the name
of the channel becomes public. That means that an attacker can watch the
channel list for channels and register channel names on others servers
in order to hijack the control of names before registering parties.

The solution I came up to this is multi-faceted:
    (1) Each name is now server-specific. By hashing the server-name as
    part of the name it will be harder to guess what name is being
    registered to register channels at other servers.
    (2) The names contain a small proof-of-work that acts as a delay
    function. The registering party 'saves up' these proofs for all
    servers in bulk and then registers everything in parallel. Naturally,
    this becomes part of the hashed name.

But what about rainbow tables?
    (1) Names may be registered on arbitrary TLDs. Each TLD acts as
    a small salt. Thus, attackers have to guess what TLDs to
    pre-compute which may be completely off. If TLD suggestions are
    randomly generated from dictionary nouns, then rainbow tables
    would be near impossible to create.
    (2) Names may contain an optional password portion. This has the
    downside of requiring the password to access the name but offers
    more protection against squatters.

These measures make race conditions and rainbow tables either
impossible or impractical depending on usage.

---

    try to test register / login -- see if infinite loop is possible
    Maybe allow the chan to expire (set this manually.

    get chan topic in session may not work appropriately
    - update test code to use some funcs from ircdns (chan names and topics)
    - code to refresh topics periodically?
    - set expire flag on topic
    - update IRC message with all measures
    - what about registering names for servers that come back online?
    - rot values in chan topic using H(x) -> chan_name, x as a one-time pad so that you must know the chan details to use the record.

    whats the best way to make this module work as long as possible?
        programmatically adjust max and min success metric somehow
            - each server has fields to indicate when connectivity
            was last made and when its over a certain amount its removed from the server set.


"""

import asyncio
import re
import random
import time
import struct
import argon2pure
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from concurrent.futures import ProcessPoolExecutor
from .utils import *
from .address import *
from .interface import *
from .base_stream import *
from .base_n import encodebytes, decodebytes
from .base_n import B36_CHARSET, B64_CHARSET, B92_CHARSET

IRC_PREFIX = "20"

IRC_VERSION = "Friendly P2PD user - see p2pd.net/irc"

IRC_CONF = dict_child({
    "use_ssl": 1,
    "ssl_handshake": 8,
    "con_timeout": 4,
}, NET_CONF)

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
        },

        'chan_len': 50,
        'chan_no': 60,
        'topic_len': 300,
        'chan_topics': 'a-zA-Z0-9all specials unicode (smilies tested)'
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
        },

        'chan_no': 25,
        'chan_len': 32,
        'topic_len': 307,
        'chan_topics': 'a-zA-Z0-9all specials unicode (smilies)'
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
        },

        'chan_no': 50,
        'chan_len': 32,
        'topic_len': 360,

        # Certain characters like ,. still not allowed.
        'chan_name': 'azAZ!@#$unicode-_',

        'chan_topics': 'a-zA-Z0-9all specials unicode (smilies)'
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
        },

        'chan_no': 30,
        'chan_len': 32,
        'topic_len': 307,
        'chan_topics': 'a-zA-Z0-9all specials unicode (smilies)'
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
        },

        'chan_no': 30,
        'chan_len': 50,
        'topic_len': 390,
        'chan_topics': 'a-zA-Z0-9all specials unicode (smilies)'
    },
]

###################################################################
# These are really IRC-server specific response strings.
IRC_POS_LOGIN_MSGS = [
    "now logged in as",
    "now identified for",
    "with the password",
    "you are now recognized",
    "Nickname [^\s]* registered"
]

IRC_POS_CHAN_MSGS = [
    "registered under",
    "is now registered",
    "successfully registered",
]

IRC_NEG_CHAN_MSGS = [
    "not complete registration",
    "following link",
    "link expires",
    "address is not confirmed"
]

IRC_NICK_POS = [
    "remember this for later",
    "nickname is registered",
    "ickname \S* is already",
    #"is reserved by a different account"
]

# SHA256 digest in ascii truncated to a str limit.
# Used for deterministic passwords with good complexity.
def f_irc_pass(x):
    return to_s(
        encodebytes(
            hashlib.sha256(
                to_b(x)
            ).digest(),
            charset=B64_CHARSET
        )
    )[:30]

def f_chan_pow(msg):
    # Time locks help prevent registration front-running.
    time_lock = argon2pure.argon2(
        # Msg portion.
        msg,

        # Unique salt for rainbow resistance.
        b'Ana main, chicken tikka masala, Blush - Wolf Alice',
        
        # Iterations.
        time_cost=2, # 700
        
        # KB needed.
        memory_cost=1024 * 2,
        
        # Threads needed.
        parallelism=1
    )

    # Channel names begin with a #.
    h = "#" + to_s(
        # The result is encoded using A-Z0-9 for chan names.
        encodebytes(
            # Multiple hash functions make collisions harder to find.
            # As a value will need to work for both functions.
            hash160(
                hashlib.sha256(
                    time_lock + msg
                ).digest()
            ),
            charset=B36_CHARSET
        )
    )[:31].lower()

    # Cache.
    return h

def irc_is_valid_chan_name(chan_name):
    p = "^[#&+!][a-zA-Z0-9_-]+$"
    return re.match(p, chan_name) != None

"""
TCP is stream-oriented and portions of IRC protocol messages
may be received. This code handles finding valid IRC messages and
truncating the recv buffer once extracted.
"""
def irc_extract_msgs(buf):
    #     optional                                       optional
    #     :prefix            CMD           param...      :suffix 
    # Changed so that multiple spaces can sep portions.
    p = "(?:[:]([^ :]+?) +)?([A-Z0-9]+) +(?:([^\r\:]+?) *)?(?:[:]([^\r]+))?\r\n"
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

# Example user!ident@hostname
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
        out = ""
        if len(self.prefix):
            out += f":{self.prefix} "

        out += self.cmd
        if len(self.param):
            out += f" {self.param}"
        
        if len(self.suffix):
            out += f" :{self.suffix}"

        out += "\r\n"
        return to_b(out)
    
    def __str__(self):
        return to_s(self.pack())
    
    def __bytes__(self):
        return self.pack()
    
    def __eq__(self, other):
        return str(self) == str(other)

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
        assert(len(seed) >= 24)
        self.started = asyncio.Future()
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
        self.chan_name_hashes = {}
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

    async def start(self, i, timeout=60):
        async def do_start():
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

            """
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
            """

            # Load pre-existing owned channels.
            #await self.load_owned_chans()

            self.started.set_result(True)
            return self
        
        return await asyncio.wait_for(
            do_start(),
            timeout=timeout
        )
    
    """
    Name -> 20 byte hash160
    (2 ** 160) - 1 yields 
    1461501637330902918203684832716283019655932542975

    IRC chan limit: 31 bytes (1 remaining for #)
    where only a-z0-9 are guaranteed
    that leaves
    ((26 + 10) ** 31) possibilities or
    1759452407304813269615619081855885739163790606335

    so all hash160 values can be stored with this encoding.
    It also allows names to have special characters and be
    longer than 20 bytes (albeit at the cost of collisions.)
    """
    async def get_irc_chan_name(self, name, tld, pw="", executor=None):
        # Domain names are unique per server.
        msg = to_b(f"{self.irc_server} {pw} {name} {tld}")
        if msg in self.chan_name_hashes:
            return self.chan_name_hashes[msg]
        
        if executor is None:
            h = f_chan_pow(msg)
        else:
            loop = asyncio.get_event_loop()
            h = await loop.run_in_executor(
                executor,
                f_chan_pow,
                (msg)
            )

        self.chan_name_hashes[msg] = h
        return h
    
    async def close(self):
        if self.con is not None:
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
        
    async def register_chan(self, chan_name, chan_desc="desc"):
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

        # Maybe allow the chan to expire (set this manually.


        """
        Todo: The servers do tell you what nodes they support in
        the join message so you could subtract what modes they
        will error on and send it all as one message. But that's
        a lot of work for such an optimization.
        """
        # +m mute conversation in the channel.
        # +s make channel secret so it doesn't show in list
        # We don't want to spam list with a bunch of non-chat channels.
        for mode in "ms":
            # Avoid flooding server.
            await asyncio.sleep(0.1)

            # Set the mode.
            await self.con.send(
                IRCMsg(
                    cmd="MODE",
                    param=f"{chan_name} +{mode}",
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

    def proto(self, msg):
        print(f"Got {msg.pack()}")

        # Process ping.
        if msg.cmd == "PING":
            return IRCMsg(
                cmd="PONG",
                param=msg.param,
                suffix=msg.suffix,
            )
        
        # End of motd.
        if msg.cmd in ["376", "411"]:
            self.get_motd.set_result(True)
            return

        # Nickname already reserved so login.
        if msg.cmd == "433":
            return IRCMsg(
                cmd="PRIVMSG",
                param="NickServ",
                suffix=f"IDENTIFY {self.user_pass}"
            )
        
        # Login if account already exists.
        for nick_success in IRC_NICK_POS:
            if len(re.findall(nick_success, msg.suffix)):
                print("sending identify. 2")
                return IRCMsg(
                    cmd="PRIVMSG",
                    param="NickServ",
                    suffix=f"IDENTIFY {self.user_pass}"
                )

        # Login success.
        if msg.cmd == "900":
            self.login_status.set_result(True)
            return

        # Login ident success or account register.
        for success_msg in IRC_POS_LOGIN_MSGS:
            if len(re.findall(success_msg, msg.suffix)):
                print("login success")
                self.login_status.set_result(True)
                return

        # Respond to CTCP version requests.
        if msg.suffix == "\x01VERSION\x01":
            sender = irc_extract_sender(msg.prefix)
            return IRCMsg(
                cmd="PRIVMSG",
                param=sender["nick"],
                suffix=f"\x01VERSION {IRC_VERSION}\x01"
            )

        # Got a channels topic.
        if msg.cmd == "332":
            _, chan_part = msg.param.split()
            if chan_part in self.chan_topics:
                self.chan_topics[chan_part].set_result(msg.suffix)

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
                    self.chans[chan].set_topic_done.set_result(
                        msg.suffix or True
                    )

        # Support checking if a channel is registered.
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

        # Channels loaded.
        if "End of /WHOIS list" in msg.suffix:
            self.chans_loaded.set_result(True)

        # Response from a WHOIS request.
        if msg.cmd == "319":
            return
            chans = msg.suffix.replace("@", "")
            chans = chans.split()
            for chan in chans:
                irc_chan = IRCChan(chan, self)
                self.chans[chan] = irc_chan

    async def msg_cb(self, msg, client_tup, pipe):
        print(msg)

        try:
            # Keep a buffer of potential protocol messages.
            # These may be partial in the case of TCP.
            self.recv_buf += to_s(msg)
            msgs, new_buf = irc_extract_msgs(self.recv_buf)
            self.recv_buf = new_buf

            # Disable chan success in some cases.
            skip_register = False
            for msg in msgs:
                for chan_fail in IRC_NEG_CHAN_MSGS:
                    if chan_fail in msg.suffix:
                        skip_register = True
                        break

            # Loop over the IRC protocol messages.
            # Process the minimal functions we understand.
            for msg in msgs:
                resp = self.proto(msg)
                if resp is not None:
                    await pipe.send(resp.pack())
    
        except Exception:
            log_exception()

class IRCDNS():
    def __init__(self, i, seed, servers, executor=None, clsChan=IRCChan, clsSess=IRCSession, do_shuffle=True):
        self.i = i
        self.seed = seed
        self.sessions = {}
        self.p_sessions_next = 0
        self.clsChan = clsChan
        self.clsSess = clsSess
        self.executor = executor

        if do_shuffle:
            random.shuffle(servers)

        self.servers = servers
        self.start_lock = asyncio.Lock()

    def get_failure_max(self):
        return int(0.4 * len(self.servers))
    
    def get_success_max(self):
        return len(self.servers) - self.get_failure_max()
    
    def get_success_min(self):
        return self.get_failure_max() + 1
    
    def needed_sessions(self):
        dif = self.p_sessions_next - self.get_success_min()
        if dif >= 0:
            return 0
        else:
            return -dif

    async def close(self):
        tasks = []
        for i in range(0, self.p_sessions_next):
            task = self.sessions[i].close()
            tasks.append(task)

        await asyncio.gather(*tasks)

    async def start_n(self, n):
        await self.start_lock.acquire()
        try:
            assert(self.p_sessions_next <= len(self.servers))

            # Are there enough unstarted servers to try?
            tasks = []; p = self.p_sessions_next
            if (p + n) > len(self.servers):
                raise Exception("No IRC servers left to try.")

            # Create sessions from any already started.
            for j in range(p, p + n):
                assert(j not in self.sessions)
                self.sessions[j] = self.clsSess(
                    self.servers[j],
                    self.seed
                )

                tasks.append(self.sessions[j].start())
                self.p_sessions_next += 1

            # Start them all at once if needed.
            if len(tasks):
                await asyncio.gather(*tasks)

            # Determine sessions that worked.
            success_no = 0
            for j in range(0, self.p_sessions_next):
                if self.sessions[j].started.done():
                    success_no += 1
            return success_no
        finally:
            self.start_lock.release()

    async def pre_cache(self, name, tld, pw=""):
        tasks = []
        for n in range(0, self.p_sessions_next):
            task = self.sessions[n].get_irc_chan_name(
                name,
                tld,
                pw,
                self.executor
            )

            tasks.append(task)

        if len(tasks):
            await asyncio.gather(*tasks)
    
    async def name_register(self, name, tld, pw=""):
        assert(self.p_sessions_next <= len(self.servers))

        # Open the bare minimum number of sessions
        # for a successful consensus result.
        success_no = await self.start_n(
            len(self.servers) - min(
                self.p_sessions_next,
                len(self.servers)
            )
        )
        if success_no < self.get_success_max():
            raise Exception("Insufficient sessions.")
        
        # Pre-cache chan name hashes.
        await self.pre_cache(name, tld, pw)
        
        # Check if name available on servers.
        tasks = []
        for n in range(0, self.p_sessions_next):
            chan_name = await self.sessions[n].get_irc_chan_name(
                name,
                tld,
                pw,
                self.executor
            )

            task = self.sessions[n].is_chan_registered(chan_name)
            tasks.append(task)
        results = await asyncio.gather(*tasks)
        
        # Check if there's enough names available.
        available_count = 0
        for is_chan_registered in results:
            if not is_chan_registered:
                available_count += 1
        if available_count < self.get_success_max():
            return False
        
        # Register name.
        tasks = []
        for n in range(0, self.p_sessions_next):
            chan_name = await self.sessions[n].get_irc_chan_name(
                name,
                tld,
                pw,
                self.executor
            )

            task = self.sessions[n].register_chan(chan_name)
            tasks.append(task)
        await asyncio.gather(*tasks)
        return True

    async def store_value(self, value, name, tld, pw=""):
        # Bytes used to make ECDSA priv key.
        priv = hashlib.sha256(
            to_b(
                f"{pw}{name}{tld}{self.seed}"
            )
        ).digest()

        # ECDSA secret key.
        sk = SigningKey.from_string(
            string=priv,
            hashfunc=hashlib.sha256,
            curve=SECP256k1
        )

        # Serialized data portion with timestamp prepend.
        val_buf = struct.pack("Q", int(time.time()))
        val_buf += to_b(value)

        # Signed val_buf with vk.
        sig_buf = sk.sign(val_buf)

        # Topic message to store (topic-safe encoding.)
        topic = "%s %s %s" % (
            "p2pd.net/irc",
            to_s(encodebytes(sig_buf, charset=B92_CHARSET)),
            to_s(encodebytes(val_buf, charset=B92_CHARSET)),
        )

        # Open as many sessions as possible.
        await self.start_n(
            len(self.servers) - self.p_sessions_next
        )

        # Pre-cache name hashes.
        await self.pre_cache(name, tld, pw)

        # Build tasks to set chan topics.
        tasks = []
        for n in range(0, len(self.servers)):
            # Select session to use.
            session = self.sessions[n]
            if not session.started.done():
                continue

            # Generate channel name.
            chan_name = await session.get_irc_chan_name(
                name,
                tld,
                pw,
                self.executor
            )

            # Load channel manager.
            if chan_name not in session.chans:
                chan = self.clsChan(chan_name, session)
                session.chans[chan_name] = chan
            else:
                chan = session.chans[chan_name]

            # Reference function to set topic.
            task = chan.set_topic(topic)
            tasks.append(task)

        # Execute tasks to update topics.
        await asyncio.gather(*tasks)

    def unpack_topic_value(self, value):
        if value is None:
            return None
        
        parts = value.split()
        if len(parts) != 3:
            return None

        # Signature part.
        sig_b = decodebytes(parts[1], charset=B92_CHARSET)

        # Message part.
        msg_b = decodebytes(parts[2], charset=B92_CHARSET)

        # List of possible public keys recovered from sig.
        vk_list = VerifyingKey.from_public_key_recovery(
            signature=sig_b,
            data=msg_b,
            curve=SECP256k1,
            hashfunc=hashlib.sha256
        )

        # Anything that validates is the right public key.
        for vk in vk_list:
            try:
                vk.verify(
                    sig_b,
                    msg_b
                )

                timestamp = struct.unpack("Q", msg_b[:8])[0]
                return {
                    "id": vk.to_string("compressed"),
                    "vk": vk,
                    "msg": msg_b[8:],
                    "sig": sig_b,
                    "time": timestamp,
                }
            except:
                log_exception()

        return None

    async def acquire_at_least(self, target):
        open_sessions = self.p_sessions_next
        if open_sessions < target:
            sessions_required = target - open_sessions
            while sessions_required:
                success_no = await self.start_n(sessions_required)
                sessions_required -= success_no

    def n_more_or_best(self, results):
        if not len(results):
            return self.get_success_min()
        
        table = {}
        for r in results:
            if r["id"] in table:
                table[r["id"]].append(r)
            else:
                table[r["id"]] = [r]

        highest = []
        for r_id in table:
            if len(highest) < len(table[r_id]):
                highest = table[r_id]

        if len(highest) >= self.get_success_min():
            freshest = highest[0]
            for result in highest:
                if result["time"] > freshest["time"]:
                    freshest = result

            return freshest
        else:
            return self.get_success_min() - len(highest)
        
    async def n_name_lookups(self, n, start_p, name, tld, pw=""):
        async def helper(self, x, y):
            chan_topic = await self.sessions[x].get_chan_topic(y)
            return self.unpack_topic_value(chan_topic)

        tasks = []; p = start_p
        while len(tasks) < n:
            if p >= len(self.servers):
                raise Exception("Exceeded irc sessions.")

            if not self.sessions[p].started.done():
                p += 1
                continue

            # Get chan name.
            chan_name = await self.sessions[p].get_irc_chan_name(
                name,
                tld,
                pw,
                self.executor
            )

            # Get name or throw an error.
            tasks.append(
                async_wrap_errors(
                    helper(self, p, chan_name),
                    5
                )
            )

            p += 1

        if len(tasks):
            return await asyncio.gather(*tasks), p
        else:
            return [], p
        
    async def name_lookup(self, name, tld, pw=""):
        # Pre-cache name hashes.
        await self.pre_cache(name, tld, pw)

        # Open the bare minimum number of sessions
        # for a successful consensus result.
        await self.acquire_at_least(
            self.get_success_min()
        )

        # Get minimum number of chan topics.
        results = []; start_p = 0
        names_required = self.n_more_or_best(results)
        while isinstance(names_required, int):
            more, start_p = await self.n_name_lookups(
                names_required,
                start_p,
                name,
                tld,
                pw
            )

            results += more
            names_required = self.n_more_or_best(results)

        # Return freshest result.
        if isinstance(names_required, dict):
            freshest = names_required
            return freshest

if __name__ == '__main__':
    pass