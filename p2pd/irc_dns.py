"""
- Firewalls for IRC servers silently drop packets if you
make successive connections too closely.
- When registration of channel names is done a user must first join
the channel. The problem is: the moment someone joins a channel the name
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

    high priority:

    - also use the otp to encrypt the sig otherwise attackers can determine which names are grouped via pub key recovery

    maybe how a way to export state in json to see what chans exist, need to be made, and so on

    - dns database by prefix and seed so multiple managers dont conflict

    - changes to the data structure for chan_list (use a dict)

    - store overall dns structure in a general key []

    - database is currently easy to corrupt if it isnt closed. it might make more sense to try see if i can use SQLLite.

    - register name should return overall status indicating
full success, full failure, partial success]

    --------

    final tasks:

    - saboteurs to throw errors in some of the funcs and try to crash the
code. make it more resilient if one server doesnt worke

    - loader would make refresher run each boot
        - install_loader(refresher)

    - still need to test regular dnsmanager usage. as all current code has used mocks
        
    - write more comments for what you've written hastily

----------------------------

    background questions about:

    - servers that are online but disable reg?
        - could parse the special flags at the start of the IRC server header and dynamically disable servers without the right flags

    - if account gets deleted for inactivity?
        - refresh to prevent that
        - channel successor
        - 

    - see if you can find any more servers to add to the list.

    - if someone sends you private messages what can they do via the protocol?

    - shelve probably isnt async safe
        - https://github.com/sabrysm/aiosqlitedict

    pip install git+https://github.com/bobuk/ubase.git


--------------------------------------
"""

import asyncio
import os
import re
import random
import time
import struct
import argon2pure
import binascii
import shelve
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from .utils import *
from .address import *
from .interface import *
from .base_stream import *
from .base_n import encodebytes, decodebytes
from .base_n import B36_CHARSET, B64_CHARSET, B92_CHARSET
from .install import *
from .sqlite_kvs import *

IRC_PREFIX = "20"

IRC_VERSION = "Friendly P2PD user - see p2pd.net/irc"

IRC_CHAN_REFRESH = "Refreshing chan as we're still using this! See p2pd.net/irc for more information."

IRC_NICK_REFRESH = "Refreshing nick as we're still using this!"

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
        'chan_topics': 'a-zA-Z0-9all specials unicode (smilies tested)',
        'nick_expiry': 21,
        'chan_expiry': 14,
        'test_chan': '#test',
        "successor": "p2pd_matthew",
        'unregistered_join': True,
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
        'chan_topics': 'a-zA-Z0-9all specials unicode (smilies)',
        'nick_expiry': 210,
        'chan_expiry': 21,
        'test_chan': '#test',
        "successor": "p2pd_matthew",
        'unregistered_join': True,
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
        'chan_topics': 'a-zA-Z0-9all specials unicode (smilies)',
        'nick_expiry': 90,
        'chan_expiry': 14,
        'test_chan': '#mSL.test',
        "successor": "p2pd_matthew",
        'unregistered_join': True,
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
        'chan_topics': 'a-zA-Z0-9all specials unicode (smilies)',
        'nick_expiry': 120,
        'chan_expiry': 60,
        'test_chan': '#test',
        'unregistered_join': True,
        "successor": "p2pd_matthew"
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
        'chan_topics': 'a-zA-Z0-9all specials unicode (smilies)',
        'nick_expiry': 30,
        'chan_expiry': 60,
        'test_chan': '#test',
        'unregistered_join': True,
        "successor": "p2pd_matthew"
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

IRC_REGISTER_SUCCESS = 0
IRC_START_FAILURE = 1
IRC_REGISTER_FAILURE = 2

IRC_CONF = dict_child({
    "use_ssl": 1,
    "ssl_handshake": 8,
    "con_timeout": 4,
}, NET_CONF)

IRC_FRESHNESS = 172800

####################################################################################

# SHA3 digest in ascii truncated to a str limit.
# Used for deterministic passwords with good complexity.
def f_irc_pass(x):
    return to_s(
        encodebytes(
            hashlib.sha3_256(
                to_b(x)
            ).digest(),
            charset=B64_CHARSET
        )
    )[:30]

def f_sha3_b36(msg):
    h_b = hashlib.sha3_256(to_b(msg)).digest()
    return to_s(
        encodebytes(
            h_b,
            charset=B36_CHARSET
        )
    )

def f_sha3_to_ecdsa_priv(msg):
    max_hex = "FFFFFFFF00000000FFFFFFFFFFFFFFFF"
    max_hex += "BCE6FAADA7179E84F3B9CAC2FC632551"
    max_int = int(max_hex, 16)

    # Continue until hash hex is <= max_int.
    while 1:
        h_b = hashlib.sha3_256(to_b(msg)).digest()
        h_hex = binascii.hexlify(h_b)
        h_int = int(h_hex, 16)
        if h_int <= max_int:
            return h_b
        else:
            msg = h_b

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
                hashlib.sha3_256(
                    msg + time_lock
                ).digest()
            ),
            charset=B36_CHARSET
        )
    )[:31].lower()

    # Cache.
    return h, time_lock

# Not meant to provide bullet-proof security.
def f_otp(msg, otp):
    # Make otp long enough.
    while len(otp) < len(msg):
        otp += hashlib.sha1(otp).digest()

    # Xor MSG with OTP.
    buf = b""
    for i in range(0, len(msg)):
        buf += bytes([
            msg[i] ^ otp[i]
        ])

    return buf

async def f_pack_topic(value, name, tld, pw, ses, clsChan, executor=None):
    # Bytes used to make ECDSA priv key.
    priv = f_sha3_to_ecdsa_priv(
        to_b(
            f"{name}{tld}{pw}{ses.seed}"
        )
    )

    # ECDSA secret key.
    sk = SigningKey.from_string(
        string=priv,
        hashfunc=hashlib.sha3_256,
        curve=SECP256k1
    )

    # Generate channel name.
    chan_name = await ses.get_irc_chan_name(
        name,
        tld,
        pw,
        executor
    )

    # Load channel manager.
    if chan_name not in ses.chans:
        chan = clsChan(chan_name, ses)
        ses.chans[chan_name] = chan
    else:
        chan = ses.chans[chan_name]

    # Time lock value used for OTP.
    time_lock = ses.chan_time_locks[chan_name]

    # Serialized data portion with timestamp prepend.
    val_buf = struct.pack("Q", int(time.time()))
    val_buf += to_b(value)

    # Weakly encrypted topic value.
    val_buf = f_otp(val_buf, time_lock)

    # Signed val_buf with vk.
    sig_buf = sk.sign(val_buf)

    # Topic message to store (topic-safe encoding.)
    return "%s %s %s" % (
        "p2pd.net/irc",
        to_s(encodebytes(sig_buf, charset=B92_CHARSET)),
        to_s(encodebytes(val_buf, charset=B92_CHARSET)),
    ), chan

def f_unpack_topic(chan_name, topic, session):
    if topic is None:
        return None
    
    parts = topic.split()
    if len(parts) != 3:
        return None

    # Signature part.
    sig_b = decodebytes(parts[1], charset=B92_CHARSET)

    # Message part.
    msg_b = decodebytes(parts[2], charset=B92_CHARSET)

    # Time lock value used for OTP.
    time_lock = session.chan_time_locks[chan_name]

    # List of possible public keys recovered from sig.
    vk_list = VerifyingKey.from_public_key_recovery(
        signature=sig_b,
        data=msg_b,
        curve=SECP256k1,
        hashfunc=hashlib.sha3_256
    )

    vk_ids = []
    for vk in vk_list:
        vk_ids.append(
            vk.to_string("compressed")
        )

    # Anything that validates is the right public key.
    for vk in vk_list:
        try:
            vk.verify(
                sig_b,
                msg_b
            )

            msg_b = f_otp(msg_b, time_lock)
            timestamp = struct.unpack("Q", msg_b[:8])[0]
            return {
                "ids": vk_ids,
                "vk": vk,
                "msg": to_s(msg_b[8:]),
                "otp": f_otp(msg_b, time_lock),
                "sig": sig_b,
                "time": timestamp,
            }
        except:
            log_exception()

def irc_is_valid_chan_name(chan_name):
    p = "^[#&+!][a-zA-Z0-9_-]+$"
    return re.match(p, chan_name) != None

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
            IRC_PREFIX +
            chan_name + 
            session.irc_server + 
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

        await asyncio.wait_for(
            self.set_topic_done,
            10
        )

        self.set_topic_done = asyncio.Future()
        return self
    
def irc_proto(self, msg):
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
            self.active_info_chan = chan_name
            self.chan_infos[chan_name].set_result(False)

        # Channel is registered.
        p = "mation ((for)|(on)) [^#]*" + re.escape(chan_name)
        if len(re.findall(p, msg.suffix)):
            self.active_info_chan = chan_name
        p = "annel \S*" + re.escape(chan_name) + "\S* is reg"
        if len(re.findall(p, msg.suffix)):
            self.active_info_chan = chan_name

    # Set channel owner.
    p = "[fF]ounder *[:] *([^:]+)"
    owner = re.findall(p, msg.suffix)
    if len(owner):
        if self.active_info_chan in self.chan_infos:
            if not self.chan_infos[self.active_info_chan].done():
                self.chan_infos[self.active_info_chan].set_result(
                    owner[0]
                )

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

class IRCSession():
    def __init__(self, server_info, seed, db=None, offset=None):
        assert(len(seed) >= 24)
        self.started = asyncio.Future()
        self.con = None
        self.recv_buf = ""
        self.get_motd = asyncio.Future()
        self.login_status = asyncio.Future()
        self.chans_loaded = asyncio.Future()
        self.chan_owners = {}
        self.chan_topics = {}
        self.chan_ident = {}
        self.chan_set_topic = {}
        self.chan_get_topic = {}
        self.chan_registered = {}
        self.chan_infos = {}; self.active_info_chan = None
        self.chan_name_hashes = {}
        self.chan_time_locks = {}
        self.server_info = server_info
        self.seed = seed
        self.db = db
        self.offset = offset

        # All IRC channels registered to this username.
        self.chans = {}

        # Derive details for IRC server.
        self.irc_server = self.server_info["domain"]
        self.username = "u" + f_sha3_b36(IRC_PREFIX + ":user:" + self.irc_server + seed)[:7]
        self.user_pass = f_irc_pass(IRC_PREFIX + ":pass:" + self.irc_server + seed)
        self.nick = "n" + f_sha3_b36(IRC_PREFIX + ":nick:" + self.irc_server + seed)[:7]
        self.email = "e" + f_sha3_b36(IRC_PREFIX + ":email:" + self.irc_server + seed)[:15]
        self.email += "@p2pd.net"
        self.last_started = f"{self.irc_server}_last_started"

        # Sanity checks.
        assert(len(self.username) <= 8)
        assert(len(self.user_pass) <= 30)
        assert(len(self.nick) <= 8)
        assert(len(self.email) <= 26)

    def db_key(self, sub_key):
        return f"{self.irc_server}/{sub_key}"
    
    def db_load_chan_list(self):
        chan_list = []
        if self.db is not None:
            key_name = self.db_key("chan_list")
            chan_list = self.db.get(key_name, [])

        return chan_list
    
    def db_is_name_registered(self, name, tld, pw=""):
        dns = {
            "name": name,
            "tld": tld,
            "pw": pw
        }

        
        chan_list = self.db_load_chan_list()
        for chan_meta in chan_list:
            if "dns" not in chan_meta:
                continue

            if dns != chan_meta["dns"]:
                continue

            if chan_meta["status"] == IRC_REGISTER_SUCCESS:
                return True

        return False
    
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

            # Set last started time.
            if self.db is not None:
                self.db[self.last_started] = time.time()

            # Trigger register if needed.
            await self.register_user()
            print("register user done")

            # Wait for login success.
            # Some servers scan for open proxies for a while.
            await asyncio.wait_for(
                self.login_status, 15
            )
            print("get login status done.")

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
        msg = to_b(f"{name} {tld} {pw} {self.irc_server}")
        if msg in self.chan_name_hashes:
            return self.chan_name_hashes[msg]
        
        if executor is None:
            h, time_lock = f_chan_pow(msg)
        else:
            loop = asyncio.get_event_loop()
            h, time_lock = await loop.run_in_executor(
                executor,
                f_chan_pow,
                (msg)
            )

        self.chan_name_hashes[msg] = h
        self.chan_time_locks[h] = time_lock
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

        # Save user details if needed.
        if self.db is not None:
            nick_key = self.db_key("nick")
            nick_info = self.db.get(nick_key, None)
            if nick_info is None:
                self.db[nick_key] = {
                    "domain": self.irc_server,
                    "nick": self.nick,
                    "username": self.username,
                    "user_pass": self.user_pass,
                    "email": self.email,
                    "last_refresh": time.time()
                }

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

        return await asyncio.wait_for(
            self.chan_infos[chan_name],
            10
        )
    
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

        # If the users nickname expires their channels will be dropped.
        # Allow such channels to be recovered.
        await asyncio.sleep(0.1)
        successor = self.server_info["successor"]
        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="ChanServ",
                suffix=f"SET {chan_name} SUCCESSOR {successor}"
            ).pack()
        )

        # Attempt to enable topic retention.
        # So the channel topic remains after the last user leaves.
        await asyncio.sleep(0.1)
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
        # +s make channel secret so it doesn't show in list
        # We don't want to spam list with a bunch of non-chat channels.
        for mode in "s":
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

        # Record list of channels that belongs to this session.
        if self.db is not None:
            # Chan list update.
            chans_key = self.db_key("chan_list")
            chan_list = self.db.get(chans_key, [])
            chan_list.append(chan_name)
            self.db[chans_key] = chan_list

            # Chan meta data.
            chan_key = self.db_key(f"chan/{chan_name}")
            self.db[chan_key] = {
                "last_refresh": time.time()
            }

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
                resp = irc_proto(self, msg)
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
        self.db = shelve.open(
            os.path.join(
                os.path.expanduser("~"),
                "irc_dns.db"
            )
        )

    # Don't include servers older than 48 hours.
    def get_server_len(self):
        # No sessions to base exclusion on.
        if not len(self.sessions):
            return len(self.servers)
        
        # Exclude servers that have been offline a long time.
        count = 0
        for n in range(0, len(self.sessions)):
            last_started = self.sessions[n].last_started
            start = time.time()
            duration = start - self.db.get(
                last_started,
                start
            )

            if duration < IRC_FRESHNESS:
                count += 1

        return count

    def get_register_failure_max(self):
        return int(0.4 * self.get_server_len())
    
    def get_register_success_min(self):
        return self.get_server_len() - self.get_register_failure_max()
    
    def get_register_success_max(self):
        return self.get_server_len()
    
    def get_lookup_success_min(self):
        return self.get_register_failure_max() + 1
    
    def count_started_sessions(self):
        # Count existing 
        success_no = 0
        for n in range(0, self.p_sessions_next):
            if self.sessions[n].started.done():
                success_no += 1

        return success_no

    async def close(self):
        self.db.close()
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
                    seed=self.seed,
                    db=self.db,
                    offset=j,
                )

                tasks.append(
                    async_wrap_errors(
                        self.sessions[j].start(self.i)
                    )
                )
                self.p_sessions_next += 1

            # Start them all at once if needed.
            if len(tasks):
                await asyncio.gather(*tasks)

            # Determine sessions that worked.
            success_no = 0
            failure_offsets = []
            for j in range(0, self.p_sessions_next):
                if self.sessions[j].started.done():
                    success_no += 1
                else:
                    failure_offsets.append(j)
            return success_no, failure_offsets
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
        # Ensure the session pointer hasn't overflowed.
        assert(self.p_sessions_next <= len(self.servers))

        # Open the bare minimum number of sessions
        # for a successful consensus result.
        success_no, failure_offsets = await self.start_n(
            len(self.servers) - min(
                self.p_sessions_next,
                len(self.servers)
            )
        )
        if success_no < self.get_register_success_min():
            raise Exception("Insufficient sessions.")
        
        # Pre-cache chan name hashes.
        await self.pre_cache(name, tld, pw)
        
        # Check if name available on servers.
        tasks = []
        for n in range(0, self.p_sessions_next):
            async def is_name_available(n):
                # Simulate name being available if we already own it.
                # This will allow the code to pass and be reused.
                if self.sessions[n].db_is_name_registered(name, tld, pw):
                    return True

                # Convert name to server-specific hash.
                chan_name = await self.sessions[n].get_irc_chan_name(
                    name,
                    tld,
                    pw,
                    self.executor
                )

                # Check if resulting channel is registered.
                ret = await self.sessions[n].is_chan_registered(chan_name)

                """
                Return that a name is available if we already own it.
                This will trick the algorithm into succeeding without
                special modifications and makes it 'smarter.'
                Success on register isn't checked for anyway. It's
                just assumed that it will work if names are available.
                """
                if ret == self.sessions[n].nick:
                    return True
                
                # Channel registered to someone else.
                if ret != False:
                    return False
                else:
                    return True
            
            # Skip sessions that aren't connected.
            if self.sessions[n].started.done():
                tasks.append(is_name_available(n))

        # Run availability checks concurrently.
        results = await asyncio.gather(*tasks)
        
        # Check if there's enough names available.
        available_count = 0
        for is_chan_available in results:
            if is_chan_available:
                available_count += 1
        if available_count < self.get_register_success_min():
            raise Exception("Not enough names available.")
        
        # Register name.
        tasks = []
        for n in range(0, self.p_sessions_next):
            # Helper function to register a name for a session.
            async def do_register(n):
                # Attempt to start session if not started.
                # Useful for the register_factory code.
                if not self.sessions[n].started.done():
                    try:
                        await self.sessions[n].start(self.i)
                    except:
                        return [
                            n,
                            False
                        ]

                # Name already registered so skip.
                if self.sessions[n].db_is_name_registered(name, tld, pw):
                    return [
                        n,
                        self.sessions[n].nick
                    ]

                # Convert name to server-specific hash.
                chan_name = await self.sessions[n].get_irc_chan_name(
                    name,
                    tld,
                    pw,
                    self.executor
                )

                # Register name on that server.
                await self.sessions[n].register_chan(chan_name)
                await asyncio.sleep(0.1)

                # Return owner of channel.
                return [
                    n,
                    await self.sessions[n].is_chan_registered(chan_name)
                ]

            tasks.append(do_register(n))

        # Do registration tasks concurrently.
        results = await asyncio.gather(*tasks)
        await asyncio.sleep(0.1)

        # Get owners for channels to see success.
        records = []
        for n in range(0, self.p_sessions_next):
            # Default to failure.
            reg_status = IRC_REGISTER_FAILURE

            # The server couldn't be connected.
            if n in failure_offsets:
                reg_status = IRC_START_FAILURE

            # Check channel owner after registration.
            # Results need to exist for success to be possible.
            for r in results:
                # If the session offset is this and
                # the session nick matches the channel nick.
                if n == r[0] and r[1] == self.sessions[n].nick:
                    reg_status = IRC_REGISTER_SUCCESS
                    break

            # Get the chan name.
            # Calling this here also ensures time_lock exists.
            chan_name = await self.sessions[n].get_irc_chan_name(
                name,
                tld,
                pw,
                self.executor
            )

            # Get the time-lock field.
            time_lock = self.sessions[n].chan_time_locks[chan_name]

            # Name portion to store in record.
            dns_meta = {
                "name": name,
                "tld": tld,
                "pw": pw
            }

            # CGet list of channels for this server.
            key_name = self.sessions[n].db_key("chan_list")
            chan_list = self.db.get(key_name, [])

            # Get failure count for registration.
            failure_count = 0
            old_record = list_get_dict("chan_name", chan_name, chan_list)
            if old_record is not None:
                if "failure_count" in old_record:
                    failure_count = old_record["failure_count"]
            if reg_status != IRC_REGISTER_SUCCESS:
                failure_count += 1

            # Record to store about name in session.
            record = {
                "domain": self.sessions[n].irc_server,
                "dns": dns_meta,
                "chan_name": chan_name,
                "time_lock": time_lock,
                "status": reg_status,
                "failure_count": failure_count,
                "last_refresh": time.time()
            }

            # Ensure existing copy of this chan is overwritten.
            # Otherwise repeat calls could grow the list forever.
            sub_list = list_exclude_dict("chan_name", chan_name, chan_list)
            sub_list.append(record)

            # Record the changes.
            self.db[key_name] = sub_list
            self.db[f"chan/{chan_name}"] = record
            records.append(record)

        return records
    
    async def store_value(self, value, name, tld, pw=""):
        async def helper(n):
            # Select session to use.
            session = self.sessions[n]
            if not session.started.done():
                return

            topic, chan = await f_pack_topic(
                value,
                name,
                tld,
                pw,
                session,
                self.clsChan,
                self.executor
            )

            # Reference function to set topic.
            await chan.set_topic(topic)

        # Open as many sessions as possible.
        await self.start_n(
            len(self.servers) - self.p_sessions_next
        )

        # Pre-cache name hashes.
        await self.pre_cache(name, tld, pw)

        # Build tasks to set chan topics.
        tasks = []
        for n in range(0, len(self.servers)):
            tasks.append(
                helper(n)
            )

        # Execute tasks to update topics.
        await asyncio.gather(*tasks)

    async def acquire_at_least(self, target):
        # Count existing 
        success_no = self.count_started_sessions()

        # Not enough sessions open to satisfy target.
        # Open needed sessions.
        if success_no < target:
            still_needed = target - success_no

            # Progress through server list until target is met
            # otherwise the end is encountered and an exception is thrown.
            while still_needed:
                success_no, _ = await self.start_n(still_needed)
                still_needed -= success_no

    def n_more_or_best(self, results):
        if not len(results):
            return self.get_lookup_success_min()
        
        table = {}
        for r in results:
            if r is None:
                continue

            for r_id in r["ids"]:
                if r_id not in table:
                    table[r_id] = [r]
                else:
                    table[r_id].append(r)

        highest = []
        for r_id in table:
            if len(highest) < len(table[r_id]):
                highest = table[r_id]

        if len(highest) >= self.get_lookup_success_min():
            freshest = highest[0]
            for result in highest:
                if result["time"] > freshest["time"]:
                    freshest = result

            return freshest
        else:
            return self.get_lookup_success_min() - len(highest)
        
    async def n_name_lookups(self, n, start_p, name, tld, pw=""):
        async def helper(self, session_offset, chan_name):
            session = self.sessions[session_offset]
            topic = await asyncio.wait_for(
                session.get_chan_topic(chan_name),
                10
            )
            
            return f_unpack_topic(
                chan_name,
                topic,
                session
            )

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
            self.get_lookup_success_min()
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
        assert(len(results) >= self.get_lookup_success_min())
        if isinstance(names_required, dict):
            freshest = names_required
            return freshest
        
class IRCRefresher():
    def __init__(self, manager):
        self.manager = manager

    async def placeholder(self):
        return

    async def refresh_chan(self, chan_name, session):
        # Session not started.
        if not session.started.done():
            await session.start(self.manager.i)

        # Join channel.
        await session.con.send(
            IRCMsg(
                cmd="JOIN",
                param=f"{chan_name}",
            ).pack()
        )

        # Send a basic refresh message.
        await session.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param=f"{chan_name}",
                suffix=IRC_CHAN_REFRESH
            ).pack()
        )

    async def refresh_nick(self, session):
        # Session not started.
        if not session.started.done():
            await session.start(self.manager.i)

        # Join testing channel.
        chan_name = f'{session.server_info["test_chan"]}'
        await session.con.send(
            IRCMsg(
                cmd="JOIN",
                param=chan_name,
            ).pack()
        )

        # Send a basic refresh message.
        await session.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param=chan_name,
                suffix=IRC_NICK_REFRESH
            ).pack()
        )

    async def refresher(self):
        tasks = []
        db = self.manager.db

        # Return coroutine that does nothing if no refresh needed.
        # Otherwise returns the coroutine that does the refresh.
        def check_last_refresh(sub_key, expiry_days, expiry_func):
            # Extract meta data.
            key_name = session.db_key(sub_key)
            info = db.get(key_name, None)
            if info is None:
                return self.placeholder()
            if "last_refresh" not in info:
                return self.placeholder()

            # Calculate the expiry time in seconds.
            day_secs = 24 * 60 * 60
            expiry_secs = expiry_days * day_secs

            # Refresh five days before expiry.
            expiry_secs -= 5 * day_secs
            assert(expiry_secs > 0)
            duration = max(time.time() - info["last_refresh"], 0)
            if duration >= expiry_secs:
                # Update refresh timer.
                info["last_refresh"] = time.time()
                db[key_name] = info

                # Factory that returns coroutine to await on.
                return expiry_func()
            
            # So results can be passed to gather.
            return self.placeholder()

        # Loop over sessions for anything that needs refreshing.
        register_list = []
        for n in range(0, self.manager.p_sessions_next):
            # Select valid session.
            session = self.manager.sessions[n]
            
            # Loop over all channels registered to session.
            chan_list = session.db_load_chan_list()
            for chan_info in chan_list:
                # Check the channel info for expiry.
                chan_name = chan_info["chan_name"]
                expiry_days = session.server_info["chan_expiry"]
                tasks.append(
                    check_last_refresh(
                        f"chan/{chan_name}",
                        expiry_days,
                        lambda: self.refresh_chan(chan_name, session)
                    )
                )

                # Sanity checks for the next part.
                # Only attempt to re-register up to 3 times.
                # Don't want to DoS server.
                if "status" not in chan_info:
                    continue 
                if "dns" not in chan_info:
                    continue
                if "failure_count" not in chan_info:
                    chan_info["failure_count"] = 0
                if chan_info["failure_count"] >= 3:
                    continue

                # If the chan info status was start failure
                # try to call register on the name again.
                if chan_info["status"] == IRC_START_FAILURE:
                    # Register handles retry for all servers.
                    if chan_info["dns"] not in register_list:
                        tasks.append(
                            self.manager.name_register(
                                name=chan_info["dns"]["name"],
                                tld=chan_info["dns"]["tld"],
                                pw=chan_info["dns"]["pw"]
                            )
                        )
                        register_list.append(chan_info["dns"])

            # See if nick needs to be refreshed.
            tasks.append(
                check_last_refresh(
                    "nick",
                    session.server_info["nick_expiry"],
                    lambda: self.refresh_nick(session)
                )
            )
            
        # Execute refresh tasks concurrently.
        if len(tasks):
            await asyncio.gather(*tasks)

if __name__ == '__main__':
    pass