import asyncio
import unittest
import platform
import socket
import hashlib
from unittest import main
from os import environ
import sys

from .errors import *
from .settings import *
from .utils import *
from .cmd_tools import *
from .net import *
from .address import *
from .interface import *

# Loads interface info on Windows.
# Make it available for all tests.
from .pipe_utils import *
from .stun_client import *


P2PD_NET_ADDR_BYTES = b'0,3-[0,149.56.128.148,149.56.128.148,10001,1,1,0]-[0,2607:5300:0201:3100:0000:0000:0000:8d2f,fe80:0000:0000:0000:f816:3eff:feae:b2d9,10001,1,1,0]-p2pd_test_node'

# Only load the test interface on the right machine.
# Otherwise the name (probably) won't exist.
P2PD_IFS = []

class PatchedAsyncTest(unittest.IsolatedAsyncioTestCase):
    def _setupAsyncioLoop(self):
        assert self._asyncioTestLoop is None
        loop = asyncio.new_event_loop()

        asyncio.set_event_loop(loop)
        loop.set_debug(False)
        self._asyncioTestLoop = loop
        fut = loop.create_future()
        self._asyncioCallsTask = loop.create_task(self._asyncioLoopRunner(fut))
        loop.run_until_complete(safe_run(fut))

# Basic echo client test.
async def check_pipe(pipe, dest_tup=None):
    # Sanity check.
    data = b"Meow"
    if pipe is None:
        log("> Check pipe: pipe is none")
        return False

    # Indicate any message is acceptable to queue.
    pipe.subscribe(sub=SUB_ALL)

    # Request peer to echo back the data sent.
    if dest_tup is None:
        if hasattr(pipe, "get_first_peer_tup"):
            dest_tup = pipe.get_first_peer_tup()
        else:
            dest_tup = pipe.sock.getpeername()

    # Give any pipes time to add callback handlers.
    # This prevents race conditions in processing messages.
    await asyncio.sleep(4)
    await pipe.echo(data, dest_tup)

    # Wait for message with timeout.
    buf = await pipe.recv(timeout=3)
    if buf is None:
        log("Check pipe: recv buf is none")
        return False

    # May not have echo process hooked up.
    if data in buf:
        return True
    else:
        log(f"Check pipe: invalid recv buf {buf}")
        return False

# If a random node ID is generated and subbed to over and over.
# The server may limit new subs from the same IP.
# But if all test nodes use the same IDs the there will be collisons.
# Hence generate a unique IQ deterministically.
def node_name(x, i):
    assert(i.resolved)
    name_base = to_b(f"{i.mac} {socket.gethostname()}")
    node_name = hashlib.sha256(x + name_base).hexdigest()
    return to_b(node_name)[:10]

class FakeSTUNClient():
    def __init__(self, dest=None, proto=UDP, mode=RFC3489, conf=NET_CONF):
        self.rip = "1.3.3.7"
        self.sock = None
        self.mappings = [] # [local, mapped] ...
        self.p = 0
        self.wan_ip = None
        self.interface = None

    def rand_server(self):
        return None

    def set_mappings(self, mappings):
        self.mappings = mappings
        self.p = 0

    def set_wan_ip(self, wan_ip):
        self.wan_ip = wan_ip

    async def get_wan_ip(self, pipe=None):
        return ip_norm(self.wan_ip)

    async def get_mapping(self, pipe=None):
        run_time = time.time()
        local, mapped = self.mappings[self.p]
        out = [local, mapped, self.sock]
        self.p = (self.p + 1) % len(self.mappings)

        return out
    
async def duel_if_setup(netifaces):
    # Load interface list
    if_names = await list_interfaces(netifaces)
    ifs = await load_interfaces(if_names)

    for af in VALID_AFS:
        found = []
        for nic in ifs:
            if af in nic.supported():
                found.append(nic)

        if len(found) >= 2:
            return found[:2], af

class FakeNetifaces():
    def __init__(self):
        self.addr_info = None

    def set_addr_info(self, addr_info):
        self.addr_info = addr_info

    def ifaddresses(self, if_name):
        return self.addr_info