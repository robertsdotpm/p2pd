"""
Given an NTP accurate time, this module computes an
approximation of how far off the system clock is
from the NTP time (clock skew.) The algorithm was
taken from gtk-gnutella.

https://github.com/gtk-gnutella/gtk-gnutella/
blob/devel/src/core/clock.c 

Original Python version by... myself! Now with async.

This code asks for many NTP readings which are slow.
It will probably be necessary to initalize this in
an create_task that sets related objects when done.
It also doesn't support the Interface object or
Address hence it defaults to the default route.

https://datatracker.ietf.org/doc/html/rfc5905#section-6
"""

import time
import random
from decimal import Decimal as Dec
from ..net.address import *
from ..vendor.ntp_client import NTPClient
from ..settings import *
from ..nic.interface import *

NTP_RETRY = 2
NTP_TIMEOUT = 2

async def get_ntp(af, interface, server=None, retry=NTP_RETRY):
    # Get a random NTP server that supports this AF.
    server = server
    if server is None:
        for _ in range(0, 20):
            random_server = random.choice(NTP_SERVERS)
            if random_server[af]:
                server = random_server
                break

    # Sanity check to see server was set.
    if server is None:
        raise Exception("Can't find compatible NTP server.")

    # Resolve af if its not set.
    if not server[af]:
        server[af] = await Address(server["host"], 123).select_ip(af).ip

    # The NTP client uses UDP so retry on failure.
    dest = (server[af], int(server["port"]),)
    try:
        for _ in range(retry):
            client = NTPClient(af, interface)
            response = await client.request(
                dest,
                version=3
            )
            if response is None:
                continue

            ntp = response.tx_time
            return ntp
    except Exception as e:
        log_exception()
        return None
    
async def get_ntp_from_dest(af, nic, dest, retry=NTP_RETRY):
    # The NTP client uses UDP so retry on failure.
    try:
        for _ in range(retry):
            client = NTPClient(af, nic)
            response = await client.request(
                dest,
                version=3
            )
            if response is None:
                continue

            ntp = response.tx_time
            return ntp
    except Exception as e:
        log_exception()
        return None

class SysClock:
    def __init__(self, interface, ntp=0):
        self.start_time = time.monotonic()
        self.interface = interface
        self.ntp = ntp

    async def start(self):
        if self.ntp:
            return
        
        for i in range(0, 5):
            for af in self.interface.supported():
                try:
                    serv = random.choice(NTP_SERVERS)
                    addr = await Address(serv["host"], 123, self.interface).res()
                    tup = addr.select_ip(af)
                    ntp = await get_ntp_from_dest(
                        af=af,
                        nic=self.interface,
                        dest=tup
                    )

                    if ntp:
                        self.ntp = ntp
                        return self
                except Exception:
                    continue

        return self

    def __await__(self):
        return self.start().__await__()

    def time(self):
        if not self.ntp:
            raise Exception("clock skew not loaded")
        
        elapsed = time.monotonic() - self.start_time
        return self.ntp + elapsed

async def test_clock_skew(): # pragma: no cover
    from p2pd.nic.interface import Interface
    interface = await Interface()


    print("loaded")
    s = await SysClock(interface=interface)
    print(s.time())
    time.sleep(1)
    print(s.time())


    return
    f = []
    for i in range(len(NTP_SERVERS)):
        out = await get_ntp(interface, server=NTP_SERVERS[i][0])
        if out is None:
            f.append(i)

    print(f)
        
if __name__ == "__main__":
    #sys_clock = SysClock()
    #print(sys_clock.clock_skew)
    async_test(test_clock_skew)


    # print(get_ntp())
    # print(get_ntp())

    """
    print(sys_clock.time())
    print()
    print(get_ntp())
    print(sys_clock.time())
    print()
    print(get_ntp())
    print(sys_clock.time())
    """
