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
an ensure_future that sets related objects when done.
It also doesn't support the Interface object or
Address hence it defaults to the default route.

https://datatracker.ietf.org/doc/html/rfc5905#section-6
"""

import random
from decimal import Decimal as Dec
from .address import *
from .ntp_client import NTPClient
from .settings import *

NTP_RETRY = 2
NTP_TIMEOUT = 2

async def get_ntp(interface, server=None, retry=NTP_RETRY):
    server = server or random.choice(NTP_SERVERS)[0]
    try:
        for _ in range(retry):
            client = NTPClient(interface)
            response = await client.request(server, version=3)
            if response is None:
                continue

            ntp = response.tx_time
            return ntp
    except Exception as e:
        log_exception()
        return None

class SysClock:
    def __init__(self, interface, clock_skew=Dec(0)):
        self.interface = interface
        self.enough_data = 40
        self.min_data = 10
        self.max_sdev = 60
        self.clean_steps = 3
        self.data_points = []
        self.clock_skew = clock_skew
        if self.clock_skew != Dec(0):
            self.clock_skew = Dec(clock_skew)

    async def start(self):
        if not self.clock_skew:
            # Test whether this host has an NTPD.
            """
            'NTP can usually maintain time to within tens of milliseconds over the public Internet, and can achieve better than one millisecond accuracy in local area networks under ideal conditions.'
            Plenty accurate for hole punching.
            """
            # NTPD listens on all interfaces so
            # the LAN IP doesn't matter.
            server = None
            local_ip = "localhost"
            ntp_ret = await async_wrap_errors(
                get_ntp(
                    self.interface,
                    local_ip
                ),
                timeout=NTP_RETRY * NTP_TIMEOUT
            )

            if ntp_ret is not None:
                log("> clockskew using local ntp daemon")
                server = local_ip

            # Calculate clock skew.
            for i in range(0, 3):
                if self.clock_skew == Dec(0):
                    await self.collect_data_points(server=server)
                    if not len(self.data_points):
                        continue

                    self.clock_skew = self.calculate_clock_skew()
                else:
                    break

            # Raise exception.
            if self.clock_skew == Dec(0):
                raise Exception("Could not get clock skew.")
    
        return self

    def __await__(self):
        return self.start().__await__()

    def __str__(self):
        return '{0:f}'.format(self.clock_skew)

    def __repr__(self):
        return f'Dec("{str(self)}")'

    def time(self):
        return Dec(timestamp(1)) - self.clock_skew

    async def collect_data_points(self, server=None):
        async def get_clock_skew():
            ntp_ret = await async_wrap_errors(
                get_ntp(self.interface, server=server),
                timeout=NTP_RETRY * NTP_TIMEOUT
            )

            if ntp_ret is None:
                return None

            return Dec(timestamp(1)) - Dec(ntp_ret)

        tasks = []
        for _ in range(0, self.enough_data + 10):
            tasks.append(
                get_clock_skew()
            )

        results = await asyncio.gather(*tasks)
        results = strip_none(results)
        self.data_points += results

    def statx_n(self, data_points):
        return len(data_points)

    def statx_avg(self, data_points):
        total = Dec("0")
        n = self.statx_n(data_points)
        for i in range(0, n):
            total += data_points[i]

        return total / Dec(n)

    def statx_sdev(self, data_points):
        def _ss(data):
            # Return sum of square deviations
            # of sequence data.
            c = self.statx_avg(data)
            return sum( (x - c ) ** 2 for x in data )

        def pstdev(data):
            # Calculates the population standard deviation.
            n = len(data)
            if n < 2:
                raise ValueError('variance requires at least two data points')

            ss = _ss(data)
            pvar = ss / n  # the population variance

            return pvar ** Dec("0.5")

        return pstdev(data_points)

    def calculate_clock_skew(self):
        """
        Computer average and standard deviation
        using all the data points.
        """
        n = self.statx_n(self.data_points)

        """
        Required to be able to compute the standard
        deviation.
        """
        if n < 1:
            log("n < 1 in cal clock skew")
            return Dec("0")

        avg = self.statx_avg(self.data_points)
        sdev = self.statx_sdev(self.data_points)

        """
        Incrementally remove aberration points.
        """
        for k in range(0, self.clean_steps):
            """
            Remove aberration points: keep only
            the sigma range around the average.
            """
            min_val = avg - sdev
            max_val = avg + sdev

            cleaned_data_points = []
            for i in range(0, n):
                v = self.data_points[i]
                if v < min_val or v > max_val:
                    continue

                cleaned_data_points.append(v)

            self.data_points = cleaned_data_points[:]

            """
            Recompute the new average using the
            "sound" points we kept.
            """
            n = self.statx_n(self.data_points)

            """
            Not enough data to compute standard
            deviation.
            """
            if n < 2:
                break

            avg = self.statx_avg(self.data_points)
            sdev = self.statx_sdev(self.data_points)
            if sdev <= self.max_sdev or n < self.min_data:
                break

        """
        If standard deviation is too large still, we
        cannot update our clock. Collect more points.

        If we don't have a minimum amount of data,
        don't attempt the update yet, continue collecting.
        """
        if sdev > self.max_sdev or n < self.min_data:
            return Dec("0")

        return avg

    def to_dict(self):
        return {
            "if": self.interface.to_dict(),
            "clock_skew": self.clock_skew
        }

    @staticmethod
    def from_dict(d):
        from p2pd.interface import Interface
        i = Interface.from_dict(d["if"])
        x = SysClock(interface=i, clock_skew=d["clock_skew"])
        return x

    # Pickle.
    def __getstate__(self):
        return self.to_dict()

    # Unpickle.
    def __setstate__(self, state):
        o = self.from_dict(state)
        self.__dict__ = o.__dict__

async def test_clock_skew(): # pragma: no cover
    from p2pd.interface import init_p2pd, Interface
    await init_p2pd()
    interface = await Interface().start_local()
    s = await SysClock(interface=interface)
    print(repr(s))


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
