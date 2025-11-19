import sys
from ....net.ip_range import *
from ....nic.nat.nat_utils import *
from ....nic.interface import *
from ....nic.nat.nat_predict import *
from ....utility.clock_skew import *
from ....net.keep_alive import set_keep_alive
from .punch_defs import *

"""
We can keep trying until success without the mappings
changing. However, unpredictable nats that use
delta N will be timing sensitive. If timing info
is available the protocol should try use that.
"""
async def delayed_punch(af, ms_delay, mapping, dest, loop, interface, conf=PUNCH_CONF):
    try:
        """
        Schedule connection to run across time.

        How long it takes the event loop to start a
        routine is outside of our control. This
        code adjusts the delay based on any amount
        of time already passed.
        """
        if ms_delay:
            await asyncio.sleep(ms_delay / 1000)

        # Bind to a specific port and interface.
        #print(dest.tup)
        if "fe80" == dest.tup[0][:4]:
            route = interface.route(af)
            await route.bind(
                ips=str(route.link_locals[0]),
                port=mapping.local
            )
        else:
            route = await interface.route(af).bind(
                mapping.local
            )

        # Open connection -- return only sock.
        sock = await socket_factory(
            route=route,
            dest_addr=dest, 
            conf=conf
        )

        # Requires this special sock option:
        reuse_set = sock.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR
        )

        # Sanity check for the sock option.
        if not reuse_set:
            log("Punch socket missing reuse addr opt.")
            if sock: sock.close()
            return

        # Async connect that sends SYN.
        await loop.sock_connect(
            sock,
            dest.tup
        )

        # Failure.
        # We strip None responses out.
        if sock is None:
            return None
        
        # Add pings in the background.
        # This helps the process pool stay clean.
        set_keep_alive(sock)

        """
        At some point I expect errors to be made if a
        local IP + local port is reused for the same
        dest IP + dest port and it successfully gets
        connected. So successive calls might fail.
        """
        mapping.sock = sock
        return mapping
    except Exception:
        #log_exception()
        return None

"""
Smarter code that is less spammy used for remote
punching. Won't overwhelm the event loop like the
above code will. Takes advantage of the massive timeouts
in the Internet as packets travel across routers.
Optimized and tested for remote connections.
"""
async def schedule_delayed_punching(af, dest_addr, send_mappings, recv_mappings, interface):
    try:
        # Config.
        secs = 10
        ms_spacing = 5

        # Create punching async task list.
        tasks = []
        if sys.version_info.minor >= 13:
            # Recent python versions are more efficient with less tasks.
            steps = 50
        else:
            steps = int((secs * 1000) / ms_spacing)


        assert(steps > 1)
        assert(steps)
        assert(len(send_mappings))
        loop = asyncio.get_event_loop()
        for i in range(0, 1):
            # Validate IP address.
            dest = Address(dest_addr, recv_mappings[i].remote)
            interface.route(af)
            await dest.res(interface.route(af))
            dest = dest.select_ip(af)
            for sleep_time in range(0, min(steps, 100)):
                task = async_wrap_errors(
                    delayed_punch(
                        # Address family for the con.
                        af,

                        # Wait until ms to do punching.
                        # Punches are split up over time
                        # to increase chances of success.
                        sleep_time * ms_spacing,

                        # Local mapping.
                        send_mappings[i],

                        # Destination addr to connect to.
                        dest,

                        # Event loop for this process.
                        loop,

                        # Punch from this interface.
                        interface
                    )
                )
                tasks.append(task)
                

        # Start running tasks.
        outs = await asyncio.gather(*tasks)
        outs = strip_none(outs)
        return outs
    except Exception:
        #what_exception()
        log_exception()