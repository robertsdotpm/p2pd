"""
The UPnP module implements IPv4 port forwarding (for NATs) and for IPv6
it provides the means to add exceptions to the router's firewall (which
it calls adding 'pin holes'.)

When using IPv6: the address to make an exception for must be the one
used to make the requests (this is handled automatically here.)
Therefore the interface used must be able to bind to the address
being added as an exception. IPv6 also requires these exceptions have
an expiry which maxes out at 24 hours (it's expressed in seconds.)
Thus, a worker process to re-add the exception at expiry is a good idea.

In IPv4 a lease time of 0 (unlimited) is allowed which is the approach
taken here. So duel-stack hosts will at least have one route that's
reachable. Assuming that the rules aren't wiped out after the router
is rebooted. It's quite possible they are. Maybe useful for security
and cleanup purposes.

Finally, the response messages after port mapping can be inconsistent
with the true outcome of the request. In testing IPv4 port forwarding
on an Open-WRT VirtualBox VM using the miniupnpd package it replies
with a 501 error message when follow-up calls indicate the mappings
were created successfully. UPnP stacks aren't perfect.

Developer resources:
https://github.com/jeremypoulter/DeveloperToolsForUPnP
    - The AV server does IPv6 and is useful for testing IPv6 code.
https://openwrt.org/docs/guide-user/virtualization/vmware#upgradedupdated_ova_for_openwrt21
    - This is a massive guide on how to get Open-WRT to run in VMWare.
    Do not follow the first part. Skip directly to the section that
    has an 'updated OVA for VMWare' this file is gold.
    Don't use VMWare for it. Open this in VirtualBox.
    It is configured to use LAN IP 192.168.1.1 by default.

    This is important:
        - When you start the VM enter passwd and set a password for root
        - enter vi /etc/config/network
        - change 192.168.1.1 to an IP in the same subnet as the
        network interface you're using for the Internet.
        (press esc then i for insert mode. esc then :qw enter to save/quit.)
        - enter reboot to restart the VM.
        - You should now be able to visit that IP in a web browser.
        - Enter the root password you set or try blank.
        - Go to the software section and update it.
        - Install miniupnpd -- the config is at /etc/config/upnpd
        - Enable it in the config file and reboot again.
http://upnp.org/specs/gw/UPnP-gw-WANIPv6FirewallControl-v1-Service.pdf
    - Specification for add pin hole for ipv6
https://github.com/PortSwigger/upnp-hunter/blob/master/UPnPHunter_Burp.py
    - Useful reference for SSPD search code
https://www.rapid7.com/blog/post/2020/12/22/upnp-with-a-holiday-cheer/
https://stackoverflow.com/questions/54802371/upnp-ssdp-discovery-with-ipv6
    - Programming references on UPnP port forwarding mostly
https://community.ui.com/questions/Ports-required-for-upnp2/6692d89e-1dd6-4abd-a6fa-350cf3444832
    - Reference for some default ports for SSDP services.

http://10.0.1.1:1900/igd.xml
"""
import socket
import asyncio
import time
from aionetiface import (
    Pipe, TCP, UDP, async_wrap_errors, strip_none, fstr, log, log_exception,
    socket_factory, ParseHTTPResponse, IP4, IP6, cancel_tasks,
    what_exception, dict_child, async_test, NET_CONF,
)
from .upnp_utils import (
    UPNP_CONF,
    UPNP_PATHS,
    UPNP_IP,
    UPNP_PORT,
    build_upnp_discover_buf,
    get_upnp_forwarding_services,
    get_upnp_forwarding_services_for_replies,
    sort_upnp_replies_by_unique_location,
    use_upnp_forwarding_services,
)


async def brute_force_port_forward(
af,
    interface,
    ext_port,
    src_tup,
    desc,
    proto,
    add_host=None,
):
    """Probe known UPnP ports on local gateways and attempt port forwarding via all found services."""
    # Check if a port is open.
    async def try_connect(port, host):
        """Attempt a TCP connection to host:port and return the dest tuple on success."""
        dest = (host, port)
        route = await interface.route(af).bind()
        try:
            pipe = await Pipe(TCP, dest, route, conf=UPNP_CONF).connect()
            await pipe.close()
            return dest
        except (OSError, ConnectionError, asyncio.TimeoutError):
            return None

    # Try to load forwarding services at path and use them.
    async def try_service_path(path, dest):
        """Fetch the UPnP description at path on dest and attempt to apply the forwarding rule."""
        # Get service URLs for port forwarding or pin hole.
        route = await interface.route(af).bind()
        service_info = await async_wrap_errors(
            get_upnp_forwarding_services(route, dest, path)
        )

        # Failed.
        if service_info is None:
            return 0

        # Attempt to forward port.
        forward_success = await async_wrap_errors(
            use_upnp_forwarding_services(
                af,
                interface,
                ext_port,
                src_tup,
                desc,
                proto,
                (service_info,),
            )
        )

        # Success so return.
        if forward_success:
            return 1

        return 0

    # List of hosts to try get a rootXML from.
    hosts = []
    gws = interface.netifaces.gateways()
    if af in gws:
        gws = gws[af]
    else:
        gws = []

    # Add all gateways netiface knows about.
    if gws:
        for gw in gws:
            hosts.append(gw[0])

    # Valid default gateway address in IPv6.
    if af == IP6:
        hosts.append("FE80::1")

    # Add fixed test IP.
    if add_host is not None:
        hosts = [add_host]

    # Nothing to do.
    if not hosts:
        return []

    # Ports to try.
    ports = [
        # UPnP port.
        1900,
        # MiniUPnP
        5000,
        # Libupnp
        49152,
        # Many routers
        5431,
        # Default web server ports.
        80,
        8080,
        56688,
    ]

    # Filter dests first by open ports.
    # The point is to cut down the number to try.
    dests = []
    for host in hosts:
        tasks = []
        for port in ports:
            tasks.append(async_wrap_errors(try_connect(port, host)))

        # Socket limit to port list * ifs.
        results = await asyncio.gather(*tasks, return_exceptions=True)
        dests += strip_none(results)

    # Build list of tasks.
    step = 10
    for dest in dests:
        for i in range(0, int(len(UPNP_PATHS) / step) + 1):
            tasks = []
            for path in UPNP_PATHS[i * step : (i * step) + step]:
                tasks.append(async_wrap_errors(try_service_path(path, dest)))

            # Socket limit to path list * ifs.
            results = await asyncio.gather(*tasks, return_exceptions=True)
            if 1 in results:
                return 1

    # All failed.
    return 0


async def discover_upnp_devices(af, nic):
    """Send an SSDP M-SEARCH multicast and collect HTTP replies from responding UPnP devices."""
    # Set protocol family for multicast socket.
    sock_conf = dict_child(
        {
            "sock_proto": socket.IPPROTO_UDP,
            "reuse_addr": True,
        },
        NET_CONF,
    )

    # Make multicast socket for M-search.
    route = await nic.route(af).bind(ips="*")
    sock = await socket_factory(route, sock_type=UDP, conf=sock_conf)
    if sock is None:
        log(fstr("discover upnp sock none {0}", (af,)))
        return

    if af == IP4:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    if af == IP6 and hasattr(socket, "IPPROTO_IPV6"):
        # sock.setsockopt(socket.IPPROTO_IPV6, socket.IP_MULTICAST_TTL, 2)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 22)

    # Create async pipe wrapper for multicast socket.
    dest = (UPNP_IP[af], UPNP_PORT)
    try:
        pipe = await Pipe(UDP, dest, route, sock=sock, conf=sock_conf).connect()
    except asyncio.CancelledError:
        raise
    except (OSError, ConnectionError):
        log_exception()
        try:
            sock.close()
        except OSError:
            pass
        pipe = None

    # print("discover upnp devs ", af, pipe)

    if pipe is None:
        log(
            fstr(
                "discover upnp pipe none {0} {1}",
                (
                    af,
                    nic.name,
                ),
            )
        )
        return

    # Send m-search message.
    buf = build_upnp_discover_buf(af)

    # Multiple sends spaced apart because UDP is garbage.
    for _ in range(0, 3):
        await pipe.send(buf)
        await asyncio.sleep(0.1)

    # Get list of HTTP replies from M-Search message.
    replies = []
    timeout = 2
    start_time = time.monotonic()
    while time.monotonic() - start_time < timeout:
        out = await pipe.recv(timeout=0.1)
        if out is None:
            continue

        try:
            reply = ParseHTTPResponse(out)
        except (OSError, ValueError):
            log_exception()
            continue

        replies.append(reply)

    await pipe.close()
    return replies


async def port_forward_from_multicast(
af,
    interface,
    ext_port,
    src_tup,
    desc,
    proto="TCP",
):
    """Discover UPnP devices via multicast and attempt port forwarding through each one."""
    try:
        # Get list of possible devices supporting UPNP.
        # I think NAT-PMP devices also reply here.
        replies = await discover_upnp_devices(af, interface)
        replies = sort_upnp_replies_by_unique_location(replies)

        # Get a list of service URLs that match forwarding or pin hole.
        service_infos = await get_upnp_forwarding_services_for_replies(
            af, src_tup, interface, replies
        )

        # Try to use the service URLs for forwarding.
        forward_success = await use_upnp_forwarding_services(
            af,
            interface,
            ext_port,
            src_tup,
            desc,
            proto,
            service_infos,
        )

        # print("multi forward ", forward_success)

        return forward_success
    except (OSError, ConnectionError, asyncio.TimeoutError, ValueError):
        what_exception()
        log_exception()
        return False


# Two algorithms are run concurrently to try do UPnP based on the AF.
# Whichever succeeds first causes the other task to be cancelled and
# the function returns as soon as possible.


async def port_forward(af, interface, ext_port, src_tup, desc, proto="TCP"):
    """
    This process is very slow and will be done in the background
    incrementally. This is because there is a 64 socket max limit
    on Windows selector event loop so async gather will cause an error.
    """
    brute_force_task = asyncio.create_task(
        async_wrap_errors(
            brute_force_port_forward(af, interface, ext_port, src_tup, desc, proto)
        )
    )

    multicast_task = asyncio.create_task(
        port_forward_from_multicast(af, interface, ext_port, src_tup, desc, proto="TCP")
    )

    tasks = [brute_force_task, multicast_task]
    winner = 0
    try:
        for done in asyncio.as_completed(tasks):
            result = await done
            if result:
                winner = 1
                break
    finally:
        await cancel_tasks(tasks)

    return winner


if __name__ == "__main__":

    async def upnp_main():
        """Standalone test entry point that runs port_forward on the first IPv4 interface."""
        from .interface import Interface

        nic = await Interface("enp0s25")
        af = IP4
        route = nic.route(af)

        # r = await nic.route(IP4).bind()
        # dest = ("192.168.0.1", 1900)
        # p = await pipe_open(route=r, proto=TCP, dest=dest, conf=NET_CONF)
        # print(p)
        # return

        if af == IP4:
            src_ip = route.nic()
        else:
            src_ip = route.ext()

        # src_ip = route.ext()

        await port_forward(af, nic, 60001, (src_ip, 8000), "test")
        while True:
            await asyncio.sleep(1)

    async_test(upnp_main)

# ip6:
#     if it uses link local for announce use that for bind otherwise ext
#
# multicast replies:
# http://192.168.21.1:56688/rootDesc.xml
# http://192.168.21.1:1990/WFADevice.xml
# http://192.168.21.5:80/description.xml
