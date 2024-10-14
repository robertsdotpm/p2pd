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
"""

import socket
import xmltodict
from .utils import *
from .net import *
from .address import *
from .pipe_utils import *
from .http_client_lib import *
from .upnp_utils import *










async def add_fixed_paths(interface, af, get_root_desc):
    # List of hosts to try get a rootXML from.
    hosts = []
    gws = interface.netifaces.gateways()[af]

    # Add all gateways netiface knows about.
    if len(gws):
        for gw in gws:
            hosts.append(gw[0])

    # Valid default gateway address in IPv6.
    if af == IP6:
        hosts.append("FE80::1")

    # Nothing to do.
    if not len(hosts):
        return []

    # Ports to try.
    ports = [
        # MiniUPnP
        5000,

        # Libupnp
        49152,

        # Many routers
        5431,

        # Default web server ports.
        80,
        8080
    ]

    # List of control urls to try.
    paths = [
        "/rootDesc.xml",
        "/"
    ]

    # Used to carry out the work.
    tasks = []
    async def worker(host, port, path):
        route = await interface.route(af).bind()
        dest = (host, port)
        return await get_upnp_forwarding_services(route, dest, path)

    # Build list of tasks.
    for host in hosts:
        for port in ports:
            for path in paths:
                tasks.append(
                    async_wrap_errors(
                        worker(host, port, path)
                    )
                )

    # Execute fetch attempts.
    results = await asyncio.gather(*tasks)
    out = []
    for result in results:
        if len(result):
            out += result

    return out


async def discover_upnp_devices(af, nic):
    # Set protocol family for multicast socket.
    sock_conf = dict_child({
        "sock_proto": socket.IPPROTO_UDP
    }, NET_CONF)

    # Make multicast socket for M-search.
    route = nic.route(af)
    await route.bind(ips=route.nic())
    sock = await socket_factory(route, sock_type=UDP, conf=sock_conf)
    if af == IP6:
        sock.setsockopt(
            socket.IPPROTO_IPV6,
            socket.IP_MULTICAST_TTL,
            2
        )

    # Create async pipe wrapper for multicast socket.
    dest = (UPNP_IP[af], UPNP_PORT)
    pipe = await pipe_open(UDP, dest, route, sock, conf=sock_conf)
    pipe.subscribe()

    # Send m-search message.
    buf = build_upnp_discover_buf(af)

    # Multiple sends spaced apart because UDP is garbage.
    for _ in range(0, 3):
        await pipe.send(buf)
        await asyncio.sleep(0.1)

    # Get list of HTTP replies from M-Search message.
    replies = []
    for _ in range(0, 10):
        out = await pipe.recv(timeout=4)
        if out is None:
            break

        try:
            reply = ParseHTTPResponse(out)
        except Exception:
            continue

        replies.append(reply)

    # Cleanup multicast socket.
    await pipe.close()
    return replies



async def port_forward(af, interface, ext_port, src_tup, desc, proto="TCP"):






    replies = await discover_upnp_devices(af, interface)
    replies = sort_upnp_replies_by_unique_location(replies)

    print(replies)


    out = await get_upnp_forwarding_services_for_replies(
        af,
        src_tup[0],
        interface,
        replies
    )

    print(out)

    # turn replies into (dest), path for get forwarding servers
    # turn result url into a add forwarding rule

    return




    # Generate fixed path attempts to increase success if m-search fails.
    tasks += await async_wrap_errors(
        add_fixed_paths(interface, af, get_root_desc)
    )

    # Return port forward tasks.
    if len(tasks):
        return await asyncio.gather(*tasks)

if __name__ == "__main__":
    async def upnp_main():
        from .interface import Interface
        nic = await Interface()
        route = nic.route(IP4)
        print(route.nic())

        await port_forward(IP4, nic, 60000, (route.nic(), 2000), "test")


    async_test(upnp_main)

"""
multicast replies:
http://192.168.21.1:56688/rootDesc.xml
http://192.168.21.1:1990/WFADevice.xml
http://192.168.21.5:80/description.xml

- prioritize gw ip replies as primary
- 
- generated replies in background:
    - if no primary 

"""