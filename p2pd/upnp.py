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
from .utils import *
from .net import *
from .address import *
from .pipe_utils import *
from .http_client_lib import *
from .upnp_utils import *

async def brute_force_port_forward(af, interface, ext_port, src_tup, desc, proto, add_host=None):
    # Check if a port is open.
    async def try_connect(port, host):
        dest = (host, port)
        route = await interface.route(af).bind()
        pipe = await pipe_open(TCP, dest, route)
        if pipe is not None:
            await pipe.close()
            return dest

    # Try to load forwarding services at path and use them.
    async def try_service_path(path, dest):
        # Get service URLs for port forwarding or pin hole.
        route = await interface.route(af).bind()
        service_info = await async_wrap_errors(
            get_upnp_forwarding_services(
                route,
                dest,
                path
            )
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
    if len(gws):
        for gw in gws:
            hosts.append(gw[0])

    # Valid default gateway address in IPv6.
    if af == IP6:
        hosts.append("FE80::1")

    # Add fixed test IP.
    if add_host is not None:
        hosts = [add_host]

    # Nothing to do.
    if not len(hosts):
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
            tasks.append(
                async_wrap_errors(
                    try_connect(port, host)
                )
            )

        # Socket limit to port list * ifs.
        results = await asyncio.gather(*tasks)
        dests += strip_none(results)

    # Build list of tasks.
    step = 10
    for dest in dests:
        for i in range(0, int(len(UPNP_PATHS) / step) + 1):
            tasks = []
            for path in UPNP_PATHS[i * step:(i  * step) + step]:
                tasks.append(
                    async_wrap_errors(
                        try_service_path(path, dest)
                    )
                )

            # Socket limit to path list * ifs.
            results = await asyncio.gather(*tasks)
            if 1 in results:
                return 1

    # All failed.
    return 0

async def discover_upnp_devices(af, nic):
    # Set protocol family for multicast socket.
    sock_conf = dict_child({
        "sock_proto": socket.IPPROTO_UDP
    }, NET_CONF)

    # Make multicast socket for M-search.
    route = await nic.route(af).bind(ips="*")
    sock = await socket_factory(route, sock_type=UDP, conf=sock_conf)
    if af == IP6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IP_MULTICAST_TTL, 2)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)

    # Create async pipe wrapper for multicast socket.
    dest = (UPNP_IP[af], UPNP_PORT)
    pipe = await pipe_open(UDP, dest, route, sock, conf=sock_conf)

    # Send m-search message.
    buf = build_upnp_discover_buf(af)

    # Multiple sends spaced apart because UDP is garbage.
    for _ in range(0, 3):
        await pipe.send(buf)
        await asyncio.sleep(0.1)

    # Get list of HTTP replies from M-Search message.
    replies = []
    for _ in range(0, 5):
        out = await pipe.recv(timeout=1)
        try:
            reply = ParseHTTPResponse(out)
        except Exception:
            continue

        replies.append(reply)

    # Cleanup multicast socket.
    await pipe.close()
    return replies

"""
1. Attempt to forward or pin hole a service. Success is based on
response from the first compatible UPnP service. Continue until
exhausted or success.

2. If continue then try to brute force forwarding or pin hole.
A list of possible hosts and ports are probed for open ports.
Then XML URLs are checked for services. Continue until success
or every possibilities is exhausted. Concurrency is used for speed
here by not excessively to avoid exhausting open socket limit.
"""
async def port_forward(af, interface, ext_port, src_tup, desc, proto="TCP"):
    # Account for errors in the main multicast code.
    try:
        # Get list of possible devices supporting UPNP.
        # I think NAT-PMP devices also reply here.
        replies = await discover_upnp_devices(af, interface)
        replies = sort_upnp_replies_by_unique_location(replies)

        # Get a list of service URLs that match forwarding or pin hole.
        service_infos = await get_upnp_forwarding_services_for_replies(
            af,
            src_tup,
            interface,
            replies
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
    except:
        log_exception()
        forward_success = False

    """
    If forwarding or pin hole was not successful using the standard
    multicast process attempt to brute force possible service URLs.
    This process is very slow and will be done in the background
    incrementally. This is because there is a 64 socket max limit
    on Windows selector event loop so async gather will cause an error.
    """
    if not forward_success:
        return await asyncio.create_task(
            async_wrap_errors(
                brute_force_port_forward(
                    af,
                    interface,
                    ext_port,
                    src_tup,
                    desc,
                    proto
                )
            )
        )
    else:
        return 1

if __name__ == "__main__":
    async def upnp_main():
        from .interface import Interface
        nic = await Interface("enp0s25")
        af = IP4
        route = nic.route(af)
        print(route.ext())

        """
        r = await nic.route(IP4).bind()
        dest = ("192.168.0.1", 1900)
        p = await pipe_open(route=r, proto=TCP, dest=dest, conf=NET_CONF)
        print(p)

        return
        """

        if af == IP4:
            src_ip = route.nic()
        else:
            src_ip = route.ext()

        #src_ip = route.ext()
        
        print(src_ip)
        task = await port_forward(af, nic, 60001, (src_ip, 8000), "test")
        while 1:
            await asyncio.sleep(1)


    async_test(upnp_main)

"""
ip6:
    if it uses link local for announce use that for bind otherwise ext


multicast replies:
http://192.168.21.1:56688/rootDesc.xml
http://192.168.21.1:1990/WFADevice.xml
http://192.168.21.5:80/description.xml


b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n<s:Body>\n<s:Fault>\n<faultcode>s:Client</faultcode>\n<faultstring>UPnPError</faultstring>\n<detail>\n<UPnPError xmlns="urn:schemas-upnp-org:control-1-0">\n<errorCode>718</errorCode>\n<errorDescription>ConflictInMappingEntry</errorDescription>\n</UPnPError>\n</detail>\n</s:Fault>\n</s:Body>\n</s:Envelope>\n'



b'<?xml version="1.0"?>\r\n<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n<s:Body>\n<u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/></s:Body>\n</
s:Envelope>\r\n'

b'<?xml version="1.0"?>\r\n<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:AddPortMappingResponse></s:Body></s:Envelope>\r\n'
"""