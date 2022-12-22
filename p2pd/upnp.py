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
from .base_stream import *
from .http_lib import *

UPNP_LEASE_TIME = 86399
UPNP_PORT = 1900
UPNP_IP   = {
    IP4: b"239.255.255.250",
    IP6: b"FF02::C"
}

"""
Port forwarding should only be done once per interface
address but each interface needs its own unique port.
Otherwise there would be conflicts with past mappings.
The function here associates a unique port with an
interface IP from a high order port range to bind on.
It's not perfects but it keeps post allocations
deterministic yet somewhat unique per NIC IP.
"""
def get_port_by_ips(if_names, port_range=[10000, 65000]):
    # Convert IP to int.
    if_names = sorted(if_names)
    as_str = ""
    for if_name in if_names:
        as_str += if_name
    as_int = hash(as_str)

    # Wrap int around finite field.
    port = field_wrap(as_int, port_range)

    return port

def m_search_buf(af):
    if af == IP4:
        host = to_s(UPNP_IP[af])
    if af == IP6:
        host = f"[{to_s(UPNP_IP[af])}]"

    buf = \
    f'M-SEARCH * HTTP/1.1\r\n' \
    f'HOST: {host}:{UPNP_PORT}\r\n' \
    f'ST: upnp:rootdevice\r\n' \
    f'MX: 5\r\n' \
    f'MAN: "ssdp:discover"\r\n' \
    f'\r\n'

    return to_b(buf)

def parse_root_xml(d, service_type):
    results = []
    for k, v in d.items():
        if isinstance(v, list):
            for e in v:
                results += parse_root_xml(e, service_type)
        elif isinstance(v, dict):
            results += parse_root_xml(v, service_type)
        else:
            if k == "serviceType":
                if service_type in v:
                    results.append(d)
                    break
    #
    return results

def port_forward_task(route, dest, service, lan_ip, lan_port, ext_port, proto, desc):
    # Do port forwarding.
    desc = to_s(desc)
    if dest.af == IP4:
        soap_action = "AddPortMapping"
        body = f"""
<u:{soap_action} xmlns:u="{service["serviceType"]}">
    <NewRemoteHost></NewRemoteHost>
    <NewExternalPort>{ext_port}</NewExternalPort>
    <NewProtocol>{proto}</NewProtocol>
    <NewInternalPort>{lan_port}</NewInternalPort>
    <NewInternalClient>{lan_ip}</NewInternalClient>
    <NewEnabled>1</NewEnabled>
    <NewPortMappingDescription>{desc}</NewPortMappingDescription>
    <NewLeaseDuration>0</NewLeaseDuration>
</u:{soap_action}>
        """

    # Add a hole in the firewall.
    # Have not added UniqueID -- will it still work?
    if dest.af == IP6:
        # Protocol field based on IANA protocol numbers.
        proto_no = proto
        if proto.lower() == "tcp":
            proto_no = 6
        if proto.lower() == "udp":
            proto_no = 17

        # https://github.com/miniupnp/miniupnp/issues/228
        soap_action = "AddPinhole"
        body = f"""
<u:{soap_action} xmlns:u="{service["serviceType"]}">
    <RemoteHost></RemoteHost>
    <RemotePort>0</RemotePort>
    <Protocol>{proto_no}</Protocol>
    <InternalPort>{lan_port}</InternalPort>
    <InternalClient>{lan_ip}</InternalClient>
    <LeaseTime>{UPNP_LEASE_TIME}</LeaseTime>
</u:{soap_action}>
        """

    # Build the XML payload to send.
    payload = f"""
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
{body}
</s:Body>
</s:Envelope>
    """

    # Custom headers for soap.
    headers = [
        [
            b"SOAPAction",
            to_b(f"\"{service['serviceType']}#{soap_action}\"")
        ],
        [b"Connection", b"Close"],
        [b"Content-Type", b"text/xml"],
        [b"Content-Length", to_b(f"{len(payload)}")]
    ]

    return http_req(
        route,
        dest,
        service["controlURL"],
        method="POST",
        payload=payload,
        headers=headers
    )

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
        dest = await Address(host, port).res(route)
        return await get_root_desc(route, dest, path)

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

async def port_forward(interface, ext_port, src_addr, desc, proto="TCP"):
    # Set protocol family for multicast socket.
    af = src_addr.af
    if af == IP4:
        sock_conf = dict_child({
            "sock_proto": socket.IPPROTO_UDP
        }, NET_CONF)
    if af == IP6:
        sock_conf = dict_child({
            "sock_proto": socket.IPPROTO_UDP
        }, NET_CONF)

    # Make multicast socket for M-search.
    route = interface.route(af)
    await route.bind(ips=route.nic())
    sock = await socket_factory(route, sock_type=UDP, conf=sock_conf)
    if af == IP6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IP_MULTICAST_TTL, 2)

    # Create async pipe wrapper for multicast socket.
    dest = await Address(UPNP_IP[af], UPNP_PORT).res(route)
    pipe = await pipe_open(route, UDP, dest, sock, conf=sock_conf)
    pipe.subscribe()

    # Send m-search message.
    buf = m_search_buf(af)

    # Multiple sends spaced apart because UDP is garbage.
    for i in range(0, 3):
        await pipe.send(buf)
        await asyncio.sleep(0.1)

    # Get list of HTTP replies from M-Search message.
    replies = []
    while 1:
        out = await pipe.recv(timeout=4)
        if out is None:
            break

        reply = ParseHTTPResponse(out)
        replies.append(reply)

    # Cleanup multicast socket.
    await pipe.close()

    # Filter duplicate replies.
    unique = {}
    for reply in replies:
        if "location" not in reply.hdrs:
            continue

        location = reply.hdrs["location"]
        if location in unique:
            continue

        unique[location] = reply

    # Save only unique replies.    
    replies = list(unique.values())

    # Main code that gets a list of port forward tasks for a device.
    async def get_root_desc(route, dest, path):
        # Service type lookup table.
        service_types = {
            IP4: "WANIPConnection",
            IP6: "WANIPv6FirewallControl"
        }

        # Bind ip for http forwarding.
        if src_addr.af == IP6:
            # The source address needs to match the internal client
            # being forwarded for add pin hole.
            ips = src_addr.tup[0]
        else:
            # The source address doesn't matter in IPv6 port forwarding.
            ips = src_addr.tup[0]

        # Get main XML for device.
        tasks = []
        try:
            # Request rootDesc.xml.
            _, http_resp = await http_req(route, dest, path)
            xml = http_resp.out()
            d = xmltodict.parse(xml)

            # Convert to a list of services.
            services = parse_root_xml(d, service_types[route.af])
        except Exception:
            log(f"Failed to get root xml {dest.tup} {path}")
            log_exception()
            return tasks

        # Get a task to port forward for each service.
        for service in services:
            forward_route = await interface.route(route.af).bind(ips=ips)
            task = async_wrap_errors(
                port_forward_task(
                    forward_route,
                    dest,
                    service,
                    src_addr.tup[0],
                    src_addr.tup[1],
                    ext_port,
                    proto,
                    desc
                )
            )
            
            # Save task.
            tasks.append(task)

        return tasks

    """
    for reply in replies:
        if "location" not in reply.hdrs:
            continue

        print(reply.hdrs["location"])
    """

    # Port forward on all devices that replied.
    tasks = []
    for req in replies:
        # Location header points to rootDesc.xml.
        url = urllib.parse.urlparse(req.hdrs["location"])
        hostname = url.hostname
        if src_addr.af == IP6:
            hostname = hostname.strip("[]")

        # Root XML address.
        xml_dest = await Address(
            hostname,
            url.port
        ).res(route)

        # Request rootDesc.xml.
        http_route = await interface.route(af).bind(ips=src_addr.tup[0])
        results = await get_root_desc(http_route, xml_dest, url.path)
        if len(results):
            tasks += results

    # Generate fixed path attempts to increase success if m-search fails.
    tasks += await add_fixed_paths(interface, af, get_root_desc)

    # Return port forward tasks.
    return tasks



if __name__ == "__main__":
    async def upnp_main():
        from .interface import Interfaces, init_p2pd
        netifaces = await init_p2pd()
        i = await Interface().start_local()
        port = 31375
        desc = b"test 10003"


        print(i.route(IP4).nic())

        # respondes dont indicate success.

        class F():
            def __init__(self, i, af):
                self.interface = i
                self.af = af

        f = F(i, IP4)
        #src_addr = await Address("fe80::1131:b51a:3f8f:1f2d", port).res(f)
        src_addr = await Address("192.168.21.21", port).res(f)
        tasks = await port_forward(i, port, src_addr, desc)
        results = await asyncio.gather(*tasks)

        print(results)

        for r in results:
            print(r[1].out())

        return

        x = results[0][1].out()
        print(x)

    async_test(upnp_main)

