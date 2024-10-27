import xmltodict
from .utils import *
from .net import *
from .http_client_lib import *

UPNP_LEASE_TIME = 86399
UPNP_PORT = 1900
UPNP_IP   = {
    IP4: b"239.255.255.250",
    IP6: b"FF02::C"
}

UPNP_PATHS = [
    "/rootDesc.xml",
    "/description.xml",
    "/DeviceDescription.xml",
    "/ssdp/desc-DSM-eth0.xml",
    "/ssdp/desc-DSM-eth1.xml",
    "/UPnP/IGD.xml",
    "/IGD.xml",
    "/igd.xml",
    "/wps_device.xml",
    "/gatedesc.xml",
    "/bmlinks/ddf.xml",
    "/MediaServerDevDesc.xml",
    "/etc/linuxigd/gatedesc.xml",
    "/ssdp/desc-DSM-ovs_eth0.xml",
    "/ssdp/device-desc.xml",
    "/WFADevice.xml",
    "/cameradesc.xml",
    "/upnp/BasicDevice.xml",
    "/upnp.jsp",
    "/simplecfg.xml",
    "/rss/Starter_desc.xml",
    "/devicedesc.xml",
    "/desc/root.cs",
    "/IGatewayDeviceDescDoc",
    "/picsdesc.xml",
    "/upnp/descr.xml",
    "/upnpdevicedesc.xml",
    "/upnp/IGD.xml",
    "/allxml/",
    "/XD/DeviceDescription.xml",
    "/devdescr.xml",
    "/dslf/IGD.xml",
    "/Printer.xml",
    "/ssdp/desc-DSM-bond0.xml",
    "/upnp/BasicDevice.xml",
    "/root.sxml",
    "/gatedesc.xml",
    "/upnp",
    "/Printer.xml",
    "/bmlinks/ddf.xml",
    "/etc/linuxigd/gatedesc.xml",
    "/gatedesc.xml",
    "/picsdesc.xml",
    "/root.sxml",
    "/rootDesc.xml",
    "/simplecfg.xml",
    "/ssdp/desc-DSM-eth0.xml",
    "/ssdp/desc-DSM-eth1.xml",
    "/ssdp/desc-DSM-ovs_eth0.xml",
    "/wps_device.xml",
    '/DSDeviceDescription.xml',
    '/device-desc.xml',
    '/gateway.xml',
    '/ssdp/desc-DSM-eth1.4000.xml',
]

"""
For IPv6 -- if you bind to a global scope address and
try request UPnP resources daemons like miniupnpd will
drop the connection for coming from a 'public' address.
Ensure we bind to link local scope and private IPs.
"""
async def get_upnp_route(af, nic, hostname=None):
    if af == IP6:
        route = nic.route(af)
        if "fe80" == hostname[:4]:
            # Link local src.
            if len(route.link_locals):
                ip = str(route.link_locals[0])
            else:
                ip = route.ext()
        else:
            # Global scope src.
            ip = route.ext()
        
        return await route.bind(
            ips=ip
        )
    else:
        return await nic.route(af).bind()

"""
Creates a packet to send to the multicast address
for discovering UPNP devices.
"""
def build_upnp_discover_buf(af):
    if af == IP4:
        host = to_s(UPNP_IP[af])
    if af == IP6:
        host = f"[{to_s(UPNP_IP[af])}]"

    #f'ST: upnp:rootdevice\r\n' \
    buf = \
    f'M-SEARCH * HTTP/1.1\r\n' \
    f'HOST: {host}:{UPNP_PORT}\r\n' \
    f'ST: upnp:rootdevice\r\n' \
    f'MX: 5\r\n' \
    f'MAN: "ssdp:discover"\r\n' \
    f'\r\n'

    return to_b(buf)

"""
Given a dictionary from xmltodict find a specific type
of service URL for a UPNP device.
"""
def find_upnp_service_by_type(d, service_type):
    results = []
    for k, v in d.items():
        if isinstance(v, list):
            for e in v:
                results += find_upnp_service_by_type(e, service_type)
        elif isinstance(v, dict):
            results += find_upnp_service_by_type(v, service_type)
        else:
            if k == "serviceType":
                if service_type in v:
                    results.append(d)
                    break
    
    return results

# Main code that gets a list of port forward tasks for a device.
async def get_upnp_forwarding_services(route, dest, path):
    # Service type lookup table.
    service_types = {
        IP4: "WANIPConnection",
        IP6: "WANIPv6FirewallControl"
    }

    # Get main XML for device.
    try:
        # Request rootDesc.xml.
        _, http_resp = await http_req(route, dest, path, do_close=True)
        if http_resp is None:
            return []

        xml = http_resp.out()
        d = xmltodict.parse(xml)

        # Convert to a list of services.
        services = find_upnp_service_by_type(d, service_types[route.af])
        if len(services):
            return (dest, services)
    except Exception:
        log(f"Failed to get root xml {dest} {path}")
        log_exception()
    
async def get_upnp_forwarding_services_for_replies(af, src_tup, nic, replies):
    # Port forward on all devices that replied.
    tasks = []
    for req in replies:
        # Location header points to rootDesc.xml.
        url = urllib.parse.urlparse(req.hdrs["location"])
        hostname = url.hostname
        if af == IP6:
            hostname = hostname.strip("[]")

        
        xml_dest = (hostname, url.port)
        route = await get_upnp_route(af, nic, hostname)
        task = async_wrap_errors(
            get_upnp_forwarding_services(
                route,
                xml_dest,
                url.path
            )
        )
        tasks.append(task)

    results = await asyncio.gather(*tasks)
    return strip_none(results)

async def add_upnp_forwarding_rule(af, nic, dest, service, lan_ip, lan_port, ext_port, proto, desc):
    # Do port forwarding.
    desc = to_s(desc)
    if af == IP4:
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
    if af == IP6:
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
    <RemoteHost>*</RemoteHost>
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

    # Requests must come from IP:port for IPv6.
    route = await get_upnp_route(
        af,
        nic,
        dest[0],
    )

    return await http_req(
        route,
        dest,
        service["controlURL"],
        do_close=True,
        method="POST",
        payload=payload,
        headers=headers
    )

def sort_upnp_replies_by_unique_location(replies):
    # Filter duplicate replies.
    unique = {}
    for reply in replies:
        if "location" not in reply.hdrs:
            continue

        location = reply.hdrs["location"]
        if location in unique:
            continue

        unique[location] = reply

    return list(unique.values())

async def use_upnp_forwarding_services(af, interface, ext_port, src_tup, desc, proto, service_infos):
    for service_info in service_infos:
        _, resp = await add_upnp_forwarding_rule(
            af,
            interface,
            service_info[0],
            service_info[1][0],
            src_tup[0],
            src_tup[1],
            ext_port,
            proto,
            desc,
        )

        """
        If you call mapping multiple times with the same details
        you can get a conflict error even though the mapping succeeded.
        So this is considered a 'success'
        """
        map_success_list = [
            b"ConflictInMappingEntry",
            b"AddPortMappingResponse",
            b"AddPinholeResponse",
        ]

        # Look for success indication in output.
        out = resp.out()
        for map_success in map_success_list:
            if map_success in out:
                return True

    return False