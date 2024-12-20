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
        host = fstr("[{0}]", (to_s(UPNP_IP[af]),))

    #f'ST: upnp:rootdevice\r\n' \
    buf = \
    fstr('M-SEARCH * HTTP/1.1\r\n') + \
    fstr('HOST: {0}:{1}\r\n', (host, UPNP_PORT,)) + \
    fstr('ST: upnp:rootdevice\r\n') + \
    fstr('MX: 5\r\n') + \
    fstr('MAN: "ssdp:discover"\r\n') + \
    fstr('\r\n')

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
        http_resp = await WebCurl(dest, route).vars().get(path)
        if http_resp is None:
            return []

        xml = http_resp.out
        d = xmltodict.parse(xml)

        # Convert to a list of services.
        services = find_upnp_service_by_type(d, service_types[route.af])
        if len(services):
            return (dest, services)
    except Exception:
        log(fstr("Failed to get root xml {0} {1}", (dest, path,)))
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
        body = fstr("""
<u:{0} xmlns:u="{1}">
    <NewRemoteHost></NewRemoteHost>
    <NewExternalPort>{2}</NewExternalPort>
    <NewProtocol>{3}</NewProtocol>
    <NewInternalPort>{4}</NewInternalPort>
    <NewInternalClient>{5}</NewInternalClient>
    <NewEnabled>1</NewEnabled>
    <NewPortMappingDescription>{6}</NewPortMappingDescription>
    <NewLeaseDuration>0</NewLeaseDuration>
</u:{7}>
        """, (soap_action, service["serviceType"], ext_port, proto, lan_port, lan_ip, desc, soap_action,))

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
        body = fstr("""
<u:{0} xmlns:u="{1}">
    <RemoteHost>*</RemoteHost>
    <RemotePort>0</RemotePort>
    <Protocol>{2}</Protocol>
    <InternalPort>{3}</InternalPort>
    <InternalClient>{4}</InternalClient>
    <LeaseTime>{5}</LeaseTime>
</u:{6}>
        """, (soap_action, service["serviceType"], proto_no, lan_port, lan_ip, UPNP_LEASE_TIME, soap_action,))

    # Build the XML payload to send.
    payload = fstr("""
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
{0}
</s:Body>
</s:Envelope>
    """, (body,))

    # Custom headers for soap.
    headers = [
        [
            b"SOAPAction",
            to_b(fstr("\"{0}#{1}\"", (service['serviceType'], soap_action,)))
        ],
        [b"Connection", b"Close"],
        [b"Content-Type", b"text/xml"],
        [b"Content-Length", to_b(fstr("{0}", (len(payload),)))]
    ]

    # Requests must come from IP:port for IPv6.
    route = await get_upnp_route(
        af,
        nic,
        dest[0],
    )

    return await WebCurl(dest, route, hdrs=headers).vars(body=payload).post(
        service["controlURL"]
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
        resp = await add_upnp_forwarding_rule(
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
        out = resp.out
        for map_success in map_success_list:
            if map_success in out:
                return True

    return False