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

"""
Creates a packet to send to the multicast address
for discovering UPNP devices.
"""
def build_upnp_discover_buf(af):
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
    
async def get_upnp_forwarding_services_for_replies(af, src_ip, nic, replies):
    # Port forward on all devices that replied.
    tasks = []
    for req in replies:
        # Location header points to rootDesc.xml.
        url = urllib.parse.urlparse(req.hdrs["location"])
        hostname = url.hostname
        if af == IP6:
            hostname = hostname.strip("[]")

        # Root XML address.
        xml_dest = (
            hostname,
            url.port,
        )

        # Request rootDesc.xml.
        http_route = await nic.route(af).bind(ips=src_ip)
        task = async_wrap_errors(
            get_upnp_forwarding_services(
                http_route,
                xml_dest,
                url.path
            )
        )
        tasks.append(task)

    results = await asyncio.gather(*tasks)
    return strip_none(results)

async def add_upnp_forwarding_rule(route, dest, service, lan_ip, lan_port, ext_port, proto, desc):
    # Do port forwarding.
    desc = to_s(desc)
    if route.af == IP4:
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
    if route.af == IP6:
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

