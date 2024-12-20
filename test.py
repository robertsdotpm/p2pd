from p2pd import *

async def workspace():

    x = b'<?xml version="1.0"?>\r\n<root xmlns="urn:schemas-upnp-org:device-1-0">\r\n<specVersion>\r\n<major>1</major>\r\n<minor>0</minor>\r\n</specVersion>\r\n<device>\r\n<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\r\n<presentationURL>http://192.168.0.1:80                                          </presentationURL>\r\n<friendlyName>Archer C80 AC1900 MU-MIMO Wi-Fi Router</friendlyName>\r\n<manufacturer>TP-Link</manufacturer>\r\n<manufacturerURL>http://www.tp-link.com</manufacturerURL>\r\n<modelDescription>AC1900 MU-MIMO Wi-Fi Router</modelDescription>\r\n<modelName>Archer C80</modelName>\r\n<modelNumber>2.20</modelNumber>\r\n<modelURL>http://192.168.0.1:80</modelURL>\r\n<serialNumber>1.0</serialNumber>\r\n<UDN>uuid:upnp-InternetGatewayDevice-E944A9CA7FD0</UDN>\r\n<UPC>123456789001</UPC>\r\n<serviceList>\r\n<service>\r\n<serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>\r\n<serviceId>urn:upnp-org:serviceId:L3Forwarding1</serviceId>\r\n<controlURL>/l3f</controlURL>\r\n<eventSubURL>/l3f</eventSubURL>\r\n<SCPDURL>/l3f.xml</SCPDURL>\r\n</service>\r\n</serviceList>\r\n<deviceList>\r\n<device>\r\n<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>\r\n<friendlyName>WAN Device</friendlyName>\r\n<manufacturer>TP-Link</manufacturer>\r\n<manufacturerURL>http://www.tp-link.com</manufacturerURL>\r\n<modelDescription>WAN Device</modelDescription>\r\n<modelName>WAN Device</modelName>\r\n<modelNumber>1</modelNumber>\r\n<modelURL></modelURL>\r\n<serialNumber>12345678900001</serialNumber>\r\n<UDN>uuid:upnp-WANDevice-E944A9CA7FD0</UDN>\r\n<UPC>123456789001</UPC>\r\n<serviceList>\r\n<service>\r\n<serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>\r\n<serviceId>urn:upnp-org:serviceId:WANCommonInterfaceConfig</serviceId>\r\n<controlURL>/ifc</controlURL>\r\n<eventSubURL>/ifc</eventSubURL>\r\n<SCPDURL>/ifc.xml</SCPDURL>\r\n</service>\r\n</serviceList>\r\n<deviceList>\r\n<device>\r\n<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>\r\n<friendlyName>WAN Connection Device</friendlyName>\r\n<manufacturer>TP-Link</manufacturer>\r\n<manufacturerURL>http://www.tp-link.com</manufacturerURL>\r\n<modelDescription>WAN Connection Device</modelDescription>\r\n<modelName>WAN Connection Device</modelName>\r\n<modelNumber>1</modelNumber>\r\n<modelURL></modelURL>\r\n<serialNumber>12345678900001</serialNumber>\r\n<UDN>uuid:upnp-WANConnectionDevice-E944A9CA7FD0</UDN>\r\n<UPC>123456789001</UPC>\r\n<serviceList>\r\n<service>\r\n<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\r\n<serviceId>urn:upnp-org:serviceId:WANIPConnection</serviceId>\r\n<controlURL>/ipc</controlURL>\r\n<eventSubURL>/ipc</eventSubURL>\r\n<SCPDURL>/ipc.xml</SCPDURL>\r\n</service>\r\n</serviceList>\r\n</device>\r\n</deviceList>\r\n</device>\r\n</deviceList>\r\n</device>\r\n</root>\r\n'

    d = xmltodict.parse(x)
    print(d)

    return

    # Setup HTTP params.
    addr = ("88.99.211.216", 80)
    path = "/win-auto-py3/"

    # Load interface and route to use.
    nic = await Interface()
    curl = WebCurl(addr, nic.route(IP4))

    # Make the web request.
    resp = await curl.vars().get(path)
    print(resp.req_buf)
    #print(len(resp.out))

asyncio.run(workspace())