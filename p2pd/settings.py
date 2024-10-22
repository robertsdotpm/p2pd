import socket
IP4 = socket.AF_INET
IP6 = socket.AF_INET6
UDP = socket.SOCK_DGRAM
TCP = socket.SOCK_STREAM

ENABLE_STUN = True
ENABLE_UDP = True
P2PD_TEST_INFRASTRUCTURE = False

"""
To keep things simple P2PD uses a number of services to
help facilitate peer-to-peer connections. At the moment
there is no massive list of servers to use because
(as I've learned) -- you need to also have a way to
monitor the integrity of servers to provide high-quality
server lists to peers. That would be too complex to provide
starting out so this may be added down the road.

Note to any engineers:

If you wanted to run P2PD privately you could simply
point all of these servers to your private infrastructure.

https://github.com/pradt2/always-online-stun/tree/master
https://datatracker.ietf.org/doc/html/rfc8489
"""

PNP_SERVERS = {
    IP4: [
        {
            "host": "hetzner1.p2pd.net",
            "ip": "88.99.211.216",
            "port": 5300,
            "pk": "0249fb385ed71aee6862fdb3c0d4f8b193592eca4d61acc983ac5d6d3d3893689f"
        },
        {
            "host": "ovh1.p2pd.net",
            "ip": "158.69.27.176",
            "port": 5300,
            "pk": "03f20b5dcfa5d319635a34f18cb47b339c34f515515a5be733cd7a7f8494e97136"
        },
    ],
    IP6: [
        {
            "host": "hetzner1.p2pd.net",
            "ip": "2a01:04f8:010a:3ce0:0000:0000:0000:0003",
            "port": 5300,
            "pk": "0249fb385ed71aee6862fdb3c0d4f8b193592eca4d61acc983ac5d6d3d3893689f"
        },
        {
            "host": "ovh1.p2pd.net",
            "ip": "2607:5300:0060:80b0:0000:0000:0000:0001",
            "port": 5300,
            "pk": "03f20b5dcfa5d319635a34f18cb47b339c34f515515a5be733cd7a7f8494e97136"
        },
    ],
}




"""
Used to lookup what a nodes IP is and do NAT enumeration.
Supports IPv6 / IPv4 / TCP / UDP -- change IP and port requests.

STUNT servers support TCP.
STUND servers support UDP.
"""

STUN_MAP_SERVERS = {UDP: {IP4: [{'mode': 2, 'host': 'stun1.p2pd.net', 'primary': {'ip': '158.69.27.176', 'port': 34780}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.kaseya.com', 'primary': {'ip': '23.21.199.62', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.solomo.de', 'primary': {'ip': '5.9.87.18', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.hoiio.com', 'primary': {'ip': '52.76.91.67', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.tel.lu', 'primary': {'ip': '85.93.219.114', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.m-online.net', 'primary': {'ip': '212.18.0.14', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '217.91.243.229', 'primary': {'ip': '217.91.243.229', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun1.p2pd.net', 'primary': {'ip': '88.99.211.216', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.linphone.org', 'primary': {'ip': '147.135.128.132', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.healthtap.com', 'primary': {'ip': '34.192.137.246', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.stadtwerke-eutin.de', 'primary': {'ip': '185.39.86.17', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '83.64.250.246', 'primary': {'ip': '83.64.250.246', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.soho66.co.uk', 'primary': {'ip': '185.112.247.26', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'relay.webwormhole.io', 'primary': {'ip': '142.93.228.31', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.freecall.com', 'primary': {'ip': '77.72.169.211', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.technosens.fr', 'primary': {'ip': '52.47.70.236', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.tula.nu', 'primary': {'ip': '94.130.130.49', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.url.net.au', 'primary': {'ip': '180.235.108.91', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.vavadating.com', 'primary': {'ip': '5.161.52.174', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.dls.net', 'primary': {'ip': '209.242.17.106', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.voipzoom.com', 'primary': {'ip': '77.72.169.212', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.levigo.de', 'primary': {'ip': '89.106.220.34', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.radiojar.com', 'primary': {'ip': '137.74.112.113', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.fbsbx.com', 'primary': {'ip': '157.240.8.3', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.vozelia.com', 'primary': {'ip': '37.139.120.14', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.gmx.de', 'primary': {'ip': '212.227.67.34', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.smartvoip.com', 'primary': {'ip': '77.72.169.213', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.flashdance.cx', 'primary': {'ip': '193.182.111.151', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.voipxs.nl', 'primary': {'ip': '194.140.246.192', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.officinabit.com', 'primary': {'ip': '83.211.9.232', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.1-voip.com', 'primary': {'ip': '209.105.241.31', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.framasoft.org', 'primary': {'ip': '178.63.240.148', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.irishvoip.com', 'primary': {'ip': '216.93.246.18', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.business-isp.nl', 'primary': {'ip': '143.198.60.79', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '62.72.83.10', 'primary': {'ip': '62.72.83.10', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '51.68.112.203', 'primary': {'ip': '51.68.112.203', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '52.26.251.34', 'primary': {'ip': '52.26.251.34', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': '90.145.158.66', 'primary': {'ip': '90.145.158.66', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.shadrinsk.net', 'primary': {'ip': '195.211.238.18', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.uls.co.za', 'primary': {'ip': '154.73.34.8', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.localphone.com', 'primary': {'ip': '94.75.247.45', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.waterpolopalermo.it', 'primary': {'ip': '185.18.24.50', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.easyvoip.com', 'primary': {'ip': '77.72.169.210', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.easybell.de', 'primary': {'ip': '138.201.243.186', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '94.23.17.185', 'primary': {'ip': '94.23.17.185', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.nextcloud.com', 'primary': {'ip': '159.69.191.124', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.poetamatusel.org', 'primary': {'ip': '136.243.59.79', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.siedle.com', 'primary': {'ip': '217.19.174.42', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.files.fm', 'primary': {'ip': '188.40.18.246', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.commpeak.com', 'primary': {'ip': '85.17.88.164', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.totalcom.info', 'primary': {'ip': '82.113.193.63', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.usfamily.net', 'primary': {'ip': '64.131.63.217', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '94.140.180.141', 'primary': {'ip': '94.140.180.141', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.babelforce.com', 'primary': {'ip': '109.235.234.65', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.tel2.co.uk', 'primary': {'ip': '27.111.15.93', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '88.198.151.128', 'primary': {'ip': '88.198.151.128', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '31.184.236.23', 'primary': {'ip': '31.184.236.23', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.sonetel.net', 'primary': {'ip': '52.24.174.49', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.nfon.net', 'primary': {'ip': '109.68.96.189', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.ru-brides.com', 'primary': {'ip': '5.161.57.75', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '24.204.48.11', 'primary': {'ip': '24.204.48.11', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '172.233.245.118', 'primary': {'ip': '172.233.245.118', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.fitauto.ru', 'primary': {'ip': '195.208.107.138', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '44.230.252.214', 'primary': {'ip': '44.230.252.214', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '34.197.205.39', 'primary': {'ip': '34.197.205.39', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.clickphone.ro', 'primary': {'ip': '193.43.148.37', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': '91.212.41.85', 'primary': {'ip': '91.212.41.85', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.plexicomm.net', 'primary': {'ip': '23.252.81.20', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.nexphone.ch', 'primary': {'ip': '212.25.7.87', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.arkh-edu.ru', 'primary': {'ip': '91.122.224.102', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.sewan.fr', 'primary': {'ip': '37.97.65.52', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.fmo.de', 'primary': {'ip': '91.213.98.54', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.infra.net', 'primary': {'ip': '195.242.206.1', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.synergiejobs.be', 'primary': {'ip': '84.198.248.217', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.myvoipapp.com', 'primary': {'ip': '46.101.202.148', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.siplogin.de', 'primary': {'ip': '3.78.237.53', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.annatel.net', 'primary': {'ip': '88.218.220.40', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.skydrone.aero', 'primary': {'ip': '52.52.70.85', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.peethultra.be', 'primary': {'ip': '81.82.206.117', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '81.3.27.44', 'primary': {'ip': '81.3.27.44', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.pure-ip.com', 'primary': {'ip': '23.21.92.55', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.ixc.ua', 'primary': {'ip': '136.243.202.77', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.ringostat.com', 'primary': {'ip': '176.9.24.184', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.voys.nl', 'primary': {'ip': '195.35.115.37', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.axialys.net', 'primary': {'ip': '217.146.224.74', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '195.145.93.141', 'primary': {'ip': '195.145.93.141', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '162.243.29.166', 'primary': {'ip': '162.243.29.166', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.planetarium.com.br', 'primary': {'ip': '198.72.119.88', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '213.239.206.5', 'primary': {'ip': '213.239.206.5', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '185.125.180.70', 'primary': {'ip': '185.125.180.70', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.signalwire.com', 'primary': {'ip': '147.182.188.245', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '51.255.31.35', 'primary': {'ip': '51.255.31.35', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '20.93.239.171', 'primary': {'ip': '20.93.239.171', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '79.140.42.88', 'primary': {'ip': '79.140.42.88', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.logic.ky', 'primary': {'ip': '216.144.89.2', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.hicare.net', 'primary': {'ip': '54.183.232.212', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.hot-chilli.net', 'primary': {'ip': '49.12.125.53', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.schoeffel.de', 'primary': {'ip': '212.118.209.86', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.eoni.com', 'primary': {'ip': '216.228.192.76', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.bergophor.de', 'primary': {'ip': '87.129.12.229', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.frozenmountain.com', 'primary': {'ip': '54.197.117.0', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.heeds.eu', 'primary': {'ip': '198.100.144.121', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.teamfon.de', 'primary': {'ip': '212.29.18.56', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.zadarma.com', 'primary': {'ip': '185.45.152.22', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.megatel.si', 'primary': {'ip': '91.199.161.149', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '202.1.117.2', 'primary': {'ip': '202.1.117.2', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.eol.co.nz', 'primary': {'ip': '202.49.164.50', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.sma.de', 'primary': {'ip': '104.45.13.239', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.srce.hr', 'primary': {'ip': '161.53.1.100', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.kanojo.de', 'primary': {'ip': '95.216.78.222', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.3wayint.com', 'primary': {'ip': '95.216.145.84', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '51.83.15.212', 'primary': {'ip': '51.83.15.212', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.diallog.com', 'primary': {'ip': '209.251.63.76', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stunserver.stunprotocol.org', 'primary': {'ip': '3.132.228.249', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '80.155.54.123', 'primary': {'ip': '80.155.54.123', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.next-gen.ro', 'primary': {'ip': '193.16.148.245', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.easter-eggs.com', 'primary': {'ip': '37.9.136.90', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '51.83.201.84', 'primary': {'ip': '51.83.201.84', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.syrex.co.za', 'primary': {'ip': '41.79.23.6', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.selasky.org', 'primary': {'ip': '212.227.67.33', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.thinkrosystem.com', 'primary': {'ip': '51.68.45.75', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.sipthor.net', 'primary': {'ip': '85.17.186.7', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.dunyatelekom.com', 'primary': {'ip': '34.193.110.91', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '185.88.236.76', 'primary': {'ip': '185.88.236.76', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.it1.hr', 'primary': {'ip': '176.62.31.10', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '212.103.68.7', 'primary': {'ip': '212.103.68.7', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.syncthing.net', 'primary': {'ip': '198.211.120.59', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.lineaencasa.com', 'primary': {'ip': '66.110.73.74', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '195.201.132.113', 'primary': {'ip': '195.201.132.113', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '54.177.85.190', 'primary': {'ip': '54.177.85.190', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.engineeredarts.co.uk', 'primary': {'ip': '35.177.202.92', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.qcol.net', 'primary': {'ip': '69.89.160.30', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.voipplanet.nl', 'primary': {'ip': '194.61.59.25', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.acronis.com', 'primary': {'ip': '69.20.59.115', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.miwifi.com', 'primary': {'ip': '111.206.174.3', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.pjsip.org', 'primary': {'ip': '139.162.62.29', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '194.149.74.157', 'primary': {'ip': '194.149.74.157', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.sylaps.com', 'primary': {'ip': '54.176.195.118', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.meowsbox.com', 'primary': {'ip': '173.255.213.166', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.voipia.net', 'primary': {'ip': '192.172.233.145', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.optdyn.com', 'primary': {'ip': '207.38.89.164', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.bearstech.com', 'primary': {'ip': '78.40.125.40', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.chatous.com', 'primary': {'ip': '52.65.142.25', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun2.l.google.com', 'primary': {'ip': '74.125.250.129', 'port': 19302}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.axeos.nl', 'primary': {'ip': '185.67.224.58', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.ippi.fr', 'primary': {'ip': '194.169.214.30', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.komsa.de', 'primary': {'ip': '217.119.210.45', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.simlar.org', 'primary': {'ip': '78.111.72.53', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '85.197.87.182', 'primary': {'ip': '85.197.87.182', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.mywatson.it', 'primary': {'ip': '92.222.127.114', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.fairytel.at', 'primary': {'ip': '77.237.51.83', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.bethesda.net', 'primary': {'ip': '3.27.214.87', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'webrtc.free-solutions.org', 'primary': {'ip': '94.103.99.223', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.voztele.com', 'primary': {'ip': '193.22.119.20', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.t-online.de', 'primary': {'ip': '217.0.12.1', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.sipgate.net', 'primary': {'ip': '15.197.250.192', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '87.253.140.133', 'primary': {'ip': '87.253.140.133', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.imp.ch', 'primary': {'ip': '157.161.10.32', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.deepfinesse.com', 'primary': {'ip': '157.22.130.80', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.jabbim.cz', 'primary': {'ip': '88.86.102.51', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '34.74.124.204', 'primary': {'ip': '34.74.124.204', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '95.216.190.5', 'primary': {'ip': '95.216.190.5', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.sky.od.ua', 'primary': {'ip': '81.25.228.2', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.myspeciality.com', 'primary': {'ip': '35.180.81.93', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.dcalling.de', 'primary': {'ip': '45.15.102.34', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.wtfismyip.com', 'primary': {'ip': '65.108.75.112', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.voicetech.se', 'primary': {'ip': '91.205.60.185', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '88.99.67.241', 'primary': {'ip': '88.99.67.241', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.splicecom.com', 'primary': {'ip': '77.246.29.197', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': '81.83.12.46', 'primary': {'ip': '81.83.12.46', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.ipshka.com', 'primary': {'ip': '193.28.184.4', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.foad.me.uk', 'primary': {'ip': '212.69.48.253', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.bitburger.de', 'primary': {'ip': '193.22.17.97', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.yollacalls.com', 'primary': {'ip': '203.189.26.131', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.teliax.com', 'primary': {'ip': '63.211.239.133', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.labs.net', 'primary': {'ip': '204.197.159.2', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.tng.de', 'primary': {'ip': '82.97.157.254', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.var6.cn', 'primary': {'ip': '111.230.157.11', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.leucotron.com.br', 'primary': {'ip': '177.66.4.31', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.imafex.sk', 'primary': {'ip': '188.123.97.201', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.gigaset.net', 'primary': {'ip': '81.173.115.217', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.crimeastar.net', 'primary': {'ip': '81.162.64.162', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '192.76.120.66', 'primary': {'ip': '192.76.120.66', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.wcoil.com', 'primary': {'ip': '65.17.128.101', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.aaisp.co.uk', 'primary': {'ip': '81.187.30.115', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.cablenet-as.net', 'primary': {'ip': '213.140.209.236', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.sipgate.net', 'primary': {'ip': '3.33.249.248', 'port': 10000}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.oncloud7.ch', 'primary': {'ip': '188.40.203.74', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '18.197.157.228', 'primary': {'ip': '18.197.157.228', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.jowisoftware.de', 'primary': {'ip': '92.205.106.161', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.taxsee.com', 'primary': {'ip': '195.209.116.72', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.nanocosmos.de', 'primary': {'ip': '45.77.173.211', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.hide.me', 'primary': {'ip': '209.250.250.224', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.netgsm.com.tr', 'primary': {'ip': '185.88.7.40', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.alphacron.de', 'primary': {'ip': '193.22.2.248', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.wxnz.net', 'primary': {'ip': '182.154.16.5', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.medvc.eu', 'primary': {'ip': '150.254.161.60', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.solnet.ch', 'primary': {'ip': '212.101.4.120', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.cope.es', 'primary': {'ip': '213.251.48.147', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.f.haeder.net', 'primary': {'ip': '188.138.90.169', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.vadacom.co.nz', 'primary': {'ip': '103.124.135.6', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.voip.blackberry.com', 'primary': {'ip': '20.14.234.57', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.voip.aebc.com', 'primary': {'ip': '66.51.128.11', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.sipglobalphone.com', 'primary': {'ip': '131.153.146.5', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.futurasp.es', 'primary': {'ip': '178.33.166.29', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '34.206.168.53', 'primary': {'ip': '34.206.168.53', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.dus.net', 'primary': {'ip': '83.125.8.47', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.bcs2005.net', 'primary': {'ip': '87.106.115.74', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.bandyer.com', 'primary': {'ip': '54.252.254.82', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.epygi.com', 'primary': {'ip': '23.253.102.137', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.rolmail.net', 'primary': {'ip': '195.254.254.20', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.elitetele.com', 'primary': {'ip': '185.41.24.10', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.hitv.com', 'primary': {'ip': '120.132.47.25', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '20.93.239.168', 'primary': {'ip': '20.93.239.168', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.comrex.com', 'primary': {'ip': '13.59.93.103', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.solcon.nl', 'primary': {'ip': '212.45.38.40', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.fathomvoice.com', 'primary': {'ip': '54.173.127.164', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '129.153.212.128', 'primary': {'ip': '129.153.212.128', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '35.158.233.7', 'primary': {'ip': '35.158.233.7', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.eleusi.com', 'primary': {'ip': '188.64.120.28', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.webmatrix.com.br', 'primary': {'ip': '192.99.194.90', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '157.90.156.59', 'primary': {'ip': '157.90.156.59', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}], IP6: [{'mode': 2, 'host': 'stun1.p2pd.net', 'primary': {'ip': '2607:5300:60:80b0::1', 'port': 34780}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.tula.nu', 'primary': {'ip': '2a01:4f8:13b:39ce::2', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.fbsbx.com', 'primary': {'ip': '2a03:2880:f019:102:face:b00c:0:24d9', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.flashdance.cx', 'primary': {'ip': '2a03:8600::89', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.framasoft.org', 'primary': {'ip': '2a01:4f8:120:1497::148', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.nextcloud.com', 'primary': {'ip': '2a01:4f8:c17:8f74::1', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.axialys.net', 'primary': {'ip': '2001:1538:1::224:74', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.hot-chilli.net', 'primary': {'ip': '2a01:4f8:242:56ca::2', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.antisip.com', 'primary': {'ip': '2001:41d0:2:12b9::1', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.ipfire.org', 'primary': {'ip': '2001:678:b28::118', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stunserver.stunprotocol.org', 'primary': {'ip': '2600:1f16:8c5:101:80b:b58b:828:8df4', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.chatous.com', 'primary': {'ip': '2406:da1c:c7:8700:3a86:24a8:3b8f:202d', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun2.l.google.com', 'primary': {'ip': '2001:4860:4864:5:8000::1', 'port': 19302}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.simlar.org', 'primary': {'ip': '2a02:f98:0:50:2ff:23ff:fe42:1b23', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.imp.ch', 'primary': {'ip': '2001:4060:1:1005::10:32', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.wtfismyip.com', 'primary': {'ip': '2a01:4f9:6b:4b55::acab', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.jowisoftware.de', 'primary': {'ip': '2a00:1169:11b:a6b0::', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}]}, TCP: {IP4: [{'mode': 2, 'host': 'stun1.p2pd.net', 'primary': {'ip': '158.69.27.176', 'port': 34780}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.kaseya.com', 'primary': {'ip': '23.21.199.62', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.m-online.net', 'primary': {'ip': '212.18.0.14', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '217.91.243.229', 'primary': {'ip': '217.91.243.229', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun1.p2pd.net', 'primary': {'ip': '88.99.211.216', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.healthtap.com', 'primary': {'ip': '34.192.137.246', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '83.64.250.246', 'primary': {'ip': '83.64.250.246', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.technosens.fr', 'primary': {'ip': '52.47.70.236', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.tula.nu', 'primary': {'ip': '94.130.130.49', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.vavadating.com', 'primary': {'ip': '5.161.52.174', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.radiojar.com', 'primary': {'ip': '137.74.112.113', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.flashdance.cx', 'primary': {'ip': '193.182.111.151', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.1cbit.ru', 'primary': {'ip': '212.53.40.43', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.business-isp.nl', 'primary': {'ip': '147.182.188.245', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '62.72.83.10', 'primary': {'ip': '62.72.83.10', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '51.68.112.203', 'primary': {'ip': '51.68.112.203', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '52.26.251.34', 'primary': {'ip': '52.26.251.34', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': '90.145.158.66', 'primary': {'ip': '90.145.158.66', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '94.23.17.185', 'primary': {'ip': '94.23.17.185', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.nextcloud.com', 'primary': {'ip': '159.69.191.124', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.poetamatusel.org', 'primary': {'ip': '136.243.59.79', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.siedle.com', 'primary': {'ip': '217.19.174.41', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.files.fm', 'primary': {'ip': '188.40.18.246', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '94.140.180.141', 'primary': {'ip': '94.140.180.141', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '88.198.151.128', 'primary': {'ip': '88.198.151.128', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '31.184.236.23', 'primary': {'ip': '31.184.236.23', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.ru-brides.com', 'primary': {'ip': '5.161.57.75', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '24.204.48.11', 'primary': {'ip': '24.204.48.11', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '172.233.245.118', 'primary': {'ip': '172.233.245.118', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.fitauto.ru', 'primary': {'ip': '195.208.107.138', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '44.230.252.214', 'primary': {'ip': '44.230.252.214', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '34.197.205.39', 'primary': {'ip': '34.197.205.39', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': '212.53.40.40', 'primary': {'ip': '212.53.40.40', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': '91.212.41.85', 'primary': {'ip': '91.212.41.85', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '143.198.60.79', 'primary': {'ip': '143.198.60.79', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.sewan.fr', 'primary': {'ip': '37.97.65.52', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.fmo.de', 'primary': {'ip': '91.213.98.54', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.synergiejobs.be', 'primary': {'ip': '84.198.248.217', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.siplogin.de', 'primary': {'ip': '35.158.233.7', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.annatel.net', 'primary': {'ip': '88.218.220.40', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.skydrone.aero', 'primary': {'ip': '52.52.70.85', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': 'stun.peethultra.be', 'primary': {'ip': '81.82.206.117', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '81.3.27.44', 'primary': {'ip': '81.3.27.44', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.pure-ip.com', 'primary': {'ip': '23.21.92.55', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.ringostat.com', 'primary': {'ip': '176.9.24.184', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.axialys.net', 'primary': {'ip': '217.146.224.74', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '195.145.93.141', 'primary': {'ip': '195.145.93.141', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '162.243.29.166', 'primary': {'ip': '162.243.29.166', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '213.239.206.5', 'primary': {'ip': '213.239.206.5', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '185.125.180.70', 'primary': {'ip': '185.125.180.70', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '51.255.31.35', 'primary': {'ip': '51.255.31.35', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '20.93.239.171', 'primary': {'ip': '20.93.239.171', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '79.140.42.88', 'primary': {'ip': '79.140.42.88', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.hot-chilli.net', 'primary': {'ip': '49.12.125.53', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.bergophor.de', 'primary': {'ip': '87.129.12.229', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.frozenmountain.com', 'primary': {'ip': '34.206.168.53', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.heeds.eu', 'primary': {'ip': '198.100.144.121', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '202.1.117.2', 'primary': {'ip': '202.1.117.2', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.kanojo.de', 'primary': {'ip': '95.216.78.222', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.3wayint.com', 'primary': {'ip': '95.216.145.84', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '51.83.15.212', 'primary': {'ip': '51.83.15.212', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.diallog.com', 'primary': {'ip': '209.251.63.76', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stunserver.stunprotocol.org', 'primary': {'ip': '3.132.228.249', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '80.155.54.123', 'primary': {'ip': '80.155.54.123', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '51.83.201.84', 'primary': {'ip': '51.83.201.84', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.thinkrosystem.com', 'primary': {'ip': '51.68.45.75', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '185.88.236.76', 'primary': {'ip': '185.88.236.76', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '212.103.68.7', 'primary': {'ip': '212.103.68.7', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '195.201.132.113', 'primary': {'ip': '195.201.132.113', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '54.177.85.190', 'primary': {'ip': '54.177.85.190', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.engineeredarts.co.uk', 'primary': {'ip': '35.177.202.92', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '134.2.17.14', 'primary': {'ip': '134.2.17.14', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.acronis.com', 'primary': {'ip': '69.20.59.115', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '194.149.74.157', 'primary': {'ip': '194.149.74.157', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.sylaps.com', 'primary': {'ip': '54.176.195.118', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.voipia.net', 'primary': {'ip': '192.172.233.145', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.chatous.com', 'primary': {'ip': '52.65.142.25', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '52.24.174.49', 'primary': {'ip': '52.24.174.49', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun2.p2pd.net', 'primary': {'ip': '158.69.27.176', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '85.197.87.182', 'primary': {'ip': '85.197.87.182', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.bethesda.net', 'primary': {'ip': '3.27.214.87', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'webrtc.free-solutions.org', 'primary': {'ip': '94.103.99.223', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '87.253.140.133', 'primary': {'ip': '87.253.140.133', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.imp.ch', 'primary': {'ip': '157.161.10.32', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '34.74.124.204', 'primary': {'ip': '34.74.124.204', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '95.216.190.5', 'primary': {'ip': '95.216.190.5', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '54.197.117.0', 'primary': {'ip': '54.197.117.0', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.myspeciality.com', 'primary': {'ip': '35.180.81.93', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.dcalling.de', 'primary': {'ip': '45.15.102.34', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '88.99.67.241', 'primary': {'ip': '88.99.67.241', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 1, 'host': '81.83.12.46', 'primary': {'ip': '81.83.12.46', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.foad.me.uk', 'primary': {'ip': '212.69.48.253', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.bitburger.de', 'primary': {'ip': '193.22.17.97', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '192.76.120.66', 'primary': {'ip': '192.76.120.66', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.oncloud7.ch', 'primary': {'ip': '188.40.203.74', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '18.197.157.228', 'primary': {'ip': '18.197.157.228', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.jowisoftware.de', 'primary': {'ip': '92.205.106.161', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.nanocosmos.de', 'primary': {'ip': '128.199.69.130', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.f.haeder.net', 'primary': {'ip': '188.138.90.169', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.voip.blackberry.com', 'primary': {'ip': '20.15.169.9', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.bcs2005.net', 'primary': {'ip': '87.106.115.74', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.bandyer.com', 'primary': {'ip': '54.252.254.80', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '20.93.239.168', 'primary': {'ip': '20.93.239.168', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '129.153.212.128', 'primary': {'ip': '129.153.212.128', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '3.78.237.53', 'primary': {'ip': '3.78.237.53', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': '157.90.156.59', 'primary': {'ip': '157.90.156.59', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}], IP6: [{'mode': 2, 'host': 'stun1.p2pd.net', 'primary': {'ip': '2607:5300:60:80b0::1', 'port': 34780}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.tula.nu', 'primary': {'ip': '2a01:4f8:13b:39ce::2', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.flashdance.cx', 'primary': {'ip': '2a03:8600::89', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.nextcloud.com', 'primary': {'ip': '2a01:4f8:c17:8f74::1', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.axialys.net', 'primary': {'ip': '2001:1538:1::224:74', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.hot-chilli.net', 'primary': {'ip': '2a01:4f8:242:56ca::2', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.antisip.com', 'primary': {'ip': '2001:41d0:2:12b9::1', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.ipfire.org', 'primary': {'ip': '2001:678:b28::118', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stunserver.stunprotocol.org', 'primary': {'ip': '2600:1f16:8c5:101:80b:b58b:828:8df4', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.chatous.com', 'primary': {'ip': '2406:da1c:c7:8700:3a86:24a8:3b8f:202d', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun2.p2pd.net', 'primary': {'ip': '2607:5300:60:80b0::1', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.imp.ch', 'primary': {'ip': '2001:4060:1:1005::10:32', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'mode': 2, 'host': 'stun.jowisoftware.de', 'primary': {'ip': '2a00:1169:11b:a6b0::', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}]}}

STUN_CHANGE_SERVERS = {UDP: {IP4: [{'mode': 1, 'host': 'stun2.p2pd.net', 'primary': {'ip': '88.99.211.211', 'port': 34780}, 'secondary': {'ip': "88.99.211.216", 'port': 34790}}, {'mode': 1, 'host': 'stun.solomo.de', 'primary': {'ip': '5.9.87.18', 'port': 3478}, 'secondary': {'ip': '136.243.205.11', 'port': 3479}}, {'mode': 1, 'host': 'stun.hoiio.com', 'primary': {'ip': '52.76.91.67', 'port': 3478}, 'secondary': {'ip': '52.74.211.13', 'port': 3479}}, {'mode': 1, 'host': 'stun.tel.lu', 'primary': {'ip': '85.93.219.114', 'port': 3478}, 'secondary': {'ip': '85.93.219.115', 'port': 3479}}, {'mode': 1, 'host': 'stun.m-online.net', 'primary': {'ip': '212.18.0.14', 'port': 3478}, 'secondary': {'ip': '62.245.150.225', 'port': 3479}}, {'mode': 1, 'host': 'stun1.p2pd.net', 'primary': {'ip': '88.99.211.216', 'port': 3478}, 'secondary': {'ip': '88.99.211.211', 'port': 3479}}, {'mode': 1, 'host': 'stun.stadtwerke-eutin.de', 'primary': {'ip': '185.39.86.17', 'port': 3478}, 'secondary': {'ip': '185.39.86.18', 'port': 3479}}, {'mode': 1, 'host': 'stun.freecall.com', 'primary': {'ip': '77.72.169.212', 'port': 3478}, 'secondary': {'ip': '77.72.169.213', 'port': 3479}}, {'mode': 1, 'host': 'stun.url.net.au', 'primary': {'ip': '180.235.108.91', 'port': 3478}, 'secondary': {'ip': '180.235.108.92', 'port': 3479}}, {'mode': 1, 'host': 'stun.dls.net', 'primary': {'ip': '209.242.17.106', 'port': 3478}, 'secondary': {'ip': '209.242.17.107', 'port': 3479}}, {'mode': 1, 'host': 'stun.voipzoom.com', 'primary': {'ip': '77.72.169.210', 'port': 3478}, 'secondary': {'ip': '77.72.169.211', 'port': 3479}}, {'mode': 1, 'host': 'stun.levigo.de', 'primary': {'ip': '89.106.220.34', 'port': 3478}, 'secondary': {'ip': '89.106.220.35', 'port': 3479}}, {'mode': 1, 'host': 'stun.vozelia.com', 'primary': {'ip': '37.139.120.14', 'port': 3478}, 'secondary': {'ip': '37.139.120.15', 'port': 3479}}, {'mode': 1, 'host': 'stun.gmx.de', 'primary': {'ip': '212.227.67.33', 'port': 3478}, 'secondary': {'ip': '212.227.67.34', 'port': 3479}}, {'mode': 1, 'host': 'stun.voipxs.nl', 'primary': {'ip': '194.140.246.192', 'port': 3478}, 'secondary': {'ip': '91.215.4.139', 'port': 3479}}, {'mode': 1, 'host': 'stun.officinabit.com', 'primary': {'ip': '83.211.9.232', 'port': 3478}, 'secondary': {'ip': '83.211.9.235', 'port': 3479}}, {'mode': 1, 'host': 'stun.1-voip.com', 'primary': {'ip': '209.105.241.31', 'port': 3478}, 'secondary': {'ip': '209.105.241.32', 'port': 3479}}, {'mode': 1, 'host': 'stun.irishvoip.com', 'primary': {'ip': '216.93.246.18', 'port': 3478}, 'secondary': {'ip': '216.93.246.15', 'port': 3479}}, {'mode': 1, 'host': 'stun.uls.co.za', 'primary': {'ip': '154.73.34.8', 'port': 3478}, 'secondary': {'ip': '154.73.34.9', 'port': 3479}}, {'mode': 1, 'host': 'stun.waterpolopalermo.it', 'primary': {'ip': '185.18.24.50', 'port': 3478}, 'secondary': {'ip': '185.18.24.16', 'port': 3479}}, {'mode': 1, 'host': 'stun.easybell.de', 'primary': {'ip': '138.201.243.186', 'port': 3478}, 'secondary': {'ip': '138.201.243.187', 'port': 3479}}, {'mode': 1, 'host': 'stun.commpeak.com', 'primary': {'ip': '138.201.60.199', 'port': 3478}, 'secondary': {'ip': '94.130.116.102', 'port': 3479}}, {'mode': 1, 'host': 'stun.totalcom.info', 'primary': {'ip': '82.113.193.63', 'port': 3478}, 'secondary': {'ip': '82.113.193.67', 'port': 3479}}, {'mode': 1, 'host': 'stun.usfamily.net', 'primary': {'ip': '64.131.63.216', 'port': 3478}, 'secondary': {'ip': '64.131.63.240', 'port': 3479}}, {'mode': 1, 'host': 'stun.babelforce.com', 'primary': {'ip': '109.235.234.65', 'port': 3478}, 'secondary': {'ip': '109.235.234.125', 'port': 3479}}, {'mode': 1, 'host': 'stun.tel2.co.uk', 'primary': {'ip': '27.111.15.93', 'port': 3478}, 'secondary': {'ip': '27.111.15.81', 'port': 3479}}, {'mode': 1, 'host': 'stun.fitauto.ru', 'primary': {'ip': '195.208.107.138', 'port': 3478}, 'secondary': {'ip': '195.208.107.140', 'port': 3479}}, {'mode': 1, 'host': 'stun.plexicomm.net', 'primary': {'ip': '23.252.81.20', 'port': 3478}, 'secondary': {'ip': '23.252.81.21', 'port': 3479}}, {'mode': 1, 'host': 'stun.nexphone.ch', 'primary': {'ip': '212.25.7.87', 'port': 3478}, 'secondary': {'ip': '212.25.7.88', 'port': 3479}}, {'mode': 1, 'host': 'stun.sewan.fr', 'primary': {'ip': '37.97.65.52', 'port': 3478}, 'secondary': {'ip': '37.97.65.53', 'port': 3479}}, {'mode': 1, 'host': 'stun.infra.net', 'primary': {'ip': '195.242.206.1', 'port': 3478}, 'secondary': {'ip': '195.242.206.28', 'port': 3479}}, {'mode': 1, 'host': 'stun.halonet.pl', 'primary': {'ip': '193.43.148.37', 'port': 3478}, 'secondary': {'ip': '193.43.148.38', 'port': 3479}}, {'mode': 1, 'host': 'stun.ixc.ua', 'primary': {'ip': '136.243.202.77', 'port': 3478}, 'secondary': {'ip': '136.243.202.78', 'port': 3479}}, {'mode': 1, 'host': '185.125.180.70', 'primary': {'ip': '185.125.180.70', 'port': 3478}, 'secondary': {'ip': '185.125.180.71', 'port': 3479}}, {'mode': 1, 'host': '51.255.31.35', 'primary': {'ip': '51.255.31.35', 'port': 3478}, 'secondary': {'ip': '162.19.91.238', 'port': 3479}}, {'mode': 1, 'host': 'stun.logic.ky', 'primary': {'ip': '216.144.89.2', 'port': 3478}, 'secondary': {'ip': '216.144.89.3', 'port': 3482}}, {'mode': 1, 'host': 'stun.hot-chilli.net', 'primary': {'ip': '49.12.125.53', 'port': 3478}, 'secondary': {'ip': '49.12.125.24', 'port': 3479}}, {'mode': 1, 'host': 'stun.eoni.com', 'primary': {'ip': '216.228.192.76', 'port': 3478}, 'secondary': {'ip': '216.228.192.77', 'port': 3479}}, {'mode': 1, 'host': 'stun.teamfon.de', 'primary': {'ip': '212.29.18.56', 'port': 3478}, 'secondary': {'ip': '212.29.18.57', 'port': 3479}}, {'mode': 1, 'host': 'stun.megatel.si', 'primary': {'ip': '91.199.161.149', 'port': 3478}, 'secondary': {'ip': '91.199.161.158', 'port': 3479}}, {'mode': 1, 'host': 'stun.aeta.com', 'primary': {'ip': '85.214.119.212', 'port': 3478}, 'secondary': {'ip': '81.169.176.31', 'port': 3479}}, {'mode': 1, 'host': 'stun.srce.hr', 'primary': {'ip': '161.53.1.100', 'port': 3478}, 'secondary': {'ip': '161.53.1.101', 'port': 3479}}, {'mode': 1, 'host': 'stun.3wayint.com', 'primary': {'ip': '95.216.145.84', 'port': 3478}, 'secondary': {'ip': '95.216.176.73', 'port': 3479}}, {'mode': 1, 'host': 'stunserver.stunprotocol.org', 'primary': {'ip': '3.132.228.249', 'port': 3478}, 'secondary': {'ip': '3.135.212.85', 'port': 3479}}, {'mode': 1, 'host': 'stun.next-gen.ro', 'primary': {'ip': '193.16.148.245', 'port': 3478}, 'secondary': {'ip': '193.16.148.244', 'port': 3479}}, {'mode': 1, 'host': 'stun.easter-eggs.com', 'primary': {'ip': '37.9.136.90', 'port': 3478}, 'secondary': {'ip': '37.9.136.91', 'port': 3479}}, {'mode': 1, 'host': 'stun.syrex.co.za', 'primary': {'ip': '41.79.23.6', 'port': 3478}, 'secondary': {'ip': '41.79.23.24', 'port': 3479}}, {'mode': 1, 'host': 'stun.sipthor.net', 'primary': {'ip': '85.17.186.7', 'port': 3478}, 'secondary': {'ip': '85.17.186.12', 'port': 3479}}, {'mode': 1, 'host': 'stun.syncthing.net', 'primary': {'ip': '198.211.120.59', 'port': 3478}, 'secondary': {'ip': '188.166.128.84', 'port': 3479}}, {'mode': 1, 'host': 'stun.qcol.net', 'primary': {'ip': '69.89.160.30', 'port': 3478}, 'secondary': {'ip': '69.89.160.31', 'port': 3479}}, {'mode': 1, 'host': 'stun.miwifi.com', 'primary': {'ip': '111.206.174.3', 'port': 3478}, 'secondary': {'ip': '111.206.174.2', 'port': 3479}}, {'mode': 1, 'host': 'stun.meowsbox.com', 'primary': {'ip': '173.255.213.166', 'port': 3478}, 'secondary': {'ip': '45.56.86.112', 'port': 3479}}, {'mode': 1, 'host': 'stun.axeos.nl', 'primary': {'ip': '185.67.224.59', 'port': 3478}, 'secondary': {'ip': '185.67.224.58', 'port': 3479}}, {'mode': 1, 'host': 'stun.mywatson.it', 'primary': {'ip': '92.222.127.114', 'port': 3478}, 'secondary': {'ip': '92.222.127.116', 'port': 5060}}, {'mode': 1, 'host': 'stun.fairytel.at', 'primary': {'ip': '77.237.51.83', 'port': 3478}, 'secondary': {'ip': '77.237.51.84', 'port': 3479}}, {'mode': 1, 'host': 'webrtc.free-solutions.org', 'primary': {'ip': '94.103.99.223', 'port': 3478}, 'secondary': {'ip': '94.103.99.224', 'port': 3479}}, {'mode': 1, 'host': 'stun.voztele.com', 'primary': {'ip': '193.22.119.20', 'port': 3478}, 'secondary': {'ip': '193.22.119.3', 'port': 3479}}, {'mode': 1, 'host': 'stun.t-online.de', 'primary': {'ip': '217.0.12.1', 'port': 3478}, 'secondary': {'ip': '217.0.12.2', 'port': 3479}}, {'mode': 1, 'host': 'stun.sipgate.net', 'primary': {'ip': '3.33.249.248', 'port': 3478}, 'secondary': {'ip': '15.197.250.192', 'port': 3479}}, {'mode': 1, 'host': 'stun.deepfinesse.com', 'primary': {'ip': '157.22.130.80', 'port': 3478}, 'secondary': {'ip': '157.22.130.81', 'port': 3479}}, {'mode': 1, 'host': 'stun.jabbim.cz', 'primary': {'ip': '88.86.102.51', 'port': 3478}, 'secondary': {'ip': '88.86.102.52', 'port': 3479}}, {'mode': 1, 'host': 'stun.sky.od.ua', 'primary': {'ip': '81.25.228.2', 'port': 3478}, 'secondary': {'ip': '81.25.228.3', 'port': 3479}}, {'mode': 1, 'host': 'stun.voicetech.se', 'primary': {'ip': '91.205.60.185', 'port': 3478}, 'secondary': {'ip': '91.205.60.139', 'port': 3479}}, {'mode': 1, 'host': 'stun.tng.de', 'primary': {'ip': '82.97.157.254', 'port': 3478}, 'secondary': {'ip': '82.97.157.252', 'port': 3479}}, {'mode': 1, 'host': 'stun.acrobits.cz', 'primary': {'ip': '85.17.88.164', 'port': 3478}, 'secondary': {'ip': '85.17.88.165', 'port': 3479}}, {'mode': 1, 'host': 'stun.leucotron.com.br', 'primary': {'ip': '177.66.4.31', 'port': 3478}, 'secondary': {'ip': '177.66.4.32', 'port': 3479}}, {'mode': 1, 'host': 'stun.imafex.sk', 'primary': {'ip': '188.123.97.201', 'port': 3478}, 'secondary': {'ip': '188.123.97.202', 'port': 3479}}, {'mode': 1, 'host': 'stun.gigaset.net', 'primary': {'ip': '81.173.115.217', 'port': 3478}, 'secondary': {'ip': '157.97.108.95', 'port': 3479}}, {'mode': 1, 'host': '192.76.120.66', 'primary': {'ip': '192.76.120.66', 'port': 3478}, 'secondary': {'ip': '64.16.250.34', 'port': 3479}}, {'mode': 1, 'host': 'stun.aaisp.co.uk', 'primary': {'ip': '81.187.30.115', 'port': 3478}, 'secondary': {'ip': '81.187.30.124', 'port': 3479}}, {'mode': 1, 'host': 'stun.cablenet-as.net', 'primary': {'ip': '213.140.209.236', 'port': 3478}, 'secondary': {'ip': '213.140.209.237', 'port': 3479}}, {'mode': 1, 'host': 'stun.taxsee.com', 'primary': {'ip': '195.209.116.72', 'port': 3478}, 'secondary': {'ip': '195.209.116.73', 'port': 3479}}, {'mode': 1, 'host': 'stun.hide.me', 'primary': {'ip': '209.250.250.224', 'port': 3478}, 'secondary': {'ip': '209.250.247.151', 'port': 3479}}, {'mode': 1, 'host': 'stun.alphacron.de', 'primary': {'ip': '193.22.2.248', 'port': 3478}, 'secondary': {'ip': '193.22.2.249', 'port': 3479}}, {'mode': 1, 'host': 'stun.wxnz.net', 'primary': {'ip': '182.154.16.7', 'port': 3478}, 'secondary': {'ip': '182.154.16.8', 'port': 3479}}, {'mode': 1, 'host': 'stun.medvc.eu', 'primary': {'ip': '150.254.161.60', 'port': 3478}, 'secondary': {'ip': '150.254.161.48', 'port': 3479}}, {'mode': 1, 'host': 'stun.vadacom.co.nz', 'primary': {'ip': '103.124.135.6', 'port': 3478}, 'secondary': {'ip': '103.124.135.7', 'port': 3479}}, {'mode': 1, 'host': 'stun.voip.aebc.com', 'primary': {'ip': '66.51.128.11', 'port': 3478}, 'secondary': {'ip': '66.51.128.12', 'port': 3479}}, {'mode': 1, 'host': 'stun.futurasp.es', 'primary': {'ip': '178.33.166.29', 'port': 3478}, 'secondary': {'ip': '91.121.210.25', 'port': 3479}}, {'mode': 1, 'host': 'stun.epygi.com', 'primary': {'ip': '23.253.102.137', 'port': 3478}, 'secondary': {'ip': '162.242.144.6', 'port': 3479}}, {'mode': 1, 'host': 'stun.rolmail.net', 'primary': {'ip': '195.254.254.20', 'port': 3478}, 'secondary': {'ip': '195.254.254.4', 'port': 3479}}, {'mode': 1, 'host': 'stun.solcon.nl', 'primary': {'ip': '212.45.38.40', 'port': 3478}, 'secondary': {'ip': '212.45.38.41', 'port': 3479}}, {'mode': 1, 'host': 'stun.fathomvoice.com', 'primary': {'ip': '54.173.127.160', 'port': 3478}, 'secondary': {'ip': '54.173.127.161', 'port': 3479}}, {'mode': 1, 'host': 'stun.webmatrix.com.br', 'primary': {'ip': '192.99.194.90', 'port': 3478}, 'secondary': {'ip': '192.99.194.91', 'port': 3479}}], IP6: [{'mode': 1, 'host': 'stun2.p2pd.net', 'primary': {'ip': '2a01:4f8:10a:3ce0::2', 'port': 34780}, 'secondary': {'ip': "2a01:4f8:10a:3ce0::3", 'port': 34790}}, {'mode': 1, 'host': 'stun.hot-chilli.net', 'primary': {'ip': '2a01:4f8:242:56ca::2', 'port': 3478}, 'secondary': {'ip': '2a01:4f8:242:56ca::3', 'port': 3479}}, {'mode': 1, 'host': 'stunserver.stunprotocol.org', 'primary': {'ip': '2600:1f16:8c5:101:80b:b58b:828:8df4', 'port': 3478}, 'secondary': {'ip': '2600:1f16:8c5:101:6388:1fb6:8b7e:c2', 'port': 3479}}]}, TCP: {IP4: [{'mode': 1, 'host': 'stun2.p2pd.net', 'primary': {'ip': '88.99.211.211', 'port': 34780}, 'secondary': {'ip': "88.99.211.216", 'port': 34790}}, {'mode': 1, 'host': 'stunserver.stunprotocol.org', 'primary': {'ip': '3.132.228.249', 'port': 3478}, 'secondary': {'ip': '3.135.212.85', 'port': 3479}}], IP6: [{'mode': 1, 'host': 'stun2.p2pd.net', 'primary': {'ip': '2a01:4f8:10a:3ce0::2', 'port': 34780}, 'secondary': {'ip': "2a01:4f8:10a:3ce0::3", 'port': 34790}}, {'mode': 1, 'host': 'stunserver.stunprotocol.org', 'primary': {'ip': '2600:1f16:8c5:101:80b:b58b:828:8df4', 'port': 3478}, 'secondary': {'ip': '2600:1f16:8c5:101:6388:1fb6:8b7e:c2', 'port': 3479}}]}}

MQTT_SERVERS = [
    {
        "host": "mqtt.eclipseprojects.io",
        "port": 1883,
        IP4: "137.135.83.217",
        IP6: None,
    },
    {
        "host": "broker.mqttdashboard.com",
        "port": 1883,
        IP4: "3.72.227.226",
        IP6: None,
    },
    {
        "host": "test.mosquitto.org",
        "port": 1883,
        IP4: "91.121.93.94",
        IP6: "2001:41d0:1:925e::1",
    },
    {
        "host": "broker.emqx.io",
        "port": 1883,
        IP4: "44.232.241.40",
        IP6: None,
    },
    {
        "host": "broker.hivemq.com",
        "port": 1883,
        IP4: "3.74.214.208",
        IP6: None,
    },
    {
        "host": "mqtt1.p2pd.net",
        "port": 1883,
        IP4: "158.69.27.176",
        IP6: "2607:5300:60:80b0::1",
    },
    {
        "host": "mqtt2.p2pd.net",
        "port": 1883,
        IP4: "88.99.211.211",
        IP6: "2a01:4f8:10a:3ce0::2",
    },
]

# Port is ignored for now.
NTP_SERVERS = [
    {
        "host": "time.google.com",
        "port": 123,
        IP4: "216.239.35.4",
        IP6: "2001:4860:4806::"
    },
    {
        "host": "pool.ntp.org",
        "port": 123,
        IP4: "162.159.200.123",
        IP6: None
    },
    {
        "host": "time.cloudflare.com",
        "port": 123,
        IP4: "162.159.200.123",
        IP6: "2606:4700:f1::1"
    },
    {
        "host": "time.facebook.com",
        "port": 123,
        IP4: "129.134.26.123",
        IP6: "2a03:2880:ff0a::123"
    },
    {
        "host": "time.windows.com",
        "port": 123,
        IP4: "52.148.114.188",
        IP6: None
    },
    {
        "host": "time.apple.com",
        "port": 123,
        IP4: "17.253.66.45",
        IP6: "2403:300:a08:3000::31"
    },
    {
        "host": "time.nist.gov",
        "port": 123,
        IP4: "129.6.15.27",
        IP6: "2610:20:6f97:97::4"
    },
    {
        "host": "utcnist.colorado.edu",
        "port": 123,
        IP4: "128.138.140.44",
        IP6: None
    },
    {
        "host": "ntp2.net.berkeley.edu",
        "port": 123,
        IP4: "169.229.128.142",
        IP6: "2607:f140:ffff:8000:0:8003:0:a"
    },
    {
        "host": "time.mit.edu",
        "port": 123,
        IP4: "18.7.33.13",
        IP6: None
    },
    {
        "host": "time.stanford.edu",
        "port": 123,
        IP4: "171.64.7.67",
        IP6: None
    },
    {
        "host": "ntp.nict.jp",
        "port": 123,
        IP4: "133.243.238.243",
        IP6: "2001:df0:232:eea0::fff4"
    },
    {
        "host": "ntp1.hetzner.de",
        "port": 123,
        IP4: "213.239.239.164",
        IP6: "2a01:4f8:0:a0a1::2:1"
    },
    {
        "host": "ntp.ripe.net",
        "port": 123,
        IP4: "193.0.0.229",
        IP6: "2001:67c:2e8:14:ffff::229"
    },
    {
        "host": "clock.isc.org",
        "port": 123,
        IP4: "64.62.194.188",
        IP6: "2001:470:1:b07::123:2000"
    },
    {
        "host": "ntp.ntsc.ac.cn",
        "port": 123,
        IP4: "114.118.7.163",
        IP6: None
    },
    {
        "host": "1.amazon.pool.ntp.org",
        "port": 123,
        IP4: "103.152.64.212",
        IP6: None
    },
    {
        "host": "0.android.pool.ntp.org",
        "port": 123,
        IP4: "159.196.44.158",
        IP6: None
    },
    {
        "host": "0.pfsense.pool.ntp.org",
        "port": 123,
        IP4: "27.124.125.250",
        IP6: None
    },
    {
        "host": "0.debian.pool.ntp.org",
        "port": 123,
        IP4: "139.180.160.82",
        IP6: None
    },
    {
        "host": "0.gentoo.pool.ntp.org",
        "port": 123,
        IP4: "14.202.65.230",
        IP6: None
    },
    {
        "host": "0.arch.pool.ntp.org",
        "port": 123,
        IP4: "110.232.114.22",
        IP6: None
    },
    {
        "host": "0.fedora.pool.ntp.org",
        "port": 123,
        IP4: "139.180.160.82",
        IP6: None
    }
]


"""
These are TURN servers used as fallbacks (if configured by a P2P pipe.)
They are not used for 'p2p connections' by default due to their use of
UDP and unordered delivery but it can be enabled by adding 'P2P_RELAY'
to the strategies list in open_pipe().

Please do not abuse these servers. If you need proxies use Shodan or Google
to find them. If you're looking for a TURN server for your production
Web-RTC application you should be running your own infrastructure and not
rely on public infrastructure (like these) which will be unreliable anyway.

Testing:

It seems that recent versions of Coturn no longer allow you to relay data
from your own address back to yourself. This makes sense -- after-all
-- TURN is used to relay endpoints and it doesn't make sense to be
relaying information back to yourself. But it has meant to designing a
new way to test these relay addresses that relies on an external server
to send packets to the relay address.

Note:
-----------------------------------------------------------------------
These servers don't seem to return a reply on the relay address.
Most likely this is due to the server using a reply port that is different
to the relay port and TURN server port. This will effect most types of 
NATs, unfortunately. So they've been removed from the server list for now.

{
    "host": b"webrtc.free-solutions.org",
    "port": 3478,
    "afs": [IP4],
    "ip": {
        IP4: "94.103.99.223"
    },
    "user": b"tatafutz",
    "pass": b"turnuser",
    "realm": None
},


{
    "host": b"openrelay.metered.ca",
    "port": 80,
    "afs": [IP4],
    "
    "user": b"openrelayproject",
    "pass": b"openrelayproject",
    "realm": None
}
    
    {
        "host": b"p2pd.net",
        "port": 3478,
        "afs": [IP4, IP6],
        "user": None,
        "pass": None,
        "realm": b"p2pd.net"
    },
"""
"""
todo: update this
{
    "host": b"us0.turn.peerjs.com",
    "port": 3478,
    "afs": [IP4, IP6],
    "user": b"peerjs",
    "pass": b"peerjsp",
    "realm": None
},
"""

TURN_SERVERS = [
    {
        "host": "turn.threema.ch",
        "port": 443,
        "afs": [IP4],
        IP4: "185.88.236.76",
        IP6: None,
        "user": "threema-angular",
        "pass": "Uv0LcCq3kyx6EiRwQW5jVigkhzbp70CjN2CJqzmRxG3UGIdJHSJV6tpo7Gj7YnGB",
        "realm": None
    },
    {
        "host": "turn.obs.ninja",
        "port": 443,
        "afs": [IP4, IP6],
        IP4: "51.195.101.185",
        IP6: "2001:41d0:701:1100::62e5",
        "user": "steve",
        "pass": "setupYourOwnPlease",
        "realm": None
    },
    {
        "host": "stun.contus.us",
        "port": 3478,
        "afs": [IP4],
        IP4: "152.67.9.43",
        IP6: None,
        "user": "contus",
        "pass": "SAE@admin",
        "realm": None
    },
    {
        "host": "turn.quickblox.com",
        "port": 3478,
        "afs": [IP4],
        IP4: "103.253.147.231",
        IP6: None,
        "user": "quickblox",
        "pass": "baccb97ba2d92d71e26eb9886da5f1e0",
        "realm": None
    },
    {
        "host": "turn1.p2pd.net",
        "port": 3478,
        "afs": [IP4, IP6],
        IP4: "158.69.27.176",
        IP6: "2607:5300:60:80b0::1",
        "user": "",
        "pass": "",
        "realm": None
    },
    {
        "host": "turn2.p2pd.net",
        "port": 3478,
        "afs": [IP4, IP6],
        IP4: "88.99.211.211",
        IP6: "2a01:4f8:10a:3ce0::2",
        "user": "",
        "pass": "",
        "realm": None
    },
]