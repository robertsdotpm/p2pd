import socket
IP4 = socket.AF_INET
IP6 = socket.AF_INET6

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
            "ip": "2a01:04f8:010a:3ce0:0000:0000:0000:0002",
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


NET_DEBUG_PROVIDERS = {
    IP4: [
        "http://net-debug.000webhostapp.com/net_debug.php"
    ],
    IP6: [
        "http://net-debug.000webhostapp.com/net_debug.php"
    ]
}

NAME_STORE_PROVIDERS = [
    {
        "afs": [IP4, IP6],
        "url": "http://net-debug.000webhostapp.com/name_store.php"
    }
]

"""
Used to lookup what a nodes IP is and do NAT enumeration.
Supports IPv6 / IPv4 / TCP / UDP -- change IP and port requests.

STUNT servers support TCP.
STUND servers support UDP.
"""
STUNT_SERVERS = {IP4: [{'host': 'stun1.p2pd.net', 'primary': {'ip': '88.99.211.216', 'port': 3478}, 'secondary': {'ip': '88.99.211.211', 'port': 3479}}, {'host': 'stun2.p2pd.net', 'primary': {'ip': '158.69.27.176', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'host': 'stun.sipnet.net', 'primary': {'ip': '212.53.40.43', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'host': 'stunserver.stunprotocol.org', 'primary': {'ip': '3.132.228.249', 'port': 3478}, 'secondary': {'ip': '3.135.212.85', 'port': 3479}}], IP6: [{'host': 'stun1.p2pd.net', 'primary': {'ip': '2a01:04f8:010a:3ce0:0000:0000:0000:0002', 'port': 3478}, 'secondary': {'ip': '2a01:04f8:010a:3ce0:0000:0000:0000:0003', 'port': 3479}}, {'host': 'stun2.p2pd.net', 'primary': {'ip': '2607:5300:0060:80b0:0000:0000:0000:0001', 'port': 3478}, 'secondary': {'ip': None, 'port': None}}, {'host': 'stunserver.stunprotocol.org', 'primary': {'ip': '2600:1f16:08c5:0101:080b:b58b:0828:8df4', 'port': 3478}, 'secondary': {'ip': '2600:1f16:08c5:0101:6388:1fb6:8b7e:00c2', 'port': 3479}}]}




STUND_SERVERS = {IP4: [{'host': 'stun1.p2pd.net', 'primary': {'ip': '88.99.211.216', 'port': 3478}, 'secondary': {'ip': '88.99.211.211', 'port': 3479}}, {'host': 'stun.voztele.com', 'primary': {'ip': '193.22.119.20', 'port': 3478}, 'secondary': {'ip': '193.22.119.3', 'port': 3479}}, {'host': 'stun.commpeak.com', 'primary': {'ip': '85.17.88.164', 'port': 3478}, 'secondary': {'ip': '85.17.88.165', 'port': 3479}}, {'host': 'stun.tel.lu', 'primary': {'ip': '85.93.219.114', 'port': 3478}, 'secondary': {'ip': '85.93.219.115', 'port': 3479}}, {'host': 'stun.gmx.net', 'primary': {'ip': '212.227.67.33', 'port': 3478}, 'secondary': {'ip': '212.227.67.34', 'port': 3479}}, {'host': 'stun.voipwise.com', 'primary': {'ip': '77.72.169.213', 'port': 3478}, 'secondary': {'ip': '77.72.169.212', 'port': 3479}}, {'host': 'stun.zoiper.com', 'primary': {'ip': '185.117.83.50', 'port': 3478}, 'secondary': {'ip': '185.117.83.51', 'port': 3479}}, {'host': 'stun.sigmavoip.com', 'primary': {'ip': '216.93.246.18', 'port': 3478}, 'secondary': {'ip': '216.93.246.15', 'port': 3479}}, {'host': 'stun.miwifi.com', 'primary': {'ip': '111.206.174.3', 'port': 3478}, 'secondary': {'ip': '111.206.174.2', 'port': 3479}}, {'host': 'stun.srce.hr', 'primary': {'ip': '161.53.1.100', 'port': 3478}, 'secondary': {'ip': '161.53.1.101', 'port': 3479}}, {'host': 'stun.rynga.com', 'primary': {'ip': '77.72.169.210', 'port': 3478}, 'secondary': {'ip': '77.72.169.211', 'port': 3479}}, {'host': 'stunserver.stunprotocol.org', 'primary': {'ip': '3.132.228.249', 'port': 3478}, 'secondary': {'ip': '3.135.212.85', 'port': 3479}}, {'host': 'stun.twt.it', 'primary': {'ip': '82.113.193.63', 'port': 3478}, 'secondary': {'ip': '82.113.193.67', 'port': 3479}}, {'host': 'stun.aa.net.uk', 'primary': {'ip': '81.187.30.115', 'port': 3478}, 'secondary': {'ip': '81.187.30.124', 'port': 3479}}, {'host': 'stun.solcon.nl', 'primary': {'ip': '212.45.38.40', 'port': 3478}, 'secondary': {'ip': '212.45.38.41', 'port': 3479}}, {'host': 'stun.voip.aebc.com', 'primary': {'ip': '66.51.128.11', 'port': 3478}, 'secondary': {'ip': '66.51.128.12', 'port': 3479}}, {'host': 'stun.usfamily.net', 'primary': {'ip': '64.131.63.217', 'port': 3478}, 'secondary': {'ip': '64.131.63.241', 'port': 3479}}, {'host': 'stun.aeta.com', 'primary': {'ip': '85.214.119.212', 'port': 3478}, 'secondary': {'ip': '81.169.176.31', 'port': 3479}}, {'host': 'stun.infra.net', 'primary': {'ip': '195.242.206.1', 'port': 3478}, 'secondary': {'ip': '195.242.206.28', 'port': 3479}}, {'host': 'stun.mywatson.it', 'primary': {'ip': '92.222.127.114', 'port': 3478}, 'secondary': {'ip': '92.222.127.116', 'port': 5060}}, {'host': 'stun.t-online.de', 'primary': {'ip': '217.0.11.225', 'port': 3478}, 'secondary': {'ip': '217.0.11.226', 'port': 3479}}, {'host': 'stun.rolmail.net', 'primary': {'ip': '195.254.254.20', 'port': 3478}, 'secondary': {'ip': '195.254.254.4', 'port': 3479}}, {'host': 'stun.halonet.pl', 'primary': {'ip': '193.43.148.37', 'port': 3478}, 'secondary': {'ip': '193.43.148.38', 'port': 3479}}, {'host': 'stun.cablenet-as.net', 'primary': {'ip': '213.140.209.236', 'port': 3478}, 'secondary': {'ip': '213.140.209.237', 'port': 3479}}, {'host': 'stun.voip.eutelia.it', 'primary': {'ip': '83.211.9.232', 'port': 3478}, 'secondary': {'ip': '83.211.9.235', 'port': 3479}}, {'host': 'stun.uls.co.za', 'primary': {'ip': '154.73.34.8', 'port': 3478}, 'secondary': {'ip': '154.73.34.9', 'port': 3479}}, {'host': 'stun.tng.de', 'primary': {'ip': '82.97.157.254', 'port': 3478}, 'secondary': {'ip': '82.97.157.252', 'port': 3479}}, {'host': 'stun.hoiio.com', 'primary': {'ip': '52.76.91.67', 'port': 3478}, 'secondary': {'ip': '52.74.211.13', 'port': 3479}}, {'host': 'stun.nexxtmobile.de', 'primary': {'ip': '5.9.87.18', 'port': 3478}, 'secondary': {'ip': '136.243.205.11', 'port': 3479}}, {'host': 'stun.vivox.com', 'primary': {'ip': '70.42.198.30', 'port': 3478}, 'secondary': {'ip': '70.42.198.16', 'port': 3479}}], IP6: [{'host': 'stun1.p2pd.net', 'primary': {'ip': '2a01:04f8:010a:3ce0:0000:0000:0000:0002', 'port': 3478}, 'secondary': {'ip': '2a01:04f8:010a:3ce0:0000:0000:0000:0003', 'port': 3479}}, {'host': 'stunserver.stunprotocol.org', 'primary': {'ip': '2600:1f16:08c5:0101:080b:b58b:0828:8df4', 'port': 3478}, 'secondary': {'ip': '2600:1f16:08c5:0101:6388:1fb6:8b7e:00c2', 'port': 3479}}]}

# The main server used to exchange 'signaling' messages.
# These are messages that help nodes create connections.
MQTT_SERVERS = [
    # [b"p2pd.net", 1883],
    [b"mqtt.eclipseprojects.io", 1883],
    [b"broker.mqttdashboard.com", 1883],
    [b"test.mosquitto.org", 1883],
    [b"broker.emqx.io", 1883],
    [b"broker.hivemq.com", 1883],
]

# Port is ignored for now.
NTP_SERVERS = [
    ["time.google.com", 123],
    ["pool.ntp.org", 123],
    ["time.cloudflare.com", 123],
    ["time.facebook.com", 123],
    ["time.windows.com", 123],
    ["time.apple.com", 123],
    ["time.nist.gov", 123],
    ["utcnist.colorado.edu", 123],
    ["ntp2.net.berkeley.edu", 123],
    ["time.mit.edu", 123],
    ["time.stanford.edu", 123],
    ["ntp.nict.jp", 123],
    ["ntp1.hetzner.de", 123],
    ["ntp.ripe.net", 123],
    ["clock.isc.org", 123],
    ["ntp.ntsc.ac.cn", 123],
    ["1.amazon.pool.ntp.org", 123],
    ["0.android.pool.ntp.org", 123],
    ["0.pfsense.pool.ntp.org", 123],
    ["0.debian.pool.ntp.org", 123],
    ["0.gentoo.pool.ntp.org", 123],
    ["0.arch.pool.ntp.org", 123],
    ["0.fedora.pool.ntp.org", 123],
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
    "user": b"tatafutz",
    "pass": b"turnuser",
    "realm": None
},


{
    "host": b"openrelay.metered.ca",
    "port": 80,
    "afs": [IP4],
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
TURN_SERVERS = [
    {
        "host": b"peerjs.com",
        "port": 3478,
        "afs": [IP4, IP6],
        "user": b"peerjs",
        "pass": b"peerjsp",
        "realm": None
    },
    {
        "host": b"turn.obs.ninja",
        "port": 443,
        "afs": [IP4, IP6],
        "user": b"steve",
        "pass": b"setupYourOwnPlease",
        "realm": None
    },
    {
        "host": b"stun.contus.us",
        "port": 3478,
        "afs": [IP4],
        "user": b"contus",
        "pass": b"SAE@admin",
        "realm": None
    },
    {
        "host": b"turn.quickblox.com",
        "port": 3478,
        "afs": [IP4],
        "user": b"quickblox",
        "pass": b"baccb97ba2d92d71e26eb9886da5f1e0",
        "realm": None
    },
    {
        "host": b"turn.threema.ch",
        "port": 443,
        "afs": [IP4],
        "user": b"threema-angular",
        "pass": b"Uv0LcCq3kyx6EiRwQW5jVigkhzbp70CjN2CJqzmRxG3UGIdJHSJV6tpo7Gj7YnGB",
        "realm": None
    },
]


