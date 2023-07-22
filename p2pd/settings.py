import socket
IP4 = socket.AF_INET
IP6 = socket.AF_INET6

ENABLE_STUN = True
ENABLE_UDP = True
P2PD_TEST_INFRASTRUCTURE = False

PDNS_REGISTRARS = {
    "000webhost": "http://net-debug.000webhostapp.com/name_store.php"
}

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
STUNT_SERVERS = {
    IP4: [
        {
            "host": "stunserver.stunprotocol.org",
            "primary": {"ip": "3.132.228.249", "port": 3478},
            "secondary": {"ip": "3.135.212.85", "port": 3479},
        },
        {
            "host": "stun.hot-chilli.net",
            "primary": {"ip": "49.12.125.53", "port": 3478},
            "secondary": {"ip": None, "port": None},
        },
        {
            "host": "stun.voip.blackberry.com",
            "primary": {"ip": "20.15.169.8", "port": 3478},
            "secondary": {"ip": None, "port": None},
        },
        {
            "host": "webrtc.free-solutions.org",
            "primary": {"ip": "94.103.99.223", "port": 3478},
            "secondary": {"ip": None, "port": None},
        },
        {
            "host": "stun.siptrunk.com",
            "primary": {"ip": "23.21.92.55", "port": 3478},
            "secondary": {"ip": None, "port": None},
        },
    ],
    IP6: [
        {
            "host": "stunserver.stunprotocol.org",
            "primary": {"ip": "2600:1f16:8c5:101:80b:b58b:828:8df4", "port": 3478},
            "secondary": {"ip": "2600:1f16:08c5:0101:6388:1fb6:8b7e:00c2", "port": 3479},
        }
    ]
}



STUND_SERVERS = {
    IP4: [
        {
            "host": "stun.voipcheap.co.uk",
            "primary": {"ip": "77.72.169.211", "port": 3478},
            "secondary": {"ip": "77.72.169.210", "port": 3479},
        },
        {
            "host": "stunserver.stunprotocol.org",
            "primary": {"ip": "3.132.228.249", "port": 3478},
            "secondary": {"ip": "3.135.212.85", "port": 3479},
        },
        {
            "host": "stun.usfamily.net",
            "primary": {"ip": "64.131.63.216", "port": 3478},
            "secondary": {"ip": "64.131.63.240", "port": 3479},
        },
        {
            "host": "stun.ozekiphone.com",
            "primary": {"ip": "216.93.246.18", "port": 3478},
            "secondary": {"ip": "216.93.246.15", "port": 3479},
        },
        {
            "host": "stun.voipwise.com",
            "primary": {"ip": "77.72.169.213", "port": 3478},
            "secondary": {"ip": "77.72.169.212", "port": 3479},
        },
        {
            "host": "stun.mit.de",
            "primary": {"ip": "62.96.96.137", "port": 3478},
            "secondary": {"ip": "62.96.96.138", "port": 3479},
        },
        {
            "host": "stun.hot-chilli.net",
            "primary": {"ip": "49.12.125.53", "port": 3478},
            "secondary": {"ip": "49.12.125.24", "port": 3479},
        },
        {
            "host": "stun.cheapvoip.com",
            "primary": {"ip": "77.72.169.212", "port": 3478},
            "secondary": {"ip": "77.72.169.213", "port": 3479},
        },
        {
            "host": "webrtc.free-solutions.org",
            "primary": {"ip": "94.103.99.223", "port": 3478},
            "secondary": {"ip": "94.103.99.224", "port": 3479},
        },
        {
            "host": "stun.t-online.de",
            "primary": {"ip": "217.0.12.17", "port": 3478},
            "secondary": {"ip": "217.0.12.18", "port": 3479},
        },
        {
            "host": "stun.sipgate.net",
            "primary": {"ip": "217.10.68.152", "port": 3478},
            "secondary": {"ip": "217.116.122.136", "port": 3479},
        },
        {
            "host": "stun.voip.aebc.com",
            "primary": {"ip": "66.51.128.11", "port": 3478},
            "secondary": {"ip": "66.51.128.12", "port": 3479},
        },
        {
            "host": "stun.callwithus.com",
            "primary": {"ip": "158.69.57.20", "port": 3478},
            "secondary": {"ip": "149.56.23.84", "port": 3479},
        },
        {
            "host": "stun.counterpath.net",
            "primary": {"ip": "216.93.246.18", "port": 3478},
            "secondary": {"ip": "216.93.246.15", "port": 3479},
        },
        {
            "host": "stun.ekiga.net",
            "primary": {"ip": "216.93.246.18", "port": 3478},
            "secondary": {"ip": "216.93.246.15", "port": 3479},
        },
        {
            "host": "stun.internetcalls.com",
            "primary": {"ip": "77.72.169.212", "port": 3478},
            "secondary": {"ip": "77.72.169.213", "port": 3479},
        },
        {
            "host": "stun.voipbuster.com",
            "primary": {"ip": "77.72.169.212", "port": 3478},
            "secondary": {"ip": "77.72.169.213", "port": 3479},
        },
        {
            "host": "stun.12voip.com",
            "primary": {"ip": "77.72.169.212", "port": 3478},
            "secondary": {"ip": "77.72.169.213", "port": 3479},
        },
        {
            "host": "stun.freecall.com",
            "primary": {"ip": "77.72.169.211", "port": 3478},
            "secondary": {"ip": "77.72.169.210", "port": 3479},
        },
        {
            "host": "stun.nexxtmobile.de",
            "primary": {"ip": "5.9.87.18", "port": 3478},
            "secondary": {"ip": "136.243.205.11", "port": 3479},
        },
        {
            "host": "stun.siptrunk.com",
            "primary": {"ip": "23.21.92.55", "port": 3478},
            "secondary": {"ip": "34.205.214.84", "port": 3479},
        },
    ],
    IP6: [
        {
            "host": "stunserver.stunprotocol.org",
            "primary": {"ip": "2600:1f16:8c5:101:80b:b58b:828:8df4", "port": 3478},
            "secondary": {"ip": "2600:1f16:08c5:0101:6388:1fb6:8b7e:00c2", "port": 3479},
        },
        {
            "host": "stun.hot-chilli.net",
            "primary": {"ip": "2a01:4f8:242:56ca::2", "port": 3478},
            "secondary": {"ip": "2a01:04f8:0242:56ca:0000:0000:0000:0003", "port": 3479},
        },
        {
            "host": "stun.simlar.org",
            "primary": {"ip": "2a02:f98:0:50:2ff:23ff:fe42:1b23", "port": 3478},
            "secondary": {"ip": "2a02:0f98:0000:0050:02ff:23ff:fe42:1b24", "port": 3479},
        },
    ]
}

"""
stun_test = [["stunserver.stunprotocol.org", 3478]]
STUNT_SERVERS = { IP4: stun_test, IP6: stun_test }
STUND_SERVERS = STUNT_SERVERS
"""

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
        "host": b"us-0.turn.peerjs.com",
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


