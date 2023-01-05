from .net import IP4, IP6

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


"""
Used to lookup what a nodes IP is and do NAT enumeration.
Supports IPv6 / IPv4 / TCP / UDP -- change IP and port requests.

STUNT servers support TCP.
STUND servers support UDP.
"""
STUNT_SERVERS = {
    # Try to use the oldest servers around.
    # Presumably these are the most reliable.
    IP4: [
        ['p2pd.net', 34780],
        ['stun.sipnet.ru', 3478], # 19 Sept 2005
        ['stun.1cbit.ru', 3478], # 30 Aug 2017
        ['stun.acronis.com', 3478], # 30 Aug 2017
        ['stun.bitburger.de', 3478], # 30 Aug 2017
        ['stun.innovaphone.com', 3478], # 30 Aug 2017
        ['stun.onthenet.com.au', 3478], # 30 Aug 2017
        ['stun.zepter.ru', 3478], # 30 Aug 2017
        ['stun.stunprotocol.org', 3478], # 19 Sept 2005
        ['stun.siedle.com', 3478], # 12 Apr 2018
    ],

    # There's basically none unfortunately.
    IP6: [
        ['p2pd.net', 34780],
        ['stun.stunprotocol.org', 3478],
    ]
}

STUND_SERVERS = {
    # A few aged, OG stun servers/
    IP4: [
        ['p2pd.net', 34780],
        ['stun.stunprotocol.org', 3478],
        ['stun.voipcheap.co.uk', 3478], # 19 Sept 2005
        ['stun.usfamily.net', 3478], # 19 Sept 2005
        ['stun.ozekiphone.com', 3478], # 19 Sept 2005
        ['stun.voipwise.com', 3478], # 19 Sept 2005
        ['stun.mit.de', 3478], # 19 Sept 2005
        ['stun.hot-chilli.net', 3478], # 14 Aug 2012
        ['stun.counterpath.com', 3478], # 19 Sept 2005
        ['stun.cheapvoip.com', 3478], # 19 Sept 2005
        ['stun.voip.blackberry.com', 3478], # 19 Sept 2005
        ['webrtc.free-solutions.org', 3478], # 17 Nov 2008
        ['stun.t-online.de', 3478], # 12 Apr 2004
        ['stun.sipgate.net', 3478], # 19 Sept 2005
        ['stun.voip.aebc.com', 3478], # 19 Sept 2005
        ['stun.callwithus.com', 3478], # 19 Sept 2005
        ['stun.counterpath.net', 3478], # 19 Sept 2005
        ['stun.ekiga.net', 3478], # 18 Sept 2005 
        ['stun.internetcalls.com', 3478], # 19 Sept 2005
        ['stun.voipbuster.com', 3478], # 19 Sept 2005
        ['stun.12voip.com', 3478], # 19 Sept 2005
        ['stun.freecall.com', 3478], # 19 Sept 2005
        ['stun.nexxtmobile.de', 3478], # 13 June 2018
        ['stun.siptrunk.com', 3478], # 1 May 2014 
    ],

    # Still not many support IP6 with multiple IPs..
    IP6: [
        ['p2pd.net', 34780],
        ['stun.einfachcallback.de', 3478], # 21 Apr 2021
        ['stun.hot-chilli.net', 3478], # 14 Aug 2012
        ['stun.palava.tv', 3478], # 21 Apr 2021
        ['stun.simlar.org', 3478], # 21 Apr 2021
        ['stun.stunprotocol.org', 3478] # 19 Sept 2005
    ]
}

# The main server used to exchange 'signaling' messages.
# These are messages that help nodes create connections.
MQTT_SERVERS = [
    [b"p2pd.net", 1883],
    [b"mqtt.eclipseprojects.io", 1883],
    [b"broker.mqttdashboard.com", 1883],
    [b"test.mosquitto.org", 1883],
    [b"broker.emqx.io", 1883],
    [b"broker.hivemq.com", 1883]
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
"""
TURN_SERVERS = [
    {
        "host": b"p2pd.net",
        "port": 3478,
        "afs": [IP4, IP6],
        "user": None,
        "pass": None,
        "realm": b"p2pd.net"
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
        "host": b"us-0.turn.peerjs.com",
        "port": 3478,
        "afs": [IP4, IP6],
        "user": b"peerjs",
        "pass": b"peerjsp",
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


