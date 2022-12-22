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

# The main server used to exchange 'signaling' messages.
# These are messages that help nodes create connections.
MQTT_SERVERS = [
    [b"p2pd.net", 1883]
]

# Used to lookup the current time with a good amount of accuracy.
# The hole punching code uses this for synchronization.
NTP_SERVER = "time.google.com"

# Used to lookup what a nodes IP is and do NAT enumeration.
# Supports IPv6 / IPv4 / TCP / UDP -- change IP and port requests.
# Much more reliable than stunservers.org.
STUN_TEMP_SERVERS = [['p2pd.net', 34780]]

# List of public TURN servers.
"""
Please don't abuse this these.
TURN plays an important role in P2P audio, video, and file
protocols as a way for peers who can't connect directly
to send data to each other. All data flows through the servers
so it costs the owners a lot of money in bandwidth and that's
why it's only used as a last resort. If you need proxies you
can literally find them with Google or Shodan. There are also
numerous free VPS' servers you could use as a proxy.
"""
TURN_SERVERS = [
    {
        "host": b"p2pd.net",
        "port": 3478,
        "afs": [IP4, IP6],
        "user": None,
        "pass": None,
        "realm": b"p2pd.net"
    }
]