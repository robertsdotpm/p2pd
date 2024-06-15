import socket
from p2pd.net import IP4, IP6
from p2pd.route_utils import rp_from_fixed

# Only used for tests.
P2PD_NET_V4_IP = "139.99.209.63"
P2PD_NET_V6_IP = "2402:1f00:8101:83f::1"
P2PD_NET_IPS = {
    IP4: P2PD_NET_V4_IP,
    IP6: P2PD_NET_V6_IP
}

P2PD_NET_V4_FIXED_ROUTES = [
    # Route 0.
    [
        # NIC IPs.
        [
            [
                "139.99.209.63"
            ],
            [
                "139.99.250.35"
            ]
        ],

        # EXT IPs.
        [
            [
                "139.99.209.63"
            ]
        ]
    ]
]

P2PD_NET_V6_FIXED_ROUTES = [
    # Route 0.
    [
        # NIC IPs.
        [
            [
                "fe80::ae1f:6bff:fe94:531a"
            ],
            [
                "2402:1f00:8101:83f::1"
            ]
        ],

        # EXT IPs.
        [
            [
                "2402:1f00:8101:83f::1"
            ]
        ]
    ]
]

def use_fixed_rp(interface):
    rp = None
    if socket.gethostname() == "p2pd.net":
        rp = {}
        rp[IP4] = rp_from_fixed(
            P2PD_NET_V4_FIXED_ROUTES,
            interface,
            IP4
        )

        rp[IP6] = rp_from_fixed(
            P2PD_NET_V6_FIXED_ROUTES,
            interface,
            IP6
        )

    return rp
