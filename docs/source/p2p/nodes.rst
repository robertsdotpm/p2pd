Nodes
=========

Your P2P node is a class where you can add message handlers for your protocol.
Every technique for making P2P TCP connections in P2PD ultimately passes
messages back to these handlers. Where P2PD really shines is it's the only
P2P networking framework that's designed to run across multiple network
interfaces and address families (IPv4 and IPv6.)

The reason this is important is different network interfaces
often have completely different qualities in terms of being able to
reach services behind them. So a design that works for multiple interfaces
maximizes peer-to-peer reachability. A direct example of this is that of
mobile phones where one interface might be for mobile data and another for Wi-Fi.

.. literalinclude:: ../../examples/p2pd_in_a_nutshell.py
    :language: python3

When the node starts it may take a few seconds to load everything. This is
because external addresses for each interface have to be loaded via STUN; MQTT
server connections opened; clock skew calculated with NTP; and any ports forwarded
or pin holed. You can configure whether you want to try use
UPnP to improve reachability for your node.

UPnP will need to be enabled on the router used for one of your nodes interfaces.
But in practice many people aren't going to have this setup or may
not want to enable it for security reasons. Fortunately, reachability
in P2PD does not depend solely on UPnP support.

.. literalinclude:: ../../examples/node_with_config.py
    :language: python3

P2PD has a data directory in your home folder. This folder stores private
keys for node nicknames and for encrypting P2P signaling messages. The folder
also stores mutexes to prevent zombie daemons from taking the same listen ports
in P2PD (this is useful when combined with socket options that allow servers to be instantly restarted.)

The most interesting stuff is yet to come.