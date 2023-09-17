More portable netifaces
=========================

In Python the PyPI module 'netifaces' is a popular project for receiving information on network cards cross-platform. However, on Windows it has a few problems:

1. It requires the .NET Framework.
2. It does not use proper names for interfaces as GUIDs are used for adapter names on Windows.

Additionally, pieces of information are incorrect or missing. Such as the interface number (needed on Windows), MAC address, and some subnet mask fields.

I've provided a wrapper around the original module to fix these problems. It has the same interface as netifaces so it can be used as a drop-in replacement (it makes command-line calls and hence needs to be ran inside an event loop.)

.. code-block:: python

    from p2pd import *
    netifaces = await init_p2pd()
    #
    ifs = netifaces.interfaces()
    # e.g. ['lo0', 'en0']
    #
    info = netifaces.ifaddresses('en0')
    # {18: [{'addr': '8c:...'}], 30: [{'addr': 'fe80::...%en0',
    # 'netmask': 'ffff:ffff:ffff:ffff::/64', 'flags': 1024},
    # {'addr': 'fdf4:1...', 'netmask': 'ffff:ffff:ffff:ffff::/
    # 64', 'flags': 1088}], 2: [{'addr': '192.168.21.144',
    # 'netmask': '255.255.255.0', 'broadcast': '...'}]}
    #
    gws = netifaces.gateways()
    # {'default': {2: ('192.168.21.1', 'en0')},
    # 2: [('192.168.21.1', 'en0', True)],
    # 30: [...]}

More information on netifaces here: https://pypi.org/project/netifaces/