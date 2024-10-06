from p2pd import *

async def example():
    netifaces = await init_p2pd()
    ifs = netifaces.interfaces()
    # e.g. ['lo0', 'en0']

    info = netifaces.ifaddresses('en0')
    # {18: [{'addr': '8c:...'}], 30: [{'addr': 'fe80::...%en0',
    # 'netmask': 'ffff:ffff:ffff:ffff::/64', 'flags': 1024},
    # {'addr': 'fdf4:1...', 'netmask': 'ffff:ffff:ffff:ffff::/
    # 64', 'flags': 1088}], 2: [{'addr': '192.168.21.144',
    # 'netmask': '255.255.255.0', 'broadcast': '...'}]}

    gws = netifaces.gateways()
    # {'default': {2: ('192.168.21.1', 'en0')},
    # 2: [('192.168.21.1', 'en0', True)],
    # 30: [...]}

if __name__ == '__main__':
    async_test(example)