import asyncio
import hashlib
import os
import socket
from ecdsa import SigningKey, SECP256k1
import pathlib
from ..settings import *
from ..utility.utils import *
from ..install import *
from ..net.address import Address
from ..net.net import *
from ..nic.interface import get_default_iface, get_mac_address
from ..traversal.signaling.signaling_client import SignalMock
from ..traversal.signaling.signaling_protocol import signal_protocol
from ..protocol.stun.stun_client import get_n_stun_clients
from ..utility.clock_skew import SysClock

def load_signing_key(listen_port):
    # Make install dir if needed.
    install_root = get_p2pd_install_root()
    pathlib.Path(install_root).mkdir(
        parents=True,
        exist_ok=True
    )

    # Store cryptographic random bytes here for ECDSA ident.
    sk_path = os.path.realpath(
        os.path.join(
            install_root,
            fstr("SECRET_KEY_DONT_SHARE_{0}.hex", (listen_port,))
        )
    )

    # Read secret key as binary if it exists.
    if os.path.exists(sk_path):
        with open(sk_path, mode='r') as fp:
            sk_hex = fp.read()

    # Write a new key if the path doesn't exist.
    if not os.path.exists(sk_path):
        sk = SigningKey.generate(curve=SECP256k1)
        sk_buf = sk.to_string()
        sk_hex = to_h(sk_buf)
        with open(sk_path, "w") as file:
            file.write(sk_hex)

    # Convert secret key to a singing key.
    sk_buf = h_to_b(sk_hex)
    sk = SigningKey.from_string(sk_buf, curve=SECP256k1)
    return sk
    
async def fallback_machine_id(netifaces, app_id="p2pd"):
    host = socket.gethostname()
    if_name = get_default_iface(netifaces)
    mac = await get_mac_address(if_name, netifaces)
    buf = fstr("{0} {1} {2} {3}", (app_id, host, if_name, mac,))
    return to_s(hashlib.sha256(to_b(buf)).hexdigest())

async def load_stun_clients(node):
    # Already loaded.
    if hasattr(node, "stun_clients"):
        return
    
    node.stun_clients = {IP4: {}, IP6: {}}
    for if_index in range(0, len(node.ifs)):
        interface = node.ifs[if_index]
        for af in interface.supported():
            node.stun_clients[af][if_index] = await get_n_stun_clients(
                af=af,
                n=USE_MAP_NO,
                interface=interface,
                proto=TCP,
                conf=PUNCH_CONF,
            )