import socket
import struct
import sys
import time

UPNP_MCAST_IPv4 = "239.255.255.250"
UPNP_MCAST_IPv6 = "ff02::c"
UPNP_PORT = 1900

MSEARCH_MSG = """M-SEARCH * HTTP/1.1
HOST: {host}:{port}
MAN: "ssdp:discover"
MX: 1
ST: ssdp:all

"""

def discover_ipv4(timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Some OSes require binding to multicast port
    try:
        sock.bind(('', UPNP_PORT))
    except OSError:
        sock.bind(('', 0))  # fallback

    # Set TTL to 2
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    # Send M-SEARCH
    msg = MSEARCH_MSG.format(host=UPNP_MCAST_IPv4, port=UPNP_PORT).encode("utf-8")
    sock.sendto(msg, (UPNP_MCAST_IPv4, UPNP_PORT))
    
    # Listen for responses
    sock.settimeout(timeout)
    replies = []
    start = time.time()
    while time.time() - start < timeout:
        try:
            data, addr = sock.recvfrom(1024)
            replies.append((addr, data.decode("utf-8", errors="ignore")))
        except socket.timeout:
            break
        except Exception:
            pass
    sock.close()
    return replies

def discover_ipv6(timeout=2):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Some OSes require binding to the multicast port
    try:
        sock.bind(('', UPNP_PORT))
    except OSError:
        sock.bind(('', 0))  # fallback

    # Hop limit
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 2)

    # Send M-SEARCH
    msg = MSEARCH_MSG.format(host=UPNP_MCAST_IPv6, port=UPNP_PORT).encode("utf-8")
    sock.sendto(msg, (UPNP_MCAST_IPv6, UPNP_PORT, 0, 0))
    
    # Listen for responses
    sock.settimeout(timeout)
    replies = []
    start = time.time()
    while time.time() - start < timeout:
        try:
            data, addr = sock.recvfrom(1024)
            replies.append((addr, data.decode("utf-8", errors="ignore")))
        except socket.timeout:
            break
        except Exception:
            pass
    sock.close()
    return replies

if __name__ == "__main__":
    print("Discovering IPv4 UPnP devices...")
    for addr, reply in discover_ipv4():
        print(f"From {addr}:")
        print(reply)
        print("-" * 40)

    print("Discovering IPv6 UPnP devices...")
    for addr, reply in discover_ipv6():
        print(f"From {addr}:")
        print(reply)
        print("-" * 40)
