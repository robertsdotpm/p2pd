from p2pd import *
import socket

"""
https://powerdns.org/tproxydoc/tproxy.md.html
https://blog.cloudflare.com/how-we-built-spectrum
https://tetrate.io/blog/what-is-tproxy-and-how-does-it-work/

For network interfaces we can normally assume the availability
of two addresses:
    - loopback
    - local addresses (like 192.168 and maybe 'link-local')

Unfortunately, this is not enough to simulate a routers NAT.
Think about it: when you're doing TCP punching code you need
to reuse ports so that external mapping allocations are
preserved. But if the external address is the same internal
address collisions with the connect sockets bound port
are guaranteed depending on NAT characteristics.

The solution is to have access to a block of IPs in order
to simulate:
    - Multiple 'external' addresses.
    - Internal gateway addresses.
    - Connect sockets.

That needs a lot of distinct IPs and they ought to be on
the same subnet to simplify things. It's hard to write code
that will automatically setup the IP blocks needed so
far now its assumed this will be manually configured.
"""
NAT_IPR_V4 = IPRange("135.0.0.0", cidr=8)



STUN_IP_PRIMARY = 1
STUN_IP_CHANGE = 2
STUN_PORT_PRIMARY = 1
STUN_PORT_CHANGE = 2
STUN_MAPPED_ADDR = b"\x00\x01"
STUN_SRC_ADDR = b"\x00\x04"
STUN_CHANGED_ADDR = b"\x00\x05"

def stun_write_attr(attr_type, attr_val):
    buf = attr_type
    buf += (  b"\x00" + i_to_b( len(attr_val) )  )[-2:]
    buf += attr_val
    return buf

def stun_endpoint_attr_val(end_tup, sock):
    ip, port = end_tup
    if sock.family == socket.AF_INET6:
        ip = ipv6_norm(ip)
    attr_val = b"\x00\x00" # Some kind of padding.
    attr_val += (  b"\x00" + i_to_b( port )  )[-2:]
    attr_val += socket.inet_aton(ip)
    return attr_val

class STUNServer(Daemon):
    def __init__(self, ip_actor, ip_port):
        self.ip_actor = ip_actor
        self.ip_port = ip_port
        self.nat = None

    def set_nat(self, nat):
        self.nat = nat

    async def msg_cb(self, msg, client_tup, pipe):
        print(msg)
        print(client_tup)

        # Minimum request size.
        msg_len = len(msg)
        if msg_len < 20:
            print("1")
            return

        # Unpack request.
        hdr = msg[0:2]
        extra_len = b_to_i(msg[2:4])
        tran_id = msg[4:20]
        if extra_len + 20 <= msg_len:
            extra = msg[20:][:extra_len]
        else:
            extra = None

        # Check hdr.
        if hdr != b"\x00\x01":
            print("2")
            return

        # Bind response msg.
        reply = b"\x01\x01"

        # Show their endpoint and our own.
        try:
            mapped_data = stun_endpoint_attr_val(client_tup, pipe.sock)
            attrs = stun_write_attr(STUN_MAPPED_ADDR, mapped_data)
            server_data = stun_endpoint_attr_val(
                client_tup[:2], pipe.sock
            )
            for attr_type in [STUN_SRC_ADDR, STUN_CHANGED_ADDR]:
                attrs += stun_write_attr(
                    attr_type,
                    server_data
                )
        except:
            what_exception()
            return

        # Attr len.
        reply += (  b"\x00" + i_to_b( len(attrs) )  )[-2:]

        # Tran id.
        reply += tran_id

        # Attrs.
        reply += attrs

        # Send reply.
        await pipe.send(reply, client_tup)

NAT_ALLOC_N = 5
class NATSim():
    def __init__(self, iface):
        self.iface = iface
        self.ext_ports = {
            UDP: { IP4: {}, IP6: {} },
            TCP: { IP4: {}, IP6: {} },
        }

    async def start(self):
        """
        Allocate a range of listen ports [udp, tcp, all supported afs.]
        These will serve as 'external' addresses to
        accept connections on.
        """
        try_again = 1
        while try_again:
            try_again = 0
            start_port = random.randrange(1024, 65535 - NAT_ALLOC_N)
            for proto in [UDP, TCP]:
                for af in self.iface.supported():
                    for port in range(start_port, start_port + NAT_ALLOC_N):
                        route = await self.iface.route(af).bind(port=port)
                        pipe = await pipe_open(
                            proto,
                            route,
                            msg_cb=self.msg_cb
                        )

                        if pipe is None:
                            await self.close()
                            try_again = 1
                            break

                        self.ext_ports[proto][af][port] = pipe

    async def close(self):
        for proto in [UDP, TCP]:
            for af in self.iface.supported():
                for port in self.ext_ports[proto][af]:
                    pipe = self.ext_ports[proto][af][port]
                    await pipe.close()

    async def msg_cb(self, msg, client_tup, pipe):
        pass


class Router():
    def __init__(self, nat):
        self.nat = nat
        self.endpoints = {
            IP4: { UDP: {}, TCP: {} },
            IP6: { UDP: {}, TCP: {} },
        }

        self.mappings = {
            IP4: { UDP: {}, TCP: {} },
            IP6: { UDP: {}, TCP: {} },
        }

        self.deltas = {
            IP4: { UDP: {}, TCP: {} },
            IP6: { UDP: {}, TCP: {} },
        }

    # Used to track increasing delta values for mapping ports.
    def init_delta(self, af, proto, dst_ip):
        deltas = self.deltas[af][proto]
        if dst_ip not in deltas:
            rand_port = random.randrange(1024, MAX_PORT + 1),
            deltas[dst_ip] = {
                # Random start port.
                "start": rand_port,

                # Tracked current port.
                "value": rand_port,

                # Local delta.
                "local": 0
            }

    # Used by connect on own NAT to simulate 'openning' the NAT.
    def approve_inbound(self, af, proto, dst_ip, dst_port):
        endpoints = self.endpoints[af][proto]
        if dst_ip not in af_proto:
            endpoints[dst_ip] = {}

        endpoints[dst_ip][dst_port] = 1

    # Return first unused port from a given port.
    def unused_delta(self, af, proto, dst_ip, dst_port):
        mappings = self.mappings[af][proto]
        if dst_ip not in mappings:
            return dst_port
        else:
            while 1:
                port = random.randrange(1024, MAX_PORT + 1)
                if port in mappings[dst_ip]:
                    continue

                return port

    # Allocates a new port for use with a new mapping.
    def request_delta(self, af, proto, src_ip, src_port, dst_ip, dst_port, delta_type=None):
        delta_type = delta_type or self.nat["delta"]["type"]
        mappings = self.mappings[af][proto]
        deltas = self.deltas[af][proto][dst_ip]
        port = 0

        # The NAT reuses the same src_port.
        if delta_type == EQUAL_DELTA:
            if dst_ip not in mappings:
                return src_port
            else:
                port = src_port

        # The distance between local ports is applied to
        # a fixed port offset to define remote mappings.
        if delta_type == PRESERV_DELTA:
            port = field_wrap(
                (src_port - 1) + self.rand_start_port, 
                [1024, MAX_PORT]
            )

        """
        There's a random, fixed-value 'delta' (either positive,
        or negative, sometimes even algebraic but this isn't
        covered) and its added to a past port allocation to
        yied a new number. The start port can be random.
        """
        if delta_type == INDEPENDENT_DELTA:
            delta = deltas["value"] + self.nat["delta"]["value"]
            port = field_wrap(
                delta,
                [1024, MAX_PORT]
            )

            # Save new allocation port value.
            deltas["value"] = delta

        """
        The distance between allocated ports also depends on
        the source port. So if you want to know what remote
        mappings occur you need to preserve the same delta
        in local port mappings.
        """
        if delta_type == DEPENDENT_DELTA:
            delta = deltas["start"] + self.nat["delta"]["value"] + src_port
            port = field_wrap(
                delta,
                [1024, MAX_PORT]
            )

        # Request port is already allocated.
        # Use the first free port from that offset.
        if port in mappings[dst_ip] or not port:
            return self.unused_delta(
                af,
                proto,
                dst_ip,
                port
            )

    # The other side calls this which returns a mapping
    # based on whether there's an approval + the nat setup.
    async def create_mapping(self, af, proto, src_ip, src_port, dst_ip, dst_port):
        self.init_delta(af, proto, dst_ip)
        af_proto = self.mappings[af][proto]
        mapping = None
        if self.nat["type"] == OPEN_INTERNET:
            mapping = [af, proto, dst_ip, dst_port]

        if self.nat["type"] == BLOCKED_NAT:
            mapping = None

        if self.nat["type"] == FULL_CONE:
            # Reuse existing mapping if it exists.
            if dst_ip in af_proto:
                if dst_port in af_proto[dst_ip]:
                    mapping = [af, proto, dst_ip, dst_port]

            # Create new mapping 

        

async def nat_sim_main():
    print(NAT_IPR_V4)
    print(len(NAT_IPR_V4))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
    s.close()
    return

    """
    # creating this, for convenience (will be used in later examples)
    IP_FREEBIND = 15

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_IP, IP_FREEBIND, 1)
    
    s.bind(("192.168.8.221", 0))
    s.listen(1)
    print(s)
    print(s.getsockname())
    """


    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.setsockopt(socket.SOL_IP, 15, 1)
    s2.bind(("192.168.8.233", 0))
    s2.connect(("192.168.8.233", 56871))

    print(s2)
    s2.close()



    return
    port = 55555
    ext_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ext_bind = ("127.0.0.1", port)
    ext_sock.bind(ext_bind)
    ext_sock.listen(1)

    con_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    con_sock.bind(("192.168.8.183", port))
    con_sock.connect(ext_bind)
    print("after non-blocking con")
    print(con_sock)

    client_sock = ext_sock.accept()
    print(client_sock)




    return

    # nic ip will be primary, loopback will be 'change'
    test_port = 3390
    ip = "127.0.0.1"
    proto = UDP
    i = await Interface().start_local()

    nat_sim = NATSim(iface=i)

    await nat_sim.start()
    print(nat_sim.ext_ports)
    await nat_sim.close()

    return
    route = await i.route().bind(port=test_port, ips=ip)
    stun_server = STUNServer(STUN_IP_PRIMARY, STUN_PORT_PRIMARY)
    await stun_server.listen_specific(
        [[route, proto]]
    )
    print(stun_server)
    
    stun_client = STUNClient(i)

    servers = [
        {
            "host": "local",
            # i.route().nic()
            "primary": {"ip": ip, "port": test_port},
            "secondary": {"ip": ip, "port": test_port},
        },
    ]


    ret = await stun_client.get_mapping(
        proto=proto,
        servers=servers
    )

    await stun_server.close()

    print(ret)
    print(ret[1].sock)

async_test(nat_sim_main)