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

class Router():
    def __init__(self, nat):
        self.nat = nat

        self.approvals = {
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
            rand_port = from_range(self.nat["range"])
            deltas[dst_ip] = {
                # Random start port.
                "start": rand_port,

                # Tracked current port.
                "value": rand_port,

                # Local delta.
                "local": 0
            }

    # Return first unused port from a given port.
    def unused_port(self, af, proto, dst_ip, dst_port):
        mappings = self.mappings[af][proto]
        if dst_ip not in mappings:
            return dst_port
        else:
            while 1:
                port = from_range(self.nat["range"])
                if port in mappings[dst_ip]:
                    continue

                return port

    # Allocates a new port for use with a new mapping.
    def request_port(self, af, proto, src_ip, src_port, dst_ip):
        delta_type = self.nat["delta"]["type"]
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
                src_port + self.nat["delta"]["value"],
                self.nat["range"]
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
                self.nat["range"]
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
            delta = src_port + deltas["start"] + self.nat["delta"]["value"]
            port = field_wrap(
                delta,
                self.nat["range"]
            )

        # Request port is already allocated.
        # Use the first free port from that offset.
        if dst_ip in mappings:
            if port in mappings:
                port = 0
        if not port:
            return self.unused_port(
                af,
                proto,
                dst_ip,
                port
            )

        return port

    # Used by connect on own NAT to simulate 'openning' the NAT.
    def approve_inbound(self, af, proto, src_ip, src_port, dst_ip, dst_port, nat_ip):
        # Add dst ip and port to approvals.
        self.approvals.setdefault(dst_ip, {})
        self.approvals[dst_ip][dst_port] = 1

        # Reuse an existing mapping if it exists.
        mapping = None
        mappings = self.mappings[af][proto]
        local_endpoint = str([src_ip, src_port])
        reuse_nats = [FULL_CONE, RESTRICT_NAT, RESTRICT_PORT_NAT]
        if nat_ip in mappings:
            if local_endpoint in mappings:
                mapping = mappings[nat_ip][local_endpoint]
                if self.nat["type"] in reuse_nats:
                    mapping = mappings[nat_ip][local_endpoint]
        else:
            mappings[nat_ip] = {}

        # Otherwise create a new mapping.
        if mapping is None:
            # Only certain NATs need a new 'mapping.'
            create_nats = reuse_nats + [SYMMETRIC_NAT]
            if self.nat["type"] in create_nats:
                # Request new port for the mapping.
                self.init_delta(af, proto, dst_ip)
                nat_port = self.request_port(
                    af,
                    proto,
                    src_ip,
                    src_port,
                    dst_ip
                )

                # The mappings are indexed by local endpoints.
                mapping = [af, proto, dst_ip, dst_port, nat_port]
                mappings[nat_ip][local_endpoint] = mapping
                mappings[nat_ip][mapping[-1]] = mapping

        # Return results.
        if mapping is not None:
            return mapping[-1]

        # Return results.
        return 0

    # The other side calls this which returns a mapping
    # based on whether there's an approval + the nat setup.
    def request_approval(self, af, proto, dst_ip, dst_port, nat_ip, nat_port):
        # Blocked.
        if self.nat["type"] in [BLOCKED_NAT, SYMMETRIC_UDP_FIREWALL]:
            return 0

        # Open internet -- can use any inbound port.
        if self.nat["type"] == OPEN_INTERNET:
            return nat_port

        # No mappings for this NAT IP exist.
        mappings = self.mappings[af][proto]
        if nat_ip not in mappings:
            return 0
        if nat_port not in mappings[nat_ip]:
            return 0

        # Handle the main NATs.
        mapping = mappings[nat_ip][nat_port]

        # Anyone can reuse this mapping.
        if self.nat["type"] == FULL_CONE:
            return nat_port

        # Inbound IP must be approved.
        if self.nat["type"] == RESTRICT_NAT:
            if dst_ip not in self.approvals:
                return 0

        # Both inbound IP and port must be aproved.
        if self.nat["type"] == RESTRICT_PORT_NAT:
            if dst_ip not in self.approvals:
                return 0
            if dst_port not in self.approvals[dst_ip]:
                return 0

        # The inbound dest has to match the mapping.
        if self.nat["type"] == SYMMETRIC_NAT:
            if dst_ip != mapping[-3]:
                return 0
            if dst_ip != mapping[-2]:
                return 0

        # Otherwise success.
        return nat_port
        

async def nat_sim_main():
    af = IP4
    proto = TCP
    int_ipr = IPRange("127.64.0.0", cidr=10)
    src_port = 1337

    ext_ipr = IPRange("127.128.0.0", cidr=10)

    print(int_ipr)
    print(len(int_ipr))


    n1 = nat_info(RESTRICT_NAT, delta=delta_info(DEPENDENT_DELTA, 10))
    r1 = Router(n1)
    r1.init_delta(af, proto, str(ext_ipr + 0))


 
    p1 = r1.request_port(af, proto, str(int_ipr + 0), src_port, str(ext_ipr + 0))
    print(p1)
    p1 = r1.request_port(af, proto, str(int_ipr + 0), src_port + 3, str(ext_ipr + 0))
    print(p1)

    m1 = r1.approve_inbound(
        af,
        proto,
        str(int_ipr + 0),
        1337,
        str(ext_ipr + 0),
        10123,
        str(ext_ipr + 1)
    )

    print(m1)

    a1 = r1.request_approval(
        af,
        proto,
        str(ext_ipr + 0),
        10123,
        str(ext_ipr + 1),
        m1
    )

    print(a1)




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