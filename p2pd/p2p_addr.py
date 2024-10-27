import struct
from .settings import *
from .nat_utils import *
from .ip_range import *


# No more than n interfaces per address family in peer addr.
PEER_ADDR_MAX_INTERFACES = 4

# No more than n signal pipes to send signals to nodes.
SIGNAL_PIPE_NO = 3

"""
        can be up to N interfaces
[ IP4 nics
    [
        interface_offset,
        ext ip,
        nic ip,
        port,
        nat_type,
        delta_type,
        delta_val
    ]
    ,... more interfaces for AF family
],[IP6 nics ...],node_id
"""
def make_peer_addr(node_id, machine_id, interface_list, signal_offsets, port=NODE_PORT, ip=None, nat=None, if_index=None):
    ensure_resolved(interface_list)

    # Make the program crash early on invalid addr inputs.
    assert(isinstance(node_id, (str, bytes)))
    assert(isinstance(machine_id, (str, bytes)))
    assert(len(interface_list))
    assert(port)
    assert(isinstance(signal_offsets, list))
    for x in signal_offsets:
        assert(isinstance(x, int))

    # Signal offsets to load.
    if len(signal_offsets):
        signal_offsets_as_str = [to_b(str(x)) for x in signal_offsets]
        bufs = [
            # Make signal pipe buf.
            b','.join(signal_offsets_as_str)
        ]
    else:
        # No signal offsets.
        bufs = [b"None"]

    for af in [IP4, IP6]:
        af_bufs = []
        for i, interface in enumerate(interface_list):
            # AF type is not supported.
            if not len(interface.rp[af].routes):
                continue

            r = interface.route(af)
            if r is None:
                continue

            if nat:
                nat_type = nat["type"]
                delta_type = nat["delta"]["type"]
                delta_value = nat["delta"]["value"]
            else:
                nat_type = interface.nat["type"]
                delta_type = interface.nat["delta"]["type"]
                delta_value = interface.nat["delta"]["value"]

            if af == IP4:
                int_ip = ip or to_b(r.nic())
            if af == IP6:
                int_ip = to_b(r.ext())
                if len(r.link_locals):
                    int_ip = to_b(str(r.link_locals[0]))
                if ip is not None:
                    int_ip = to_b(ip)

            af_bufs.append(b"[%d,%d,%b,%b,%d,%d,%d,%d]" % (
                interface.netiface_index,
                if_index or i,
                ip or to_b(r.ext()),
                int_ip,
                port,
                nat_type,
                delta_type,
                delta_value
            ))

        if len(af_bufs):
            af_bufs = b'|'.join(af_bufs)
        else:
            af_bufs = b''
        
        # The as_buf may be empty if AF has no routes.
        # Expected and okay.
        bufs.append(af_bufs or b"0")
    
    bufs.append(to_b(node_id))
    bufs.append(to_b(machine_id))
    return b'-'.join(bufs)

"""
New packed binary format for addresses. 
Doing this was necessary for the IRC DNS module as space in
topics for records is quite scarce. There's room here for improvement
if you wanted to make each bit count. But I haven't gone overboard here.
"""
def pack_peer_addr(node_id, interface_list, signal_offsets, port=NODE_PORT, ip=None, nat=None, if_index=None):
    # Truncate node id to 8.
    node_id = node_id[:8]

    """
    Indicates variable length sections (list of signal offsets
    and number of interfaces.) Encodes 1 byte integers as byte
    characters so they can be stored in an unsigned char.
    """
    args = [
        # Node ID(8), lport(2), signal offsets(1), if no(1)
        # signal offsets[] ...
        "HBB" + ("B" * len(signal_offsets)),
        port,
        len(signal_offsets),
        len(interface_list)
    ]
    for offset in signal_offsets:
        args.append(offset)
    
    # Pack header portion.
    buf = node_id
    buf += struct.pack(*args)

    # if_no, ip4, null or ..., ip6, null or ...
    for i, interface in enumerate(interface_list):
        # Append interface no.
        buf += bytes([if_index or i])

        # Loop over AFs.
        for af in [IP4, IP6]:
            # Append AF type.
            buf += bytes([int(af)])

            # AF type is not supported.
            if not len(interface.rp[af].routes):
                buf += bytes([0])
                continue

            # AF type not supported.
            r = interface.route(af)
            if r is None:
                buf += bytes([0])
                continue

            # Indicate segment is filled.
            buf += bytes([1])

            # Main details for this interface.
            if nat:
                nat_type = nat["type"]
                delta_type = nat["delta"]["type"]
                delta_value = nat["delta"]["value"]
            else:
                nat_type = interface.nat["type"]
                delta_type = interface.nat["delta"]["type"]
                delta_value = interface.nat["delta"]["value"]

            # Pack interface details.
            # nat type 1 - 7
            # delta type 1 - 7
            # delta value +/- port
            nat_packed = struct.pack(
                "BBxxi",
                nat_type,
                delta_type,
                delta_value
            )
            assert(len(nat_packed) == 8)
            buf += nat_packed

            # Convert IPs to bytes.
            cidr = af_to_cidr(af)
            nic_ip = bytes(IPRange(ip or r.nic(), cidr=cidr))
            ext_ip = bytes(IPRange(ip or r.ext(), cidr=cidr))
            if af == IP4:
                assert(len(nic_ip) == 4)
                assert(len(ext_ip) == 4)
            else:
                assert(len(nic_ip) == 16)
                assert(len(ext_ip) == 16)

            buf += nic_ip
            buf += ext_ip

    return buf

def validate_peer_addr(addr):
    # Check signal server offsets.
    for offset in addr["signal"]:
        if not in_range(offset, [0, len(MQTT_SERVERS) - 1]):
            log("p2p addr signal offset outside server range.")
            return None
        
    # Too many signal pipe offsets.
    if len(addr["signal"]) > (SIGNAL_PIPE_NO + 3):
        log("p2p addr invalid signal no for p2p addr")
        return None
    
    for af in VALID_AFS:
        for if_offset in addr[af]:
            if_info = addr[af][if_offset]

            # Is listen port right?
            if not in_range(if_info["port"], [1, MAX_PORT]):
                log("p2p addr: listen port invalid")
                return None
            
            # Check NAT type is valid.
            if not in_range(if_info["nat"]["type"], [OPEN_INTERNET, BLOCKED_NAT]):
                log("p2p addr: nat type invalid")
                return None

            # Check delta type is valid.
            if not in_range(if_info["nat"]["delta"]["type"], [NA_DELTA, RANDOM_DELTA]):
                log("p2p addr: delta type invalid")
                return None

            # Check delta value is valid.
            delta = if_info["nat"]["delta"]["value"]
            delta = -delta if delta < 0 else delta
            if not in_range(delta, [0, MAX_PORT]):
                log("p2p addr: Delta value invalid")
                return None
            
    return addr

def unpack_peer_addr(addr):
    # Unpack header portion.
    node_id = addr[:8]; p = 8;
    port, signal_no, if_no = struct.unpack("HBB", addr[p:p + 4]); p += 4;

    # Unpack signal offsets (variable length.)
    signal_offsets = struct.unpack("B" * signal_no, addr[p:p + signal_no])
    out = {
        IP4: [],
        IP6: [],
        "node_id": node_id,
        "signal": signal_offsets
    }

    # Unpack if list.
    p += signal_no;
    for _ in range(0, if_no):
        if_index = addr[p]; p += 1;
        for _ in range(0, 2):
            # Get AF at pointer.
            af = addr[p]; p += 1

            # Address type for IF unsupported.
            if addr[p] == 0:
                # Next byte is another AF or if_index.
                p += 1
                continue
            else:
                # Segment is supported (and filled.)
                # Next byte starts the segment.
                p += 1

            # Unpack interface details.
            parts = struct.unpack("BBxxi", addr[p:p + 8]); p += 8;
            nat_type = parts[0]
            delta_type = parts[1]
            delta_value = parts[2]

            # Determine IP field sizes based on AF.
            if af == IP4:
                ip_size = 4
                
            if af == IP6:
                ip_size = 16

            # Exact IP portions.
            b_nic_ip = addr[p:p + ip_size]; p += ip_size;
            b_ext_ip = addr[p:p + ip_size]; p += ip_size;

            # Build dictionary of results.
            delta = delta_info(delta_type, delta_value)
            nat = nat_info(nat_type, delta)
            as_dict = {
                "if_index": if_index,
                "ext": IPRange(socket.inet_ntop(af, b_ext_ip)),
                "nic": IPRange(socket.inet_ntop(af, b_nic_ip)),
                "nat": nat,
                "port": port
            }

            # Save results.
            out[af].append(as_dict)

    return validate_peer_addr(out)

def parse_peer_addr(addr):
    # Already passed.
    if isinstance(addr, dict):
        return addr

    addr = to_b(addr)
    af_parts = addr.split(b'-')
    if len(af_parts) != 5:
        log("p2p addr invalid parts")
        return None

    # Parse signal server offsets.
    sig_part = af_parts.pop(0)
    if sig_part == b"None":
        signal = []
    else:
        p = sig_part.split(b",")
        signal = [int(n) for n in p if in_range(int(n), [0, len(MQTT_SERVERS) - 1])]

    # Parsed dict.
    schema = [is_no, is_no, is_b, is_b, is_no,  is_no, is_no, is_no]
    translate = [to_n, to_n, to_b, to_b, to_n, to_n, to_n, to_n]
    out = {
        IP4: {},
        IP6: {},
        "node_id": to_s(af_parts[2]),
        "signal": signal,
        "machine_id": to_s(af_parts[3]),
        "bytes": addr,
    }

    for af_index, af_part in enumerate(af_parts[:2]):
        interface_infos = af_part.split(b'|')
        for info in interface_infos:
            # Strip outer braces.
            if len(info) < 2:
                continue
            inner = info[1:-1]

            # Split into components.
            parts = inner.split(b',')
            if len(parts) != 8:
                log("p2p addr: invalid parts no.")
                continue

            # Test type of field.
            # Convert to its end value if it passes.
            try:
                for j, part in enumerate(parts):
                    if not schema[j](part):
                        raise Exception("Invalid type.")
                    else:
                        parts[j] = translate[j](part)
            except Exception:
                continue

            # Is it a valid IP?
            try:
                IPRange(to_s(parts[2]))
            except Exception:
                log("p2p addr: ip invalid.")
                continue

            # Is it a valid IP?
            try:
                IPRange(to_s(parts[3]))
            except Exception:
                log("p2p addr: ip invalid.")
                continue
                    
            # Build dictionary of results.
            delta = delta_info(parts[6], parts[7])
            nat = nat_info(parts[5], delta)
            as_dict = {
                "netiface_index": parts[0],
                "if_index": parts[1],
                "ext": IPRange(to_s(parts[2])),
                "nic": IPRange(to_s(parts[3])),
                "nat": nat,
                "port": parts[4]
            }

            # Save results.
            af = VALID_AFS[af_index]
            out[af][parts[1]] = as_dict

    # Sanity check address.
    validate_peer_addr(out)

    # Convert to tuple to prevent change.
    out["signal"] = tuple(out["signal"])

    return out

def peer_addr_extract_exts(p2p_addr):
    exts = []
    for af in VALID_AFS:
        for info in p2p_addr[af]:
            exts.append(info["ext"])
            exts.append(info["nic"])

    return exts

def is_p2p_addr_us(addr_bytes, if_list):
    # Parse address bytes to address.
    addr = parse_peer_addr(addr_bytes)

    # Check all address families.
    for af in VALID_AFS:
        # Check all interface details for AF.
        for info in addr[af]:
            # Compare the external address.
            ipr = info["ext"]

            # Set the right interface to check.
            if_index = info["if_index"]
            if if_index + 1 > len(if_list):
                continue

            # Check all routes in the interface.
            interface = if_list[if_index]
            for route in interface.rp[af].routes:
                # Only interested in the external address.
                for ext_ipr in route.ext_ips:
                    # IPs are equal or in same block.
                    if ipr in ext_ipr:
                        return True

    # Nothing found that matches.
    return False

if __name__ == "__main__": # pragma: no cover
    from .interface import Interface
    async def test_p2p_addr():
        x = await Interface("enp3s0").start()
        if_list = [x]
        node_id = b"noasdfosdfo"
        b_addr = make_peer_addr(node_id, if_list)
        print(b_addr)

        addr = parse_peer_addr(b_addr)
        print(addr)

    async_test(test_p2p_addr)
