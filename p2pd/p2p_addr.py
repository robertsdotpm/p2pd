from .nat import *
from .ip_range import *

# No more than 4 interfaces per address family in peer addr.
PEER_ADDR_MAX_INTERFACES = 4

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
def make_peer_addr(node_id, interface_list, port=NODE_PORT, ip=None, nat=None, if_index=None):
    ensure_resolved(interface_list)
    bufs = []
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

            af_bufs.append(b"[%d,%b,%b,%d,%d,%d,%d]" % (
                if_index or i,
                ip or to_b(r.ext()),
                ip or to_b(r.nic()),
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
    
    bufs.append(node_id)
    return b'-'.join(bufs)

def parse_peer_addr(addr):
    af_parts = addr.split(b'-')
    if len(af_parts) != 3:
        log("p2p addr invalid parts")
        return None

    schema = [is_no, is_b, is_b, is_no,  is_no, is_no, is_no]
    translate = [to_n, to_b, to_b, to_n, to_n, to_n, to_n]
    out = {IP4: [], IP6: [], "node_id": af_parts[2]}
    for af_index, af_part in enumerate(af_parts[:2]):
        interface_infos = af_part.split(b'|')
        for info in interface_infos:
            # Strip outer braces.
            if len(info) < 2:
                continue
            inner = info[1:-1]

            # Split into components.
            parts = inner.split(b',')
            if len(parts) != 7:
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
                IPRange(to_s(parts[1]))
            except Exception:
                log("p2p addr: ip invalid.")
                continue

            # Is it a valid IP?
            try:
                IPRange(to_s(parts[2]))
            except Exception:
                log("p2p addr: ip invalid.")
                continue

            # Is listen port right?
            if not in_range(parts[3], [1, MAX_PORT]):
                log("p2p addr: listen port invalid")
                continue

            # Check NAT type is valid.
            if not in_range(parts[4], [OPEN_INTERNET, BLOCKED_NAT]):
                log("p2p addr: nat type invalid")
                continue

            # Check delta type is valid.
            if not in_range(parts[5], [NA_DELTA, RANDOM_DELTA]):
                log("p2p addr: delta type invalid")
                continue

            # Check delta value is valid.
            if not in_range(parts[6], [0, MAX_PORT]):
                log("p2p addr: Delta value invalid")
                continue
                    
            # Build dictionary of results.
            delta = delta_info(parts[5], parts[6])
            nat = nat_info(parts[4], delta)
            as_dict = {
                "if_index": parts[0],
                "ext": IPRange(to_s(parts[1])),
                "nic": IPRange(to_s(parts[2])),
                "nat": nat,
                "port": parts[3]
            }

            # Save results.
            af = VALID_AFS[af_index]
            out[af].append(as_dict)

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
