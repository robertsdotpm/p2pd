from ....net.ip_range import *
from ....nic.nat.nat_utils import *
from ....nic.nat.nat_predict import *
from ....nic.interface import *
from ....utility.clock_skew import *
from .punch_defs import *

"""
The function bellow is used to adjust sleep parameters
for the punching algorithm. Sleep time is reduced
based on how close the destination is.
"""
def get_punch_mode(af, dest_ip, same_machine):
    cidr = af_to_cidr(af)
    dest_ipr = IPRange(dest_ip, cidr=cidr)

    # Calculate punch mode
    if dest_ipr.is_public:
        return TCP_PUNCH_REMOTE
    else:
        if same_machine:
            return TCP_PUNCH_SELF
        else:
            return TCP_PUNCH_LAN

def tcp_puncher_states(dest_mappings, state):
    # bool of dest_mappings, start state, to state.
    progressions = [
        [False, None, INITIATED_PREDICTIONS],
        [True, None, RECEIVED_PREDICTIONS],
        [True, INITIATED_PREDICTIONS, UPDATED_PREDICTIONS]
    ]

    # What protocol 'side' corresponds to a state.
    sides = {
        INITIATED_PREDICTIONS: INITIATOR,
        UPDATED_PREDICTIONS: INITIATOR,
        RECEIVED_PREDICTIONS: RECIPIENT,
    }

    # Progress the state machine.
    for progression in progressions:
        from_recv, from_state, to_state = progression
        if from_recv != bool(dest_mappings):
            continue

        if from_state != state:
            continue

        return (to_state, sides[to_state])
    
    raise Exception("Invalid puncher state progression.")

def choose_same_punch_sock(our_wan, outs):
    chosen_sock = None
    try:
        our_ip_num = ip_str_to_int(our_wan)
        h_val = 0
        for mapping in outs:
            sock = mapping.sock
            remote_port = mapping.remote
            their_ip_host, their_r_port = sock.getpeername()[:2]
            their_ip_num = ip_str_to_int(
                their_ip_host
            )

            """
            A TCP connection is defined by a unique tuple of
            src_ip, src_port, dest_ip, dest_port. The purpose
            of this code is to define a single view of the
            'highest' value connection based on the tuple.
            The highest connection will be used in the event
            multiple 'holes' were punched. The clients will
            close the unneeded connections.
            """
            str_to_hash = ""
            socket_quad_list = sorted([our_ip_num, their_ip_num, remote_port, their_r_port])
            for entry in socket_quad_list:
                str_to_hash += fstr("{0} ", (entry,))

            # Mix values into a somewhat unique result.
            str_hash = hashlib.sha256(to_b(str_to_hash)).hexdigest()
            str_hash_as_int = int(to_s(str_hash), 16)
            assert(str_hash_as_int > 0)
            if str_hash_as_int > h_val:
                h_val = str_hash_as_int
                chosen_sock = sock
    except Exception as e:
        log_exception()
        log("unknown exception occured")

    return chosen_sock

def close_unneeded_socks(needed, outs):
    for mapping in outs:
        if mapping.sock is None:
            continue

        if mapping.sock != needed:
            mapping.sock.close()

def punching_sanity_check(mode, our_wan, dest_addr, send_mappings, recv_mappings):
    if mode == TCP_PUNCH_SELF:
        for sm in send_mappings:
            for rm in recv_mappings:
                if sm.local == rm.local:
                    error = \
                    fstr("punch self local port conflict ")
                    fstr("{0} {1}", (sm.local, rm.local,))
                    log(error)

    if mode == TCP_PUNCH_REMOTE:
        if our_wan == dest_addr:
            error = \
            fstr("punch remote but dest is the same ")
            fstr("as our ext {0}", (our_wan,))
            log(error)
            
# Not really the best approach but process communication is a pain.
async def punch_close_msg(msg, client_tup, pipe):
    if msg in PUNCH_END:
        # Allow time to send message down pipes.
        await asyncio.sleep(2)
        await pipe.close()

def puncher_to_dict(self):
    assert(self.interface)
    assert(self.sys_clock)
    assert(self.state)
    recv_mappings = mappings_objs_to_dicts(self.recv_mappings)
    send_mappings = mappings_objs_to_dicts(self.send_mappings)
    return {
        "af": self.af,
        "src_info": self.src_info,
        "dest_info": self.dest_info,
        "sys_clock": self.sys_clock.to_dict(),
        "start_time": self.start_time,
        "same_machine": self.same_machine,
        "interface": self.interface.to_dict(),
        "punch_mode": self.punch_mode,
        "state": self.state,
        "side": self.side,
        "recv_mappings": recv_mappings,
        "send_mappings": send_mappings,
    }

def puncher_from_dict(d, cls):
    interface = Interface.from_dict(d["interface"])
    recv_mappings = mappings_dicts_to_objs(d["recv_mappings"])
    send_mappings = mappings_dicts_to_objs(d["send_mappings"])
    sys_clock = SysClock.from_dict(d["sys_clock"])
    puncher = cls(
        af=d["af"],
        src_info=d["src_info"],
        dest_info=d["dest_info"],
        stuns=None,
        sys_clock=sys_clock,
        same_machine=d["same_machine"],
        nic=interface
    )
    puncher.state = d["state"]
    puncher.side = d["side"]
    puncher.punch_mode = d["punch_mode"]
    puncher.recv_mappings = recv_mappings
    puncher.send_mappings = send_mappings
    puncher.start_time = Dec(d["start_time"])
    return puncher
