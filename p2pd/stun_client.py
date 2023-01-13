"""
Taken directly from here: https://github.com/talkiq/pystun3
I'm forking it because I want to add small changes

changes:
- full async support
- add more stun servers
- test that they all work
- improve error checking
- add ipv6 support
- improve commenting
- fix some smol bugs (including nat test bugs)
- load balancing to avoid overloading
- result average support to avoid invalid servers
- separate list of hosts that support ipv6 for less failures on ipv6
- TCP support (for get mappings)
- delta n test (some nats have predictable mappings and assign then a delta apart)
- added better checking for 'change IPs' and made a new address family for hosts that return correct change ip responses. the nat determination code needs to use these hosts. for regular 'get wan ip' and 'get port mapped' lookups you can use the change hosts or the mapping hosts (larger list)

Note 1: Some of the response times for DNS lookups to the STUN servers in
this module are on the order of 1 second or higher -- an astronomical
amount of time for a network. I have tried to use concurrency patterns
where ever possible to avoid delaying other, faster lookups.4

Note 2: I've read the STUN RFC and it seems to indicate that many of the fields in the protocol format take place over byte boundaries. Yet the client code here works on all the servers I've tested it on and doesn't make these assumptions. It's possible the spec is wrong or maybe my code just won't work with particular features of the STUN protocol. No idea.

TODO: sort the hosts by how fast they respond to a STUN request from domain resolution to reply time.
TODO: It seems that this is a pattern that reoccurs in several functions.
The general form might also make sense to add to the Net module.
TODO: Refactor code. The code in this module offers many good features but the code reflects too much cruft. It could do with a good cleanup.
"""

import time
import binascii
import random
import socket
import asyncio
import ipaddress
import copy
import struct
import re
from .utils import *
from .net import *
from .address import *
from .nat import *
from .base_stream import pipe_open
from .settings import *

"""
In most requests the max STUN time is given by:
    (
        (
            (addr_retry * (dns_timeout + con_timeout_if_applicable))
                + 
            (packet_retry * recv_timeout)
        ) * retry_no
    ) * consensus[1]

Put another way:
    for consensus [1]:
        for retry_no:
            for addr_retry:
                dns_timeout
                optional: con_timeout

            for packet_retry:
                recv_timeout

I don't know if my formula is correct though.
"""

STUN_CONF = dict_child({
    # Retry N times on reply timeout.
    "packet_retry": 2,

    # Retry N times on invalid address.
    "addr_retry": 2,

    # Seconds to use for a DNS request before timeout exception.
    "dns_timeout": 2,

    # N of M required for agreement.
    "consensus": [1, 1],

    # Retry no -- if an individual call fails how
    # many times to retry the whole thing.
    "retry_no": 3,

    # Reuse address tuple for bind() socket call.
    "reuse_addr": True,
}, NET_CONF)

# Replace with servers from settings.
# Remove distinction between 'map' and 'change' servers.
# Just keep change servers to keep things simple.
STUN_SERVERS_MAP_UDP_V6 = [STUND_SERVERS[IP6][0]] + shuffle(STUND_SERVERS[IP6][1:])
STUN_SERVERS_CHANGE_UDP_V6 = [STUND_SERVERS[IP6][0]] + shuffle(STUND_SERVERS[IP6][1:])
STUN_SERVERS_MAP_UDP_V4 = [STUND_SERVERS[IP4][0]] + shuffle(STUND_SERVERS[IP4][1:])
STUN_SERVERS_CHANGE_UDP_V4 = [STUND_SERVERS[IP4][0]] + shuffle(STUND_SERVERS[IP4][1:])
STUN_SERVERS_MAP_TCP_V6 = [STUNT_SERVERS[IP6][0]] + shuffle(STUNT_SERVERS[IP6][1:])
STUN_SERVERS_CHANGE_TCP_V6 = [STUNT_SERVERS[IP6][0]] + shuffle(STUNT_SERVERS[IP6][1:])
STUN_SERVERS_MAP_TCP_V4 = [STUNT_SERVERS[IP4][0]] + shuffle(STUNT_SERVERS[IP4][1:])
STUN_SERVERS_CHANGE_TCP_V4 = [STUNT_SERVERS[IP4][0]] + shuffle(STUNT_SERVERS[IP4][1:])

# Apply funcs easier to all server lists.
STUN_SERVERS = [
    STUN_SERVERS_MAP_UDP_V4, STUN_SERVERS_MAP_UDP_V6,
    STUN_SERVERS_MAP_TCP_V4, STUN_SERVERS_MAP_TCP_V6,
    STUN_SERVERS_CHANGE_UDP_V4, STUN_SERVERS_CHANGE_UDP_V6,
    STUN_SERVERS_CHANGE_TCP_V4, STUN_SERVERS_CHANGE_TCP_V6,
]

# Return stun server list easily.
STUN_SERVER_INDEX = {
    "change": {
        socket.SOCK_DGRAM: {
            socket.AF_INET: STUN_SERVERS_CHANGE_UDP_V4,
            socket.AF_INET6: STUN_SERVERS_CHANGE_UDP_V6
        },
        socket.SOCK_STREAM: {
            socket.AF_INET: STUN_SERVERS_CHANGE_TCP_V4,
            socket.AF_INET6: STUN_SERVERS_CHANGE_TCP_V6
        }
    },
    "map": {
        socket.SOCK_DGRAM: {
            socket.AF_INET: STUN_SERVERS_MAP_UDP_V4,
            socket.AF_INET6: STUN_SERVERS_MAP_UDP_V6
        },
        socket.SOCK_STREAM: {
            socket.AF_INET: STUN_SERVERS_MAP_TCP_V4,
            socket.AF_INET6: STUN_SERVERS_MAP_TCP_V6
        }
    }
}

# stun consts
MappedAddress = '0001'
SourceAddress = '0004'
ChangedAddress = '0005'
ChangeRequest = '0003'
BindRequestMsg = '0001'
dictValToMsgType = {"0101": "BindResponseMsg"}

# Unexpected error during NAT determination -- try again.
ChangedAddressError = 12

# Requests.
changeRequest = ''.join(
    [ChangeRequest, '0004', "00000006"]
)
changePortRequest = ''.join(
    [ChangeRequest, '0004', "00000002"]
)

# There are two groups of servers - change and map.
# change means it supports nat testing.
# map means it only supports standard bind requests.
# Servers are further divided by protocol (dgram or stream)
# and by IP type = ipv4 or ipv6.
def get_stun_servers(af, proto=socket.SOCK_DGRAM, group="change", do_shuffle=0):
    servers = STUN_SERVER_INDEX[group][proto][af][:]
    if do_shuffle:
        random.shuffle(servers)

    return servers

# Make a random transaction ID -- using in bind requests.
# Kind of like a poor-mans sequence number for UDP packets.
# Not that useful when TCP is used with the servers.
def gen_tran_id():
    return rand_b(16)

# Filter all other messages that don't match this.
def tran_info_patterns(src_tup=None):
    tranid = gen_tran_id()
    b_msg_p = b".{4}" + re.escape(tranid)
    b_addr_p = b"%s:%d" % (
        re.escape(
            to_b(src_tup[0])
        ),
        src_tup[1]
    )

    return [b_msg_p, b_addr_p, tranid]

# Extract either IPv4 or IPv6 addr from STUN attribute.
def extract_addr(buf, af=socket.AF_INET, base=20):
    # Config for ipv4 and ipv6.
    if af == socket.AF_INET:
        seg_no = 4
        seg_size = 1
        delim = "."
        form = lambda x: str(int(to_h(x), 16))
    else:
        seg_no = 8
        seg_size = 2
        delim = ":"
        form = lambda x: str(to_h(x))

    # Port part.
    p = 6
    port = int(to_h(buf[base + p:base + p + 2]), 16)
    p += 2

    # Binary encodes pieces of address.
    segments = []
    for i in range(0, seg_no):
        part = form(buf[base + p:base + p + seg_size])
        segments.append(part)
        p += seg_size

    # Return human readable version.
    ip = delim.join(segments)
    return [ip, port]

# Check whether a STUN reply is correct.
def stun_check_reply(dest_addr, reply, lax=0):
    try:
        if reply is None:
            return "> STUN reply is none."

        # They replied, go to next test.
        if not reply['resp']:
            return "> STUN get_nat_type first nat test failure"

        # Sanity checking.
        check_fields = [
            'rip', 'rport',
        ]
        for field in check_fields:
            if reply[field] is None:
                return "STUN field %s is None, try again" % (field)

        # External port must be valid port.
        if not valid_port(reply['rport']):
            return "STUNs external port was invalid"

        # Additional fields to check.
        if not lax:
            check_fields = [
                'cip', 'cport',
            ]
            for field in check_fields:
                if reply[field] is None:
                    return "STUN field %s is None, try again" % (field)

            try:
                # If the servers changed address matches its source
                # then it only has one IP and can't be used for the full tests
                if reply["sip"] is not None:
                    if ip_f(reply['cip']) == ip_f(reply["sip"]):
                        return "STUN server only had one address"

                # STUN servers changed IP was the same as the destination address.
                if ip_f(reply['cip']) == ip_f(dest_addr.target()):
                    return "STUN server only had one address"
            except Exception:
                return "STUN ip invalid when given to ip_f"

            # Some STUN servers return local addresses for the changed address.
            # They could be either malicious or misconfigured.
            if not IS_DEBUG:
                if ipaddress.ip_address(reply['cip']).is_private:
                    return "STUNs changed address is private"

            # Filter out this junk IP.
            if reply["cip"] == "8.8.8.8":
                return "STUN change ip was 8.8.8.8"

            # Changed port must be valid port.
            if not valid_port(reply['cport']):
                return "STUNs changed port was invalid"

            # Must be unique to differentiate port tests.
            if reply['cport'] == dest_addr.port:
                return "STUNs changed port same as dest"

        return 0
    except Exception as e:
        return "STUNs check reply unknown error e = %s" % (str(e))

# Send a valid stun request to a server
# and process the reply.
async def do_stun_request(pipe, dest_addr, tran_info, extra_data="", changed_addr=None, conf=STUN_CONF):
    assert(dest_addr is not None)
    ret = {
        # Got response or not.
        'resp': False,

        # Our external IP.
        'rip': None,

        # Our externally mapped port.
        'rport': None,

        # Our local port.
        'lport': pipe.sock.getsockname()[1],

        # Our local IP.
        'lip': pipe.sock.getsockname()[0],

        # Servers IP address.
        'sip': None,

        # Servers reply port.
        'sport': None,

        # IP server will send change requests from.
        'cip': None,

        # Port server will send change requests from.
        'cport': None
    }

    # Sanity checking.
    if pipe is None:
        log("> STUN skipping get nat port mapping - s = None")
        return ret

    # Init values.
    str_len = to_hs( struct.pack("!h", int(len(extra_data) / 2)) )
    str_data = ''.join([BindRequestMsg, str_len, to_h(tran_info[2]), extra_data])
    data = binascii.a2b_hex(str_data)
    recvCorr = False
    recieved = False

    # Convenience function to call on failure or complete.
    def handle_cleanup(ret, msg="ok"):
        log("> STUN do request status = %s" % (msg))

        if msg != "ok":
            ret['resp'] = False

        return ret

    # Keep trying to get through.
    log("> STUN do request dest = {}:{}".format(*dest_addr.tup))
    for i in range(0, conf["packet_retry"]):
        try:
            # Send request.
            # Multiplexed for UDP stream.
            # For TCP the dest addr arg is ignored.
            if not await pipe.stream.send(data, dest_addr.tup):
                log("STUN req send all unknown error.")
                continue

            # Receive response -- but only
            # expect a certain client addr.
            buf = await pipe.recv(
                tran_info[:2],
                timeout=conf["recv_timeout"]
            )

            # Error or timeout.
            if buf is None:
                raise asyncio.TimeoutError("STUN recv n timeout.")

            # Check buffer is min length to avoid overflows.
            if len(buf) < 20:
                log("Invalid buf len in main STUN res.")
                continue

            # Only support certain message type.
            msgtype = to_h(buf[0:2])
            if msgtype not in dictValToMsgType:
                log("> STUN unknown msg type %s" % (to_s(msgtype)))
                continue

            # Process response
            # Only interested in bind responses tho.
            bind_resp_msg = dictValToMsgType[msgtype] == "BindResponseMsg"
            tranid_match = tran_info[2] == buf[4:20]
            if bind_resp_msg and tranid_match:
                # Extract length of message attributes.
                len_message = int(to_h(buf[2:4]), 16)
                len_remain = len_message

                # Avoid overflowing buffer.
                if len(buf) - 20 < len_message:
                    log("> Invalid message length recv for stun reply.")
                    continue

                # Start processing message attributes.
                log("> stun parsing bind = %d" % len_remain)
                base = 20
                recvCorr = True
                ret['resp'] = True
                while len_remain > 0:
                    # Avoid overflow for attribute parsing.
                    if base + 4 >= len(buf):
                        log("> new attr field overflow")
                        break

                    # Extract attributes from message buffer.
                    attr_type = to_h(buf[base:(base + 2)])
                    attr_len = int(to_h(buf[(base + 2):(base + 4)]), 16)

                    # Avoid attribute overflows.
                    if attr_len <= 0:
                        log("> STUN attr len")
                        break
                    if attr_len + base + 4 > len(buf):
                        log("> attr len overflow")
                        break

                    # Log attribute type.
                    log("> STUN found attribute type = %s" % (to_s(attr_type)))

                    # Your remote IP and reply port. The important part.
                    if attr_type == MappedAddress:
                        ip, port = extract_addr(buf, dest_addr.chosen, base)
                        ret['rip'] = ip
                        ret['rport'] = port
                        log(f"set mapped address {ip}:{port}")

                    # Original address of the server. Not really that important.
                    if attr_type == SourceAddress:
                        ip, port = extract_addr(buf, dest_addr.chosen, base)
                        ret['sip'] = ip
                        ret['sport'] = port
                        log(f"set SourceAddress {ip}:{port}")

                    # Address that the STUN server would send change reqs from.
                    if attr_type == ChangedAddress:
                        ip, port = extract_addr(buf, dest_addr.chosen, base)
                        ret['cip'] = ip
                        ret['cport'] = port
                        log(f"set ChangedAddress {ip}:{port}")

                    base = base + 4 + attr_len
                    len_remain -= (4 + attr_len)

                break
            else:
                log("> not bind respond msg and tran id match %s %s %s" % (
                    to_s(dictValToMsgType[msgtype]),
                    to_h(tran_info[2]),
                    to_h(buf[4:20]).upper()
                )
                )
        except asyncio.TimeoutError as e:
            log("> STUN get nat port map.. sendto e = %s, timeout = %s" % (str(e), str(conf["recv_timeout"])))

        # Allow other coroutines to do work.
        await asyncio.sleep(0.5)

    return handle_cleanup(ret)    

# Build new pipe or return existing ones
# based on proto. Handle initialization.
async def init_pipe(dest_addr, interface, af, proto, source_port, local_addr=None, conf=STUN_CONF):
    # Make a new socket if this is the first time running.
    assert(dest_addr is not None)

    """
    # Will throw address reuse errors until the port
    # becomes available again. Keep trying to bind until
    # it succeeds -- there's no other way for TCP.
    # This makes determining NAT type via TCP much slower than
    # for UDP. Especially considering multiple tests are done.
    """
    if local_addr is None:
        route = interface.route(af)
        """
        ipr = get_pub_ipr_from_list(route.nic_ips)
        if ipr is not None:
            ips = ipr_norm(ipr)
        else:
            ips = route.nic()
        """

        local_addr = await route.bind(source_port)

    pipe = await pipe_open(
        route=local_addr,
        proto=proto,
        dest=dest_addr,
        conf=conf
    )

    return pipe   

async def stun_check_addr_info(stun_host, stun_port, af, proto, interface, local_addr=None):
    # Load details from local_addr.
    if local_addr is not None:
        route = local_addr
    else:
        route = interface.route(af)

    # Resolve host to ips.
    try:
        dest_addr = await Address(
            stun_host,
            stun_port,
            route,
            proto,
        ).res()
    except Exception as e:
        # Unable to find A or AAA record for address family.
        log("> STUN get_nat_type can't load A/AAA %s" % (str(e)))
        return None

    # No IP address returned for server.
    if dest_addr.target() is None:
        log("> STUN get_nat_type domain a records empty")
        return None

    # If the stun server resolves to a local address then skip it.
    if not IS_DEBUG:
        if ipaddress.ip_address(dest_addr.target()).is_private:
            log("> STUN get_nat_type skipping private dns ip")
            return None

    return dest_addr

# Code for doing a single NAT test with logging.
async def stun_sub_test(msg, dest, interface, af, proto, source_port, changed, extra="", pipe=None, tran_info=None, local_addr=None, conf=STUN_CONF):
    log("> STUN %s" % (msg))

    # Set transaction ID if no match function provided.
    if tran_info is None:
        tran_info = tran_info_patterns(changed.tup)

    # New con for every req if it's TCP.
    if proto == TCP:
        if pipe is not None:
            await pipe.close()
            pipe = None

    # Build sock if none provided.
    if pipe is None:
        # Get new sock with a timeout.
        # The timeout is really only useful for TCP connect.
        pipe = await init_pipe(
            dest,
            interface,
            af,
            proto,
            source_port, 
            local_addr=local_addr,
            conf=conf
        )

        # Check for succcess or not.
        if pipe is None:
            return None, None

    pipe.subscribe(tran_info[:2])
    return await async_wrap_errors(
        do_stun_request(
            pipe,
            dest,
            tran_info,
            extra,
            changed_addr=changed,
            conf=conf
        )
    ), pipe

"""
Does multiple sub tests to determine NAT type.
It will differ dest ips, reply ips and/or reply ports.
Reply success or failure + external ports reported
by servers are used to infer the type of NAT.
Note: complete resolution of NAT type is only
possible with proto = SOCK_DGRAM. This is because
the router doesn't just allow inbound connects
that either haven't been forwarded or
contacted specifically.
"""
async def do_nat_test(stun_addr, interface, af=IP4, proto=UDP, group="change", do_close=1, conf=STUN_CONF):
    # Important vars / init.
    test = {} # test[test_no] = test result
    source_port = 0
    pipe_list = []

    # Log errors, cleanup and retry.
    async def handle_error(msg, pipe_list, do_close=1):
        log("> STUN handle = %s" % (to_s(msg)))

        # Cleanup socket.
        if do_close:
            for pipe in pipe_list:
                if pipe is not None:
                    await pipe.close()

        # Error -- stun server failed.
        return [], None, None

    # Helper function to run a nat test.
    async def run_nat_test(pipe, nat_test, tran_info, conf):
        test_name, log_msg, dest_addr, test_addr, extra = nat_test
        ret, pipe = await stun_sub_test(
            log_msg,
            dest_addr,
            interface,
            af,
            proto,
            source_port,
            test_addr,
            extra,
            pipe=pipe,
            tran_info=tran_info,
            conf=conf
        )

        return [test_name, ret, pipe]

    # Do first NAT test.
    _, test[1], pipe = await run_nat_test(None, [
            1,
            "doing first nat test",
            stun_addr,
            stun_addr,
            ""
        ],
        tran_info_patterns(stun_addr.tup),
        conf
    )
    
    # Check first reply.
    error = stun_check_reply(stun_addr, test[1])
    if error or pipe is None:
        return await handle_error("invalid stun reply = %s" % (error), pipe_list)
    else:
        source_port = pipe.route.bind_port
        pipe_list.append(pipe)

    # Log changed port.
    log(
        "> STUN changed port = %d, stun port = %d" % (
            test[1]['cport'],
            stun_addr.port
        )
    )
    log(
        "> STUN t1 changed ip = %s" % (
            test[1]['cip']
        )
    )

    # List of nat tests to perform concurrently.
    # ID, log msg, dest addr, resp addr, extra req data.
    assert(stun_addr.tup[0] != test[1]['cip'])
    assert(stun_addr.tup[1] != test[1]['cport'])
    route = interface.route(af)
    nat_tests = [
        [
            2,
            "doing NAT test 2 - change req",
            stun_addr,
            await Address(
                test[1]['cip'],
                test[1]['cport'],
                route,
                proto
            ).res(),
            changeRequest
        ],
        [
            3,
            "doing NAT test 3 - to changed addr - reply expected",
            await Address(
                test[1]['cip'],
                stun_addr.port,
                route,
                proto
            ).res(),
            await Address(
                test[1]['cip'],
                stun_addr.port,
                route,
                proto
            ).res(),
            ""
        ],
        [
            4,
            "nat test 4",
            await Address(
                test[1]['cip'],
                stun_addr.port,
                route,
                proto
            ).res(),
            await Address(
                test[1]['cip'],
                test[1]['cport'],
                route,
                proto
            ).res(),
            changePortRequest
        ]
    ]

    # Schedule nat tests to run concurrently.
    tasks = []
    results = []
    for i, nat_test in enumerate(nat_tests):
        # Subscribe to certain messages.
        tran_info = tran_info_patterns(nat_test[3].tup)
        pipe.subscribe(tran_info[0:2])

        # Record the NAT test.
        tasks.append(run_nat_test(pipe, nat_test, tran_info, conf))

    # Check results and index them.
    results = await asyncio.gather(*tasks)
    for result in results:
        result_name, result_ret, _ = result
        if result_ret is None:
            return await handle_error("STUN %s failed" % (result_name), pipe_list)

        test[result_name] = result_ret

    # Used later on for nat test 3 code
    # The fields may not be set if there was no response.
    if test[1]['rip'] is None or test[3]['rip'] is None:
        return await handle_error("STUN rip missing", pipe_list)
    else:
        ip_check = ip_f(test[1]['rip']) == ip_f(test[3]['rip'])
        log("> STUN t1 rip = {} t3 rip = {}".format(
            test[1]['rip'],
            test[3]['rip']
        ))
    port_check = test[1]['rport'] == test[3]['rport']
    test3_dest = nat_tests[1][2]
    error = stun_check_reply(test3_dest, test[3])
    log("> STUN t1 rport = {} t3 rport = {}".format(
        test[1]['rport'],
        test[3]['rport']
    ))
    log("> STUN t2 resp = {}".format(test[2]['resp']))


    # Our local bind addr was equal to external address.
    # Server is directly open to internet.
    # TODO: this may be invalid?
    source_ip = pipe.route.bind_ip()
    log("> STUN source ip = {}".format(source_ip))
    if ip_f(test[1]['rip']) == ip_f(source_ip):
        if test[2]['resp']:
            # Got a reply back = completely open.
            log("> STUN open internet detected")
            typ = OPEN_INTERNET
        else:
            # Something is filtering replies.
            log("> STUN firewall detected")
            test[1]["resp"] = False
            typ = SYMMETRIC_UDP_FIREWALL
    else:
        # Got a reply from a different IP.
        # NAT opens mapping for source ip and port
        # Open to any remote host
        if test[2]['resp']:
            """
            It should be noted that a NAT that preserves the source port
            will also give a positive for this test though it may not
            be a full code NAT in reality. Preserving type NATs are
            accounted for in the mapping behaviour tests though.
            """
            log("> STUN full cone detected")
            typ = FULL_CONE
        else:
            # We're sending to the servers
            # advertised 'change address'
            # or its second address.
            # We should be able to get a reply.
            if error:
                # Exception -- replies should be possible to receive if we send.
                return await handle_error("invalid stun reply = %s" % (error), pipe_list)
            else:
                # NAT reuses port mappings based on source ip and port.
                # These conditions apply to test 3.
                if ip_check and port_check:
                    # Check results.
                    if test[4]['resp']:
                        # NAT reuses port mappings based on src ip and port
                        # dest host most be white listed and can send from any port.
                        log("> STUN restrict nat detected")
                        typ = RESTRICT_NAT
                    else:
                        # NAT reuses mappings based on src ip and port
                        # Dest host must be white listed and send from same port.
                        log("> STUN restricted port detected")
                        test[1]['resp'] = False
                        typ = RESTRICT_PORT_NAT
                else:
                    # NAT maps different external ports based on outgoing host.
                    log("> STUN symmetric nat detected")
                    typ = SYMMETRIC_NAT

    # Port mappings may still be predictable if NAT
    # Uses an increasing delta value for successive cons
    # Simultaneous open will test this.
    # Note: SymmetricNAT, SymmetricUDPFirewall
    pipe_list, _, _ = await handle_error(
        "stun test success",
        pipe_list,
        do_close
    )

    return pipe_list, typ, test[1]

# Basic interface to the most useful functions.
class STUNClient():
    def __init__(self, interface, af=IP4, sock_timeout=2, consensus=[1, 1], proto=UDP):
        self.interface = interface
        self.af = af
        self.proto = proto
        self.sock_timeout = sock_timeout

        # Threshold / Number = agreement.
        self.t, self.n = consensus

    """
    Internal function - don't use directly.
    I liek the cat.

    This function has two main modes:
    - regular
    - fast fail

    Regular is designed to use UDP and it will have access to
    far more servers. But the disadvantage is when using
    interfaces that you don't know have a route to the Internet
    you won't know straight away if it works.

    Fast fail uses TCP and will fail immediately if it can't
    do N connections in a row to different servers. This is
    very useful for rapidly determining whether an interface
    is routable via a certain 'address type'.
    """
    async def _get_field(self, name, af, proto, interface, source_port=0, group="map", alt_port=0, do_close=0, fast_fail=0, servers=None, local_addr=None, conf=STUN_CONF):
        # Record start time and define fail result funv.
        random.seed()
        start_time = time.time()
        f_fail = lambda: [None, None, time.time() - start_time]
        use_proto = TCP if fast_fail else proto
        lax = 0 if group == "change" else 1

        # Limit at 20 to avoid massive delays.
        # If 20 consecutive servers fail
        # something else is wrong.
        servers = servers or get_stun_servers(af, proto, group)
        stun_addr = None
        for server in servers:
            for i in range(conf["retry_no"]):
                # Get a valid STUN Address.
                for j in range(conf["addr_retry"]):
                    # Basic server address check.
                    stun_port = 3479 if alt_port else server[1]

                    # Resolve address with a timeout.
                    try:
                        stun_addr = await asyncio.wait_for(
                            stun_check_addr_info(
                                server[0],
                                stun_port,
                                af,
                                proto,
                                interface,
                                local_addr
                            ),
                            conf["dns_timeout"]
                        )
                    except asyncio.TimeoutError:
                        log("> stun addr_task timeout in _getfield")
                        stun_addr = None
                        continue

                    # Check address was resolved.
                    if stun_addr is None:
                        log("> get field error stun addr is None")
                        continue

                    break

                # Monitor basic loop exit.
                if stun_addr is None:
                    continue

                # Do stun test.
                msg = "doing stun sub test for %s" % (name)
                ret = await stun_sub_test(msg, stun_addr, interface, af, proto, source_port, stun_addr, "", local_addr=local_addr, conf=conf)
                nat_info, pipe = ret

                # Check response.
                error = stun_check_reply(stun_addr, nat_info, lax)
                stop_time = time.time() - start_time
                if error:
                    log("> get field error = %s" % (str(error)))
                    if pipe is not None:
                        log("> closing stream get field")
                        await pipe.close()
                        pipe = None

                    continue

                # Return IP section of STUN reply.
                if do_close:
                    if pipe is not None:
                        await pipe.close()
                        pipe = None

                # Return results.
                stop_time = time.time() - start_time
                if name == "nat_info":
                    # Valid STUN reply has main fields set.
                    stun_fields = ["rip", "rport", 'lport', 'lip']
                    do_continue = False
                    for stun_field in stun_fields:
                        if nat_info[stun_field] is None:
                            do_continue = True
                            break

                    # Field wasn't properly set.
                    if do_continue:
                        continue
                    else:
                        return nat_info, pipe, stop_time
                else:
                    # Field wasn't set in STUN reply.
                    if nat_info[name] is None:
                        continue
                    else:
                        return nat_info[name], pipe, stop_time

        # Retry failed.
        return f_fail()

    async def get_nat_type(self, af=None, servers=None):
        if self.proto != UDP:
            raise Exception("NAT type test requires udp proto.")

        # Setup conf for NAT type.
        conf = copy.deepcopy(STUN_CONF)
        conf["packet_retry"] = 3
        #conf["recv_timeout"] = 4
        conf["addr_retry"] = 6
        #conf["retry_no"] = 3
        #conf["consensus"] = [3, 5]

        # Main function defaults.
        interface = self.interface
        threshold_n = conf["consensus"][0] or self.n
        threshold_t = conf["consensus"][1] or self.t
        group = "change"
        af = af or self.af
        servers = servers or get_stun_servers(
            af,
            self.proto,
            group,
            0
        )

        # Do NAT test with retry.
        async def nat_test_with_retry(servers, interface, conf):
            # Try find a valid STUN server -- max 20 rand attempts.
            random.seed()
            stun_addr = None
            for j in range(conf["retry_no"]):
                for i in range(conf["addr_retry"]):
                    server = random.choice(servers)
                    try:
                        stun_addr = await asyncio.wait_for(
                            stun_check_addr_info(
                                server[0],
                                server[1],
                                af,
                                self.proto,
                                interface
                            ),
                            conf["dns_timeout"]
                        )
                        break
                    except asyncio.TimeoutError:
                        stun_addr = None
                        continue

                # Check it was set or skip this test.
                if stun_addr is None:
                    continue

                # Do the nat test.
                ret = await do_nat_test(
                    stun_addr,
                    self.interface,
                    af,
                    self.proto,
                    group,
                    do_close=1,
                    conf=conf
                )

                if ret[1] is not None:
                    return ret

        # Make list of tests for getting NAT type.
        tasks = []
        for i in range(threshold_n):
            # Go ahead and use that STUN addr for the test.
            tasks.append(
                nat_test_with_retry(servers, interface, conf)
            )

        # Return threshold results.
        f_filter = lambda r: [x[1] for x in r if isinstance(x[1], int)]
        return await threshold_gather(tasks, f_filter, threshold_t)

    async def get_wan_ip(self, af=None, interface=None, fast_fail=0, servers=None, local_addr=None, conf=STUN_CONF):
        # Defaults.
        af = af or self.af
        interface = interface or self.interface
        group = "map"

        # sock_timeout + interface added to be compatible
        # with other get wan ip functions -- ignored.
        log("> STUN trying to get WAN IP; af = %d, fast fail = %d" % (af, fast_fail))
        threshold_n = conf["consensus"][0] or self.n
        threshold_t = conf["consensus"][1] or self.t

        # Make list of tests for getting remote IP.
        tasks = []
        for i in range(threshold_n):
            tasks.append(
                self._get_field("rip", af, self.proto, interface, 0, group=group, do_close=1, fast_fail=fast_fail, servers=servers, local_addr=local_addr, conf=conf)
            )

        # Return threshold results.
        f_filter = lambda r: [x for x, _, _ in r if isinstance(x, str)]
        wan_ip = await threshold_gather(tasks, f_filter, threshold_t)
        if wan_ip is not None:
            return ip_norm(wan_ip)

    """
    Coming to consensus from multiple STUN results is not supported for
    get_mapping as it is expected for there to be differences in
    successive mappings as part of how NATs work.
    """
    async def get_mapping(self, proto, af=None, source_port=0, group="map", alt_port=0, do_close=0, fast_fail=0, servers=None, conf=STUN_CONF):
        # Defaults.
        af = af or self.af
        log("> stun mapping for proto = %d; af = %d" % (proto, af))

        # Get port mapping from first working server.
        interface = self.interface
        nat_info, s, run_time = await self._get_field("nat_info", af, proto, interface, source_port, group, alt_port, do_close, fast_fail, servers=servers, conf=conf)
        if nat_info is None:
            return [None, None, None, None, None, None]

        # Return mapping section of STUN reply.
        local = nat_info["lport"] or source_port
        mapped = nat_info["rport"]
        rip = nat_info["rip"]
        if mapped:
            mapped = int(mapped)

        return [interface, s, local, mapped, rip, run_time]

    async def get_nat_info(self):
        nat_type = await self.get_nat_type()

        # Delta not applicable for some NAT types.
        if nat_type == OPEN_INTERNET:
            delta = delta_info(NA_DELTA, 0)
        else:
            delta = await delta_test(self)
            
        return nat_info(nat_type, delta)
    
#######################################################################
if __name__ == "__main__": # pragma: no cover
    """
    Some custom STUN servers don't include the rip attribute
    for change requests -- in this case we issue get_wan_ips
    to both test addresses and use the result for the tests.
    for ip_check in [[1, stun_addr], [3, nat_tests[1][2]]]:
        n, addr = ip_check
        if test[n]['rip'] is None:
            ret, test_pipe = await stun_sub_test(
                "custom get ip for non conforming server",
                addr,
                interface,
                af,
                proto,
                0,
                addr,
                ""
            )

            print(ret)

            await test_pipe.close()
            test[n]['rip'] = ret['rip']

    # Filters out invalid servers based on response.
    async def get_valid_stun_servers(interface, af, proto, group="map", sock_timeout=2, check_change=0):
        return
        valid_servers = []
        extended_servers = []
        stun_servers = get_stun_servers(af, proto, group)
        for stun_server in stun_servers:
            dest_addr = await stun_check_addr_info(
                stun_server[0],
                stun_server[1],
                af,
                proto,
                stun_check_addr_info
            )
            if dest_addr is None:
                log("> STUN valid servers ... dest addr is none.")
                continue

            s, _ = await init_socket(dest_addr, interface, af, proto, 0)
            if s is None:
                log("> STUN valid servers ... first s is none.")
                continue

            # Get initial port mapping.
            # A response is expected.
            tran_info = tran_info_closure(dest_addr)
            s.subscribe(tran_info[1])
            nat_info = ret = await do_stun_request(
                s,
                dest_addr,
                tran_info
            )

            # Set source port.
            lax = not check_change
            error = stun_check_reply(dest_addr, ret, lax)
            if error:
                log("> STUN valid servers ... first reply error = %s." % (error))
                continue

            if check_change:
                changed_addr = await stun_check_addr_info(
                    ret["ChangcipedIP"],
                    dest_addr.port,
                    af,
                    proto,
                    interface
                )
                if changed_addr is None:
                    log("> STUN valid servers ... changed addr is none.")
                    continue

                s, _ = await init_socket(changed_addr, interface, af, proto, 0)
                if s is None:
                    log("> STUN valid servers ... second s is none.")
                    continue

                tran_info = tran_info_closure(changed_addr)
                s.subscribe(tran_info[1])
                ret = await do_stun_request(
                    s,
                    changed_addr,
                    tran_info
                )

                # Check reply.
                error = stun_check_reply(changed_addr, ret, lax)
                if error:
                    log("> STUN valid servers ... error 2 = %s." % (error))
                    continue

            extended_servers.append(
                [stun_server[0], nat_info["cport"]]
            )
            extended_servers.append(
                [ret["cip"], ret["cport"]]
            )

            valid_servers.append([stun_server[0], stun_server[1]])

        return valid_servers, extended_servers
    """

    async def test_stun_client():
        from .interface import Interface, load_interfaces, init_p2pd


        # Maybe has a turn server.
        # https://wiki.innovaphone.com/index.php?#title=Howto:Innovaphones_public_services#TURN
        server = ['stun.innovaphone.com', 3478]

        netifaces = await init_p2pd()


        i = await Interface().start_local()
        s = STUNClient(interface=i, proto=UDP)
        out = await s.get_nat_type()
        print(out)
        out = await s.get_mapping(proto=TCP)
        print(out)

        i = await Interface().start()
        print(i)

        return



        """
        if there's no default route for an af then the route
        func should skip it.
        """

        """
        r = interface.route()
        await r.bind()
        print(r.bind.ip)
        print(r.bind.port)
        return
        """

        stun_client = STUNClient(
            interface,
            af,
            consensus=[1, 1]
        )


        # Which bind IP for ip4?
        # How to do the open internet check?


        route = await interface.rp[af].routes[0].bind()
        ret = await stun_client.get_wan_ip(local_addr=route)
        #ret = await stun_client.get_nat_type()
        print(ret)
        return
        nat = await stun_client.get_nat_info()
        print(nat)
        #print(ret)
        return

        ret = await stun_client.get_mapping(proto)
        print(ret)
        #return

    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(test_stun_client())
    loop.close()

