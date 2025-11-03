from struct import pack
import hmac
import socket
import hashlib
import socket
from ...utility.utils import *
from ...net.net_utils import *

STUN_CHANGE_NONE = 1
STUN_CHANGE_PORT = 2
STUN_CHANGE_BOTH = 3
STUN_MAGIC_COOKIE = b"\x21\x12\xA4\x42"
STUN_MAGIC_XOR = b'\x00\x00\x21\x12' + STUN_MAGIC_COOKIE
RFC3489 = 1
RFC5389 = 2
RFC8489 = 3

def _get_const_name(cls, val, type_: type) -> str:
    for attr_name in dir(cls):
        attr = getattr(cls, attr_name)
        if isinstance(attr, type_) and attr == val:
            return attr_name
    return ''

class STUNMsgTypes:
    Reversed            = b"\x00\x00" # RFC5389
    Binding             = b"\x00\x01"
    SharedSecret        = b"\x00\x02" # Reserved - RFC5389
    
    # https://tools.ietf.org/html/rfc5766#section-13
    # https://datatracker.ietf.org/doc/html/draft-rosenberg-midcom-turn-08#section-9.1
    Allocate            = b"\x00\x03"
    Refresh             = b"\x00\x04"
    Send                = b"\x00\x06" # 4 or 6? send was previously wrong
    SendResponse        = b"\x01\x04"
    DataIndication      = b"\x01\x15"
    Data                = b"\x00\x07"
    CreatePermission    = b"\x00\x08"
    ChannelBind         = b"\x00\x09"

    # https://tools.ietf.org/html/rfc6062#section-6.1
    Connect             = b"\x00\x0a" # RFC6062
    ConnectionBind      = b"\x00\x0b" # RFC6062
    ConnectionAttempt   = b"\x00\x0c" # RFC6062

    get = classmethod(lambda cls, val, type_=int: _get_const_name(cls, val, type_))

class STUNAttrs:
    Reserved            = b"\x00\x00" # RFC5389
    MappedAddress       = b"\x00\x01" # RFC5389
    ResponseAddress     = b"\x00\x02" # Reserved - RFC5389
    ChangeRequest       = b"\x00\x03" # Reserved - RFC5389
    SourceAddress       = b"\x00\x04" # Reserved - RFC5389
    ChangedAddress      = b"\x00\x05" # Reserved - RFC5389
    Username            = b"\x00\x06" # RFC5389
    Password            = b"\x00\x07" # Reserved - RFC5389
    MessageIntegrity    = b"\x00\x08" # RFC5389
    ErrorCode           = b"\x00\x09" # RFC5389
    UnknownAttribute    = b"\x00\x0A" # RFC5389
    ReflectedFrom       = b"\x00\x0B" # Reserved - RFC5389


    ChannelNumber       = b"\x00\x0C" # RFC5766
    Lifetime            = b"\x00\x0D" # RFC5766
    Bandwidth           = b"\x00\x10" # Reserved - RFC5766
    DestinationAddress  = b"\x00\x11"

    XorPeerAddress      = b"\x00\x12" # RFC5766
    Data                = b"\x00\x13" # RFC5766

    Realm               = b"\x00\x14" # RFC5389
    Nonce               = b"\x00\x15" # RFC5389
    
    XorRelayedAddress   = b"\x00\x16" # RFC5766
    EvenPort            = b"\x00\x18" # RFC5766
    RequestedTransport  = b"\x00\x19" # RFC5766
    RequestedAddress    = b"\x00\x17" # draft-ietf-behave-turn-ipv6
    DontFragment        = b"\x00\x1A" # RFC5766

    XorMappedAddress    = b"\x00\x20" # RFC5389

    TimerVal            = b"\x00\x21" # Reserved - RFC5766
    ReservationToken    = b"\x00\x22" # RFC5766

    ConnectionID        = b"\x00\x2A" # RFC6062

    XorMappedAddressX   = b"\x80\x20"
    Software            = b"\x80\x22" # RFC5389
    AlternateServer     = b"\x80\x23" # RFC5389
    Fingerprint         = b"\x80\x28" # RFC5389
    UnknownAddress2     = b"\x80\x2b"
    UnknownAddress3     = b"\x80\x2c"
    
    get = classmethod(lambda cls, val, type_=bytes: _get_const_name(cls, val, type_))

class STUNMsgCodes:
    Request     = b"\x00\x00"
    Indication  = b"\x00\x10"
    SuccessResp = b"\x01\x00"
    ErrorResp   = b"\x01\x10"

    get = classmethod(lambda cls, val, type_=int: _get_const_name(cls, val, type_))

class STUNAddrTup:
    def __init__(self, ip=None, port=None, af=IP4, txid=b"", magic_cookie=STUN_MAGIC_XOR):
        self.ip = ip
        self.port = port 
        self.af = af
        self.txid = txid
        self.magic_cookie = magic_cookie
        self.tup = ()

    def get_family_buf(self):
        if self.af == IP4:
            return b"\0\1"
        else:
            return b"\0\2"
        
    @staticmethod
    def get_addr_bufs(af, attr_data):
        port_buf = attr_data[2:4]
        if af == IP4:
            ip_buf = attr_data[4:8]
        else:
            ip_buf = attr_data[4:20]

        return (ip_buf, port_buf)
    
    @staticmethod
    def addr_bufs_to_tup(af, ip_buf, port_buf):
        port = b_to_i(port_buf, 'big')
        ip = socket.inet_ntop(af, ip_buf)
        return (ip, port)

    def decode(self, code, data):
        # Get field bufs.
        ip_buf, port_buf = STUNAddrTup.get_addr_bufs(self.af, data)

        # XORed per individual fields.
        if code == STUNAttrs.XorMappedAddressX:
            # Get field bufs.
            ip_buf, port_buf = STUNAddrTup.get_addr_bufs(self.af, data)

            # UnXOR.
            mask = self.magic_cookie + self.txid
            port_buf = xor_bufs(port_buf, mask)
            ip_buf = xor_bufs(ip_buf, mask)

        # XORed starting from the port to the IP.
        codes = [
            STUNAttrs.XorMappedAddress,
            STUNAttrs.XorPeerAddress,
            STUNAttrs.XorRelayedAddress,
        ]
        if code in codes:
            mask = b'\x00\x00\x21\x12' + self.magic_cookie + self.txid
            if len(self.txid):
                data = xor_bufs(data, mask)

            # Get field bufs.
            ip_buf, port_buf = STUNAddrTup.get_addr_bufs(self.af, data)

        # Convert to correct format.
        self.tup = STUNAddrTup.addr_bufs_to_tup(self.af, ip_buf, port_buf)
        return ip_buf, port_buf, data
    
    def encode(self, code):
        # Convert IP address to binary.
        family = self.get_family_buf()
        if family == b"\0\1":
            ip_b = socket.inet_pton(
                socket.AF_INET,
                self.ip
            )
        else:
            ip_b = socket.inet_pton(
                socket.AF_INET6,
                self.ip
            )

        # Avoid copying fields as much as possible.
        buf = bytearray().join([
            family,
            memoryview(pack('!H', self.port)),
            ip_b
        ])

        dec_ip, dec_port, dec_buf = self.decode(code, buf)

        # Decode moved to XOR across whole buffer so use that.
        if dec_buf != buf:
            return dec_buf
        else:
            # Decode moved to encode IP and port segments manually.
            # Amend fields.
            if dec_port != dec_port:
                return bytearray().join([
                    family,
                    dec_port,
                    dec_ip
                ])

        return buf
    
    def pack(self, ip, port, af):
        inst = STUNAddrTup(ip=ip, port=port, af=af, xor_extra=self.xor_extra, magic_cookie=self.magic_cookie)
        return inst.encode()

    def unpack(self, code, data):
        inst = STUNAddrTup(af=self.af, txid=self.txid, magic_cookie=self.magic_cookie)
        inst.decode(code, data)
        return inst

    def __str__(self):
        return '{}:{}'.format(self.ip, self.port)

class STUNMsg:
    def __init__(self, msg_type=STUNMsgTypes.Binding, msg_code=STUNMsgCodes.Request, mode=RFC3489):
        self.msg_code = msg_code
        self.msg_type = msg_type # type: int
        self.msg_len = 0 # type: int
        self.txn_id = rand_b(12) # type: bytes
        self.msg = bytearray()
        self.attr_cursor = 0 # type: int
        self.mode = mode

        # To enable RFC 3489 compatibility the magic cookie is
        # intentionally set to an incorrect value.
        if self.mode == RFC3489:
            self.magic_cookie = b'1234'
        else:
            self.magic_cookie = STUN_MAGIC_COOKIE

    def reset_attr(self):
        self.msg_len = 0
        self.msg = bytearray()

    def write_attr(self, attr: bytes, *data, fmt: str = None):
        # process data -> bytes
        if fmt:
            data = pack(fmt, *data)
        else:
            data = data[0]
            if isinstance(data, STUNAddrTup):
                data = data.encode(STUNAttrs.XorMappedAddress)

        # Rule of 4:
        # https://tools.ietf.org/html/rfc5766#section-14
        padding = b""
        if len(data) % 4 != 0:
            padding = b'\x00' * (4 - len(data) % 4)

        buf = bytearray().join([
            memoryview(attr),
            memoryview(pack("!H", len(data))),
            memoryview(data),
            memoryview(padding)
        ])

        self.msg_len += len(buf)
        self.msg += buf

    def write_credential(self, username: str, realm: str, nonce: bytes = b''):
        self.write_attr(STUNAttrs.Username, username)
        self.write_attr(STUNAttrs.Realm, realm)
        self.write_attr(STUNAttrs.Nonce, nonce)

    def _hmac(self, key: bytes, msg: bytes) -> bytes:
        hashed = hmac.new(key, msg, hashlib.sha1)
        return hashed.digest()
    
    def write_hmac(self, key: bytes):
        self.msg_len += 24
        msg_hmac = self.pack()
        self.msg_len -= 24
        self.write_attr(STUNAttrs.MessageIntegrity, self._hmac(key, msg_hmac))

    def eof(self) -> bool:
        return self.attr_cursor >= self.msg_len - 1

    def read_attr(self) -> tuple:
        # Process serialized attribute chunk using pointers.
        msg = memoryview(self.msg)
        msg_len = len(msg)
        m_attr = m_len = m_data = None
        if msg_len and self.attr_cursor + 3 <= msg_len - 1:
            # Unpack first two fields of an attribute.
            attr_hdr = msg[self.attr_cursor:self.attr_cursor + 4]
            m_attr = attr_hdr[0:2]
            m_len = b_to_i(attr_hdr[2:4], 'big')

            # Avoid overflows for attribute data.
            self.attr_cursor += 4
            if m_len:
                if self.attr_cursor + (m_len - 1) <= msg_len - 1:
                    # Get attribute data.
                    m_data = msg[self.attr_cursor:self.attr_cursor + m_len]

                    # Rule of block 4: 
                    # https://tools.ietf.org/html/rfc5766#section-14
                    attr_pad = 0
                    if m_len % 4 != 0:
                        attr_pad = 4 - m_len % 4

                    # Increase attribute pointer.
                    self.attr_cursor += m_len + attr_pad
                else:
                    raise Exception("TURN attribute len invalid.")

        # Return results.
        return m_attr, m_len, m_data 

    def __bytes__(self):
        return b''

    def pack(self) -> bytes:
        # Starting with RFC 5389 and on a more complex
        # bit scheme is used for the message type.
        if self.mode != RFC3489:
            msg_type = b_and(b_or(self.msg_type, self.msg_code), b"\x3F\xFF")
        else:
            #print("rfc34553")
            msg_type = self.msg_type

        return bytes().join([
            msg_type,
            pack("!H", self.msg_len),
            self.magic_cookie,
            self.txn_id,
            self.msg
        ])

    def decode(self, msg: memoryview) -> memoryview:
        # Unpack data from buffer using memory views.
        msg_len = len(msg)
        self.attr_cursor = 0
        if msg_len >= 20:
            # Unpack message fields.
            self.msg_type = msg[0:2]
            self.msg_len = b_to_i(msg[2:4], 'big')
            self.magic_cookie = msg[4:8]
            self.txn_id = msg[8:20]

            # Make sure message len accurately reflects size.
            if self.msg_len:
                if 20 + (self.msg_len - 1) <= msg_len - 1:
                    self.msg = msg[20:20 + self.msg_len]

                    # ret data left in buffer, usually NULL
                    return msg[20 + self.msg_len:]
                else:
                    raise Exception("Invalid length for STUN msg.")

    """
    def encode(cls, msg_type: bytes, msg: memoryview) -> memoryview:
        inst = cls(msg_type=msg_type, msg=msg, msg_len=len(msg))
        return inst.encode()
    """
    

    def unpack(msg, mode=RFC3489):
        inst = STUNMsg(mode=mode)
        buf = inst.decode(msg)
        return inst, buf