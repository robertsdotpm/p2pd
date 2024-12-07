import asyncio
import socket
import os
from .utils import *


async def create_datagram_endpoint(loop, protocol_factory,
                                   local_addr=None, remote_addr=None, *,
                                   family=0, proto=0, flags=0,
                                   reuse_port=None,
                                   allow_broadcast=None, sock=None):
    """Create datagram connection."""
    if sock is not None:
        if sock.type == socket.SOCK_STREAM:
            raise ValueError(
                fstr('A datagram socket was expected, got {0}', (sock,))
            )
        if (local_addr or remote_addr or
                family or proto or flags or
                reuse_port or allow_broadcast):
            # show the problematic kwargs in exception msg
            opts = dict(local_addr=local_addr, remote_addr=remote_addr,
                        family=family, proto=proto, flags=flags,
                        reuse_port=reuse_port,
                        allow_broadcast=allow_broadcast)
            problems = ', '.join(fstr('{0}={1}', (k, v,)) for k, v in opts.items() if v)
            raise ValueError(
                fstr('socket modifier keyword arguments can not be used ') +
                fstr('when sock is specified. ({0})', (problems,)))
        sock.setblocking(False)
        r_addr = None
    else:
        if not (local_addr or remote_addr):
            if family == 0:
                raise ValueError('unexpected address family')
            addr_pairs_info = (((family, proto), (None, None)),)
        elif hasattr(socket, 'AF_UNIX') and family == socket.AF_UNIX:
            for addr in (local_addr, remote_addr):
                if addr is not None and not isinstance(addr, str):
                    raise TypeError('string is expected')

            if local_addr and local_addr[0] not in (0, '\x00'):
                try:
                    if stat.S_ISSOCK(os.stat(local_addr).st_mode):
                        os.remove(local_addr)
                except FileNotFoundError:
                    pass
                except OSError as err:
                    # Directory may have permissions only to create socket.
                    log(
                        fstr(
                            'socket {0} {1)',
                            (local_addr, str(err),)
                        )
                    )

            addr_pairs_info = (((family, proto),
                                (local_addr, remote_addr)), )
        else:
            # join address by (family, protocol)
            addr_infos = {}  # Using order preserving dict
            for idx, addr in ((0, local_addr), (1, remote_addr)):
                if addr is not None:
                    if not (isinstance(addr, tuple) and len(addr) == 2):
                        raise TypeError('2-tuple is expected')

                    """
                    infos = await loop._ensure_resolved(
                        addr, family=family, type=socket.SOCK_DGRAM,
                        proto=proto, flags=flags, loop=loop)
                        
                    """
                    
                    infos = await loop.getaddrinfo(
                        *addr, family=family, type=socket.SOCK_DGRAM,
                        proto=proto, flags=flags)
                        
                    if not infos:
                        raise OSError('getaddrinfo() returned empty list')

                    for fam, _, pro, _, address in infos:
                        key = (fam, pro)
                        if key not in addr_infos:
                            addr_infos[key] = [None, None]
                        addr_infos[key][idx] = address

            # each addr has to have info for each (family, proto) pair
            addr_pairs_info = [
                (key, addr_pair) for key, addr_pair in addr_infos.items()
                if not ((local_addr and addr_pair[0] is None) or
                        (remote_addr and addr_pair[1] is None))]

            if not addr_pairs_info:
                raise ValueError('can not get address information')

        exceptions = []

        for ((family, proto),
             (local_address, remote_address)) in addr_pairs_info:
            sock = None
            r_addr = None
            try:
                sock = socket.socket(
                    family=family, type=socket.SOCK_DGRAM, proto=proto)
                if reuse_port:
                    _set_reuseport(sock)
                if allow_broadcast:
                    sock.setsockopt(
                        socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.setblocking(False)

                if local_addr:
                    sock.bind(local_address)
                if remote_addr:
                    if not allow_broadcast:
                        await loop.sock_connect(sock, remote_address)
                    r_addr = remote_address
            except OSError as exc:
                if sock is not None:
                    sock.close()
                exceptions.append(exc)
            except:
                if sock is not None:
                    sock.close()
                raise
            else:
                break
        else:
            raise exceptions[0]

    protocol = protocol_factory()
    #waiter = loop.create_future()
    waiter = asyncio.futures.Future(loop=loop)
    transport = loop._make_datagram_transport(
        sock, protocol, r_addr, waiter)
    if loop._debug:
        err_str = fstr("remote_addr={0} ", (remote_addr,))
        err_str += fstr("created: {0} {1} ", (str(transport), str(protocol),))
        if local_addr:
            err_str += fstr("Datagram endpoint local_addr={0} ", (local_addr,))
        
        log(err_str)
    try:
        await waiter
    except:
        transport.close()
        raise

    return transport, protocol
    
class EchoServerProtocol:
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        message = data.decode()
        print('Received %r from %s' % (message, addr))
        print('Send %r to %s' % (message, addr))
        self.transport.sendto(data, addr)
    
async def workspace():
    print("w")
    loop = asyncio.get_event_loop()
    tran, pro = await create_datagram_endpoint(
        loop,
        EchoServerProtocol,
        local_addr=('127.0.0.1', 9999),
    )
    print(tran, pro)
    while 1:
        await asyncio.sleep(0.1)
    
