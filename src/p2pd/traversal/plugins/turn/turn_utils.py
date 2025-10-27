from ....net.net import *
from ....settings import *
from ....utility.utils import *
from ....protocol.turn.turn_client import TURNClient

async def get_turn_client(af, serv_id, interface, dest_peer=None, dest_relay=None, msg_cb=None):
    # TODO: index by id and not offset.
    turn_server = TURN_SERVERS[serv_id]
    if turn_server[af] is None:
        raise Exception("Turn server does not support this AF.")

    # The TURN address.
    turn_addr = (
        turn_server["host"],
        turn_server["port"],
    )

    # Make a TURN client instance to whitelist them.
    turn_client = TURNClient(
        af=af,
        dest=turn_addr,
        nic=interface,
        auth=(turn_server["user"], turn_server["pass"]),
        realm=turn_server["realm"],
        msg_cb=msg_cb,
    )

    # Start the TURN client.
    # Raise timeout if it takes too long.
    await asyncio.wait_for(
        turn_client.start(),
        10
    )
    
    # Wait for our details.
    peer_tup  = await turn_client.client_tup_future
    relay_tup = await turn_client.relay_tup_future

    # Whitelist a peer if desired.
    if None not in [dest_peer, dest_relay]:
        await asyncio.wait_for(
            turn_client.accept_peer(
                dest_peer,
                dest_relay
            ),
            6
        )

    return peer_tup, relay_tup, turn_client

async def get_first_working_turn_client(af, offsets, nic, msg_cb):
    for offset in offsets:
        try: 
            peer_tup, relay_tup, turn_client = await get_turn_client(
                af,
                offset,
                nic,
                msg_cb=msg_cb,
            )

            turn_client.serv_offset = offset
            return turn_client
        except:
            log_exception()
            continue