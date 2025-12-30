import asyncio
from aionetiface import *
from ...vendor.gmqtt import Client as MQTTClient
from .signal_defs import *

async def f_proto_print(data):
    print(data)

class SignalMock():
    def __init__(self, peer_id, f_proto, mqtt_server, conf=MQTT_CONF):
        # Setup.
        self.peer_id = to_s(peer_id)
        self.conf = conf
        self.f_proto = f_proto
        self.sub_ready = asyncio.Event()
        self.mqtt_server = mqtt_server
        self.is_connected = False

        # Other.
        self.client = None

        # Tasks pending.
        self.pending_tasks = []

    def on_message(self, client, topic, payload, qos, properties):
        print("in sig mock on msg ")
        try:
            self.f_proto(payload, client, self)
        except Exception:
            log_exception() # todo disable what except

    def on_connect(self, client, flags, rc, properties):
        self.is_connected = True
        client.subscribe(self.peer_id, qos=2)

    def on_disconnect(self, client, packet, exc=None):
        log("Signal pipe disconnected.")

    def on_subscribe(self, client, mid, qos, properties):
        self.sub_ready.set()

    async def start(self):
        self.client = await self.get_client(self.mqtt_server)
        return self

    async def send(self, data, client_tup):
        await self.send_msg(data, client_tup)

    async def send_msg(self, msg, peer_id):
        log(fstr("> Send signal to {0} = {1}.", (peer_id, msg,)))        
        self.client.publish(
            to_s(peer_id),
            to_s(msg),
            qos=2,

            # Allow time for P2P protocol to finish.
            message_expiry_interval=120
        )
        if not self.is_connected:
            return 0
        else:
            return len(msg)

    async def echo(self, msg, dest_chan):
        out = fstr("ECHO {0} {1}", (self.peer_id, msg,))
        await self.send_msg(to_s(out), to_s(dest_chan))

    async def get_client(self, mqtt_server):
        """
        I've learned recently with a session ID anyone can use it and boot
        off the person using that session. Reusing session IDs or making them
        guessable is not how MQTT is meant to work. MQTT doesn't show
        session IDs of recived messages but I guess plain text mqtt leaks them.
        TODO: Use TLS only.
        """
        session_id = rand_plain(10)
        client = MQTTClient(session_id, clean_session=True)
        client.set_config({
            'reconnect_retries': -1,
            'reconnect_delay': 60
        })
        client.on_connect = self.on_connect
        client.on_message = self.on_message
        client.on_disconnect = self.on_disconnect
        client.on_subscribe = self.on_subscribe

        await asyncio.wait_for(
            client.connect(
                host=mqtt_server[0],
                port=mqtt_server[1]
            ),
            2
        )

        return client

    async def close(self):
        if self.client is not None:
            await self.client.disconnect()

async def is_valid_mqtt(dest):
    found_msg = asyncio.Queue()

    # Executed on receipt of a new MQTT message.
    def mqtt_proto_closure(ret):
        def mqtt_proto(payload, client_tup, signal_client):
            found_msg.put_nowait(payload)

        return mqtt_proto

    # Setup MQTT client with basic proto.
    mqtt_proto = mqtt_proto_closure(found_msg)
    peer_id = to_s(rand_plain(10))
    client = SignalMock(peer_id, mqtt_proto, dest)

    # Try to start client.
    client = await async_wrap_errors(
        client.start(),
        timeout=2
    )

    # Cannot get client reference. Return failure.
    if client is None:
        return None

    # Send message to self and try receive it.
    for _ in range(0, 3):
        await client.send_msg(peer_id, peer_id)

        # Allow time to receive responds.
        await asyncio.sleep(0.1)
        if not found_msg.empty(): break

    # Wait for a reply.
    try:
        out = await asyncio.wait_for(found_msg.get(), 4.0)
        await client.close()
        return client
    except asyncio.TimeoutError:
        return None

if __name__ == "__main__": # pragma: no cover
    async def f_proto(msg):
        print(type(msg))
        print(msg)

    async def test_signal_mock():
        peer_id = "sdfjk12j312j312j3qsafd"
        s = await SignalMock(peer_id, f_proto).start()

        await s.send_msg(b"test msg", peer_id)

        while 1:
            await asyncio.sleep(1)

    async_test(test_signal_mock)