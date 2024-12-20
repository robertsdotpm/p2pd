import asyncio
from .gmqtt import Client as MQTTClient
from .net import *
from .settings import *

MQTT_CONF = dict_child({
    "con_timeout": 4,
    "recv_timeout": 4
}, NET_CONF)

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
        self.pending_tasks.append(
            create_task(
                async_wrap_errors(
                    self.f_proto(payload, self),

                    # Set a timeout of 20 seconds to do tasks.
                    # Make everything timeout and end if it meets this.
                    #20
                )
            )
        )

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
        client = MQTTClient(self.peer_id)
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
            5
        )

        return client

    async def close(self):
        if self.client is not None:
            await self.client.disconnect()

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