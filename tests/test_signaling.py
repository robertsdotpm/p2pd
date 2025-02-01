from p2pd import *


class TestSignaling(unittest.IsolatedAsyncioTestCase):
    async def test_node_signaling(self):
        msg = "test msg"
        peerid = to_s(rand_plain(10))
        nic = await Interface()
        for af in nic.supported():
            for index in [-1, -2]:
                serv_info = MQTT_SERVERS[index]
                dest = (serv_info[af], serv_info["port"])
                found_msg = []

                def closure(ret):
                    async def f_proto(payload, client):
                        if to_s(payload) == to_s(msg):
                            found_msg.append(True)

                    return f_proto

                f_proto = closure(found_msg)
                client = await SignalMock(peerid, f_proto, dest).start()
                print(client)
                await client.send_msg(msg, peerid)
                await asyncio.sleep(2)

                if not len(found_msg):
                    print(fstr("mqtt {0} {1} broken", (af, dest,)))
                else:
                    print(fstr("mqtt {0} {1} works", (af, dest,)))

                await client.close()

if __name__ == '__main__':
    main()