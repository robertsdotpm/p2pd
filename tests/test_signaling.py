from p2pd import *


class TestSignaling(unittest.IsolatedAsyncioTestCase):
    async def test_node_signaling(self):
        msg = "test msg"
        peerid = to_s(rand_plain(10))
        nic = await Interface()
        for af in nic.supported():
            for server in MQTT_SERVERS:
                

                if server[af] is None:
                    continue

                dest = (server[af], server["port"])
                found_msg = []

                client = await is_valid_mqtt(dest)

                if not client:
                    print(fstr("mqtt {0} {1} broken", (af, dest,)))
                else:
                    print(fstr("mqtt {0} {1} works", (af, dest,)))
                    break

                await client.close()

if __name__ == '__main__':
    main()