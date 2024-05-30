
"""
If you do multiple calls with the api and dont sleep between them
the timestamp can end up being the same and get rejected by the client
it might make sense to for the update initialization to be done by the client
with an async sleep to ensure its always unique. the problem is only apparently for push and delete tho.

add random nonce that gets returned to help udp protocol
"""

from p2pd import *

"""
Don't use a fixed key so randoms can't screw with the tests.
Not that you want to run this on production anyway.
"""
PNP_LOCAL_SK = SigningKey.generate()
PNP_TEST_PORT = PNP_PORT + 1
PNP_TEST_NAME = b"pnp_test_name"
PNP_TEST_VALUE = b"pnp_test_value"

async def pnp_clear_tables():
    db_con = await aiomysql.connect(
        user=DB_USER, 
        password=DB_PASS,
        db=DB_NAME
    )

    async with db_con.cursor() as cur:
        await cur.execute("DELETE FROM names WHERE 1=1")
        await cur.execute("DELETE FROM ipv4s WHERE 1=1")
        await cur.execute("DELETE FROM ipv6s WHERE 1=1")
        await db_con.commit()
        
    db_con.close()

async def pnp_get_test_client_serv(v4_name_limit=V4_NAME_LIMIT, v6_name_limit=V6_NAME_LIMIT, min_name_duration=MIN_NAME_DURATION, v6_serv_ips="::1"):
    i = await Interface().start_local()
    serv_v4 = await i.route(IP4).bind(PNP_TEST_PORT, ips="127.0.0.1")
    serv_v6 = await i.route(IP6).bind(PNP_TEST_PORT, ips=v6_serv_ips)
    serv = await PNPServer(v4_name_limit, v6_name_limit, min_name_duration).listen_all(
        [serv_v4, serv_v6],
        [PNP_TEST_PORT],
        [TCP, UDP]
    )

    clients = {}
    dest_ips = {IP4: "127.0.0.1", IP6: v6_serv_ips}
    for af in VALID_AFS:
        route = i.route(af)
        dest = await Address(dest_ips[af], PNP_TEST_PORT, route)
        clients[af] = PNPClient(PNP_LOCAL_SK, dest)

    return clients, serv

async def pnp_cleanup_client_serv(client, serv):
    await serv.close()

class TestPNPFromServer(unittest.IsolatedAsyncioTestCase):
    async def test_pnp_insert_fetch_del(self):
        await pnp_clear_tables()
        clients, serv = await pnp_get_test_client_serv()
        for af in VALID_AFS: # VALID_AFS
            # Do insert.
            await clients[af].push(
                PNP_TEST_NAME,
                PNP_TEST_VALUE
            )

            # Test value was stored by retrieval.
            ret = await clients[af].fetch(PNP_TEST_NAME)
            update_x = ret.updated
            assert(ret.value == PNP_TEST_VALUE)
            assert(ret.vkc == clients[af].vkc)

            # Ensure new timestamp greater than old.
            await asyncio.sleep(2)

            # Do update.
            await clients[af].push(
                PNP_TEST_NAME,
                PNP_TEST_VALUE + b"changed"
            )

            # Test value was stored by retrieval.
            ret = await clients[af].fetch(PNP_TEST_NAME)
            update_y = ret.updated
            assert(ret.value == (PNP_TEST_VALUE + b"changed"))
            assert(ret.vkc == clients[af].vkc)
            print(update_y)
            print(update_x)
            assert(update_y > update_x)

            # Now delete the value.
            ret = await clients[af].delete(PNP_TEST_NAME)
            assert(ret.vkc == clients[af].vkc)

            # Test value was deleted.
            ret = await clients[af].fetch(PNP_TEST_NAME)
            assert(ret.value == None)
            assert(ret.vkc == clients[af].vkc)

        await serv.close()

    async def test_pnp_migrate_name_afs(self):
        async def is_af_valid(af):
            sql = "SELECT * FROM names WHERE name=%s AND af=%s"
            db_con = await aiomysql.connect(
                user=DB_USER, 
                password=DB_PASS,
                db=DB_NAME
            )

            is_valid = False
            async with db_con.cursor() as cur:
                await cur.execute(sql, (PNP_TEST_NAME, int(af)))
                row = await cur.fetchone()
                print(row)
                print(af)
                is_valid = row is not None

            db_con.close()
            return is_valid

        await pnp_clear_tables()
        clients, serv = await pnp_get_test_client_serv()
        for af_x in VALID_AFS:
            # Create the ini-tial value.
            await clients[af_x].push(
                PNP_TEST_NAME,
                PNP_TEST_VALUE
            )

            # Ensure AF is valid.
            is_valid = await is_af_valid(af_x)
            assert(is_valid)

            # Migrate the name to a different address.
            for af_y in VALID_AFS:
                if af_x == af_y:
                    continue

                # New signed updates need a higher time stamp.
                await asyncio.sleep(2)

                # Do the migration.
                await clients[af_y].push(
                    PNP_TEST_NAME,
                    PNP_TEST_VALUE
                )

                # Ensure the AF is valid.
                is_valid = await is_af_valid(af_y)
                assert(is_valid)

        await serv.close()

    async def test_pnp_name_pop_works(self):
        # Set test params needed for test
        vectors = [
            [IP4, 3],
            [IP6, 3]
        ]

        # 0, 1, 2 ... oldest = 0
        # 1, 2, 3 (oldest is popped)
        for af, name_limit in vectors:
            await pnp_clear_tables()
            clients, serv = await pnp_get_test_client_serv(3, 3, 0)

            # Fill the stack.
            for i in range(0, name_limit):
                await clients[af].push(f"{i}", "val")
                await asyncio.sleep(1)

            # Now pop the oldest.
            await clients[af].push(f"3", "val")
            await asyncio.sleep(1)

            # Now validate the values.
            for i in range(1, name_limit + 1):
                ret = await clients[af].fetch(f"{i}")
                assert(ret.value == b"val")

            # Oldest should be popped.
            ret = await clients[af].fetch(f"0")
            assert(ret.value == None)

            # Cleanup server.
            await serv.close()

    async def test_pnp_freshness_limit(self):
        name_limit = 3
        for af in VALID_AFS:
            await pnp_clear_tables()
            clients, serv = await pnp_get_test_client_serv(name_limit, name_limit)

            # Fill the stack past name_limit.
            for i in range(1, name_limit + 2):
                await clients[af].push(f"{i}", "val")
                await asyncio.sleep(1)

            # Check values still exist.
            for i in range(1, name_limit + 1):
                ret = await clients[af].fetch(f"{i}")
                assert(ret.value == b"val")

            # Check insert over limit rejected.
            ret = await clients[af].fetch("4")
            assert(ret.value == None)
            await serv.close()

    async def test_pnp_respect_owner_access(self):
        i = await Interface().start_local()
        await pnp_clear_tables()
        _, serv = await pnp_get_test_client_serv()

        alice = {}
        bob = {}
        for af in VALID_AFS:
            route = i.route(af)
            dest = await Address('localhost', PNP_TEST_PORT, route)
            alice[af] = PNPClient(SigningKey.generate(), dest)
            bob[af] = PNPClient(SigningKey.generate(), dest)

        test_name = b"some_name"
        alice_val = b"alice_val"
        for af in VALID_AFS:
            await alice[af].push(test_name, alice_val)
            await asyncio.sleep(2)

            # Bob tries to write to alices name with incorrect sig.
            await bob[af].push(test_name, b"changed val")
            await asyncio.sleep(2)

            # The changes aren't saved then.
            ret = await bob[af].fetch(test_name)
            assert(ret.value == alice_val)

        await serv.close()

    async def test_pnp_polite_no_bump(self):
        name_limit = 3
        for af in VALID_AFS:
            await pnp_clear_tables()
            clients, serv = await pnp_get_test_client_serv(name_limit, name_limit, 0)

            # Fill up the name queue.
            for i in range(0, name_limit):
                await clients[af].push(f"{i}", f"{i}")
                await asyncio.sleep(2)

            # Normally this would bump one.
            await clients[af].push(f"3", f"3", BEHAVIOR_DONT_BUMP)
            ret = await clients[af].fetch(f"3")
            assert(ret.value == None)

            # All original values should exist.
            for i in range(0, name_limit):
                ret = await clients[af].fetch(f"{i}")
                assert(ret.value == to_b(f"{i}"))

            await serv.close() 

    """
ip address add fe80:3456:7890:1111:0000:0000:0000:0001/128 dev enp0s31f6
ip address add fe80:3456:7890:1111:0000:0000:0000:0002/128 dev enp0s31f6
ip address add fe80:3456:7890:1111:0000:0000:0000:0003/128 dev enp0s31f6
ip address add fe80:3456:7890:2222:0000:0000:0000:0001/128 dev enp0s31f6
ip address add fe80:3456:7890:2222:0000:0000:0000:0002/128 dev enp0s31f6
ip address add fe80:3456:7890:2222:0000:0000:0000:0003/128 dev enp0s31f6
ip address add fe80:3456:7890:3333:0000:0000:0000:0001/128 dev enp0s31f6
    """
    async def test_pnp_v6_range_limits(self):
        """
        i = await Interface().start_local()
        r = await i.route(IP6).bind(ips="fe80:3456:7890:1111:0000:0000:0000:0001")
        p = await pipe_open(TCP, r)
        print(p)
        print(p.sock)
        await p.close()
        return
        """
    

        # Subnet limit = 2
        # Iface limit = 2
        await pnp_clear_tables()
        clients, serv = await pnp_get_test_client_serv(v6_serv_ips="fe80:3456:7890:1111:0000:0000:0000:0001")
        serv.set_v6_limits(2, 2)

        vectors = [
            # Exhaust iface limit:
            [
                # glob          net  iface
                "fe80:3456:7890:1111:0000:0000:0000:0001",
                b"0"
            ],
            [
                # glob          net  iface
                "fe80:3456:7890:1111:0000:0000:0000:0002",
                b"1"
            ],
            [
                # glob          net  iface
                "fe80:3456:7890:1111:0000:0000:0000:0003",
                None
            ],

            # Exhaust subnet limit.
            [
                # glob          net  iface
                "fe80:3456:7890:2222:0000:0000:0000:0001",
                b"3"
            ],
            [
                # glob          net  iface
                "fe80:3456:7890:2222:0000:0000:0000:0002",
                b"4"
            ],
            [
                # glob          net  iface
                "fe80:3456:7890:2222:0000:0000:0000:0003",
                None
            ],
            [
                # glob          net  iface
                "fe80:3456:7890:3333:0000:0000:0000:0001",
                None
            ],
        ]

        for offset in range(0, len(vectors)):
            src_ip, expect = vectors[offset]
            client = clients[IP6]

            # Patch client pipe to use a specific fixed IP.
            async def get_dest_pipe():
                # Bind to specific local IP.
                route = client.dest.route.interface.route(
                    client.dest.route.af
                
                )
                print(f"binding to {src_ip}")
                await route.bind(ips=src_ip)
                print(route._bind_tups)

                # Return a pipe to the PNP server.
                return await pipe_open(
                    client.proto,
                    route,
                    client.dest
                )

            # Patch the client to use specific src ip.
            client.get_dest_pipe = get_dest_pipe

            # Test out the vector.
            await client.push(f"{offset}", f"{offset}")
            await asyncio.sleep(2)
            ret = await client.fetch(f"{offset}")
            if ret.value is None:
                assert(expect is None)
            else:
                assert(expect == to_b(f"{offset}"))

        # Cleanup.
        await serv.close()

# Prune admin code?
# make sure your pub key is returned
if __name__ == '__main__':
    main()