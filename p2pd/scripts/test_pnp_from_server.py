
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

async def pnp_get_test_client_serv(v4_name_limit=V4_NAME_LIMIT, v6_name_limit=V6_NAME_LIMIT, min_name_duration=MIN_NAME_DURATION):
    i = await Interface().start_local()
    serv_v4 = await i.route(IP4).bind(PNP_TEST_PORT, ips="127.0.0.1")
    serv_v6 = await i.route(IP6).bind(PNP_TEST_PORT, ips="::1")
    serv = await PNPServer(v4_name_limit, v6_name_limit, min_name_duration).listen_all(
        [serv_v4, serv_v6],
        [PNP_TEST_PORT],
        [TCP, UDP]
    )

    clients = {}
    for af in VALID_AFS:
        route = i.route(af)
        dest = await Address('localhost', PNP_TEST_PORT, route)
        clients[af] = PNPClient(PNP_LOCAL_SK, dest)

    return clients, serv

async def pnp_cleanup_client_serv(client, serv):
    await serv.close()

class TestPNPFromServer(unittest.IsolatedAsyncioTestCase):
    async def test_pnp_insert_fetch_del(self):
        await pnp_clear_tables()
        clients, serv = await pnp_get_test_client_serv()
        for af in VALID_AFS:
            # Do insert.
            await clients[af].push(
                PNP_TEST_NAME,
                PNP_TEST_VALUE
            )

            # Test value was stored by retrieval.
            ret = await clients[af].fetch(PNP_TEST_NAME)
            assert(ret == PNP_TEST_VALUE)

            # Now delete the value.
            await clients[af].delete(PNP_TEST_NAME)

            # Test value was deleted.
            ret = await clients[af].fetch(PNP_TEST_NAME)
            assert(ret == None)

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

    # Todo: add politeness bump test.
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
                assert(ret == b"val")

            # Oldest should be popped.
            ret = await clients[af].fetch(f"0")
            assert(ret == None)

            # Cleanup server.
            await serv.close()

    async def test_pnp_freshness_limit(self):
        # 0, 1, 2 ... oldest = 0
        # 1, 2, 3 (oldest is popped)
        name_limit = 3
        for af in [IP4]:
            await pnp_clear_tables()
            clients, serv = await pnp_get_test_client_serv(name_limit, name_limit)

            # Fill the stack past name_limit.
            for i in range(1, name_limit + 2):
                await clients[af].push(f"{i}", "val")
                await asyncio.sleep(1)

            # Check values still exist.
            for i in range(1, name_limit + 1):
                ret = await clients[af].fetch(f"{i}")
                assert(ret == b"val")

            """
            Need to think more about how this should happen.
            """
            # Check insert over limit rejected.
            ret = await clients[af].fetch("4")
            print(ret)
            assert(ret == None)

            await serv.close()
            

    """
    test pops respect name limit (af dependant)
        test polite behavior

    test v6 range restrictions
        - dude to the code and need to test addresses the
        special test range of addresses might be useful here
  

    ensure we cant modify others names

    test freshness limit prevents unwanted early bumps
    """




if __name__ == '__main__':
    main()