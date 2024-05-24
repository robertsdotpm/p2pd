
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

async def pnp_get_test_client_serv():
    i = await Interface().start_local()
    serv_v4 = await i.route(IP4).bind(PNP_TEST_PORT, ips="127.0.0.1")
    serv_v6 = await i.route(IP6).bind(PNP_TEST_PORT, ips="::1")
    serv = await PNPServer().listen_all(
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
            sql = "SELECT * FROM names WHERE name=%s AND AF=%s"
            db_con = await aiomysql.connect(
                user=DB_USER, 
                password=DB_PASS,
                db=DB_NAME
            )

            is_valid = False
            async with db_con.cursor() as cur:
                await cur.execute(sql, (PNP_TEST_NAME, int(af)))
                is_valid = (await cur.fetchone()) is not None

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

                # Do the migration.
                await clients[af_y].push(
                    PNP_TEST_NAME,
                    PNP_TEST_VALUE
                )

                # Ensure the AF is valid.
                is_valid = await is_af_valid(af_y)
                assert(is_valid)





    """
    test migrate af x <--> af y
    test pops respect name limit (af dependant)
        set the min MIN_NAME_DURATION to 0 to test 
    test v6 range restrictions
    ensure we cant modify others names
    """




if __name__ == '__main__':
    main()