"""
Hijacking a name?
    - 


bump old ipv6s?
pruning all expired (access to localhost)
    - prune ipv6s not refreshed for n
        - delete associated names
    - delete all names for both afs that have expired

increase name no so demos are possible for both afs
test you cant update others names

"""


import aiomysql
from ecdsa import SigningKey, VerifyingKey
from .pnp_utils import *
from .net import *
from .ip_range import IPRange
from .daemon import *

async def v6_range_usage(cur, v6_glob_main, v6_glob_extra, v6_lan_id, _):
    # Count number of subnets used.
    sql  = "SELECT COUNT(DISTINCT v6_lan_id) "
    sql += "FROM ipv6s WHERE v6_glob_main=%s AND v6_glob_extra=%s"
    await cur.execute(sql, (v6_glob_main, v6_glob_extra))

    v6_subnets_used = (await cur.fetchone())[0]
    print("Subnets used = ", v6_subnets_used)

    # Count number of interfaces used.
    sql  = "SELECT COUNT(*) FROM ipv6s "
    sql += "WHERE v6_glob_main=%s AND v6_glob_extra=%s "
    sql += "AND v6_lan_id=%s "
    sql_params = (v6_glob_main, v6_glob_extra, v6_lan_id)

    await cur.execute(sql, sql_params)
    v6_ifaces_used = (await cur.fetchone())[0]
    print("ifaces used = ", v6_ifaces_used)

    return v6_subnets_used, v6_ifaces_used

async def v6_exists(cur, v6_glob_main, v6_glob_extra, v6_lan_id, v6_iface_id):
    # Check if v6 subnet component exists.
    sql  = "SELECT * FROM ipv6s WHERE v6_glob_main=%s "
    sql += "AND v6_glob_extra=%s AND v6_lan_id=%s "
    sql_params = (v6_glob_main, v6_glob_extra, v6_lan_id)

    await cur.execute(sql, sql_params)
    v6_lan_exists = (await cur.fetchone()) is not None

    # Check if IPv6 record exists.
    sql += "AND v6_iface_id=%s"
    await cur.execute(
        sql.replace("COUNT(*)", "*"), # Change count to select.
        (v6_glob_main, v6_glob_extra, v6_lan_id, v6_iface_id)
    )

    v6_record = await cur.fetchone()
    return v6_lan_exists, v6_record

async def v6_insert(cur, v6_glob_main, v6_glob_extra, v6_lan_id, v6_iface_id):
    sql = """INSERT INTO ipv6s
        (
            v6_glob_main,
            v6_glob_extra,
            v6_lan_id,
            v6_iface_id,
            timestamp
        )
        VALUES (%s, %s, %s, %s, %s)
    """
    sql_params = (v6_glob_main, v6_glob_extra, v6_lan_id)
    sql_params += (v6_iface_id, int(time.time()))

    await cur.execute(sql, sql_params)
    return cur.lastrowid

def get_v6_parts(ipr):
    ip_str = str(ipr) # Normalize IPv6.
    v6_glob_main = int(ip_str[:9].replace(':', ''), 16) # :
    v6_glob_extra = int(ip_str[10:14], 16)
    v6_lan_id = int(ip_str[15:19], 16)
    v6_iface_id = int(ip_str[20:].replace(':', ''), 16) # :
    v6_parts = (v6_glob_main, v6_glob_extra, v6_lan_id, v6_iface_id)

    #v6_glob_main = 23
    #v6_glob_extra = 19
    #v6_lan_id = 3

    print(v6_glob_main)
    print(v6_glob_extra)
    print(v6_lan_id)
    print(v6_iface_id)
    return v6_parts

async def record_v6(params, serv):
    # Replace ipr parameter with v6_parts.
    params = (params[0],) + get_v6_parts(params[1])

    # Get consumption numbers for the IPv6 range.
    v6_subnets_used, v6_ifaces_used = await v6_range_usage(*params)

    # Check whether the LAN ID already exists.
    # If the whole IPv6 already exists the record is not None.
    v6_lan_exists, v6_record = await v6_exists(*params)
    
    # Start logic to handle inserting the IPv6.
    if v6_record is None:
        # Are we within the subnet limitations?
        if not (v6_lan_exists or (v6_subnets_used < serv.v6_subnet_limit)):
            raise Exception("IPv6 subnet limit reached.")

        # Are we within the iface limitations?
        if not (v6_ifaces_used < serv.v6_iface_limit):
            raise Exception("IPv6 iface limit reached.")
        
        # IP row ID.
        ip_id = await v6_insert(*params)
    else:
        # IP row ID.
        ip_id = v6_record[0]

    return ip_id

async def record_v4(params, serv):
    cur, ipr = params

    sql = "SELECT * FROM ipv4s WHERE v4_val=%s"
    await cur.execute(sql, (int(ipr),))
    row = await cur.fetchone()

    if row is not None:
        ip_id = row[0]
    else:
        sql  = "INSERT INTO ipv4s (v4_val, timestamp) "
        sql += "VALUES (%s, %s)"
        await cur.execute(sql, (int(ipr), int(time.time())))
        ip_id = cur.lastrowid

    return ip_id

async def record_ip(af, params, serv):
    if af == IP6:
        ip_id = await record_v6(params, serv)
    
    # Load existing ip_id or create it - V4.
    if af == IP4:
        ip_id = await record_v4(params, serv)

    return ip_id

def name_limit_by_af(af, serv):
    if af == IP4:
        return serv.v4_name_limit
    if af == IP6:
        return serv.v6_name_limit

# TODO: maybe just use this in insert name?
async def will_bump_names(af, cur, serv, ip_id):
    current_time = int(time.time())
    min_name_duration = serv.min_name_duration
    sql = f"""
    SELECT COUNT(*)
    FROM names
    WHERE ip_id = %s
    AND af = %s
    AND (({current_time} - timestamp) >= {min_name_duration})
    """
    print(sql)

    name_limit = name_limit_by_af(af, serv)
    await cur.execute(sql, (ip_id, int(af),))
    names_used = (await cur.fetchone())[0]
    print("in will bump names = ")
    print(names_used)

    if names_used >= name_limit:
        return True
    else:
        return False

async def bump_name_overflows(af, cur, serv, ip_id):
    print("Testing for pop")

    # Set number of names allowed per IP.
    name_limit = name_limit_by_af(af, serv)
    current_time = int(time.time())
    min_name_duration = serv.min_name_duration
    sql = f"""
    DELETE FROM names
    WHERE id IN (
        SELECT id
        FROM (
            SELECT id
            FROM names 
            WHERE ip_id = %s
            AND af = %s
            AND (({current_time} - timestamp) >= {min_name_duration})
            ORDER BY timestamp DESC 
            LIMIT 100 OFFSET %s
        ) AS rows_to_delete
    );
    """
    print(sql)
    print("ip_id = ", ip_id)
    out = await cur.execute(sql, (ip_id, int(af), name_limit))
    print(out)

async def fetch_name(cur, name):
    # Does name already exist.
    sql = "SELECT * FROM names WHERE name=%s"
    await cur.execute(sql, (name,))
    row = await cur.fetchone()
    print("test name", row)
    return row
    name_exists = row is not None

async def record_name(cur, serv, af, ip_id, name, value, owner_pub, updated):
    # Does name already exist.
    row = await fetch_name(cur, name)
    name_exists = row is not None

    # Update an existing name.
    if name_exists:
        print("updating name")
        if row[6] >= updated:
            raise Exception("Replay attack for name update.")

        sql  = """
        UPDATE names SET 
        value=%s,
        af=%s,
        ip_id=%s,
        timestamp=%s
        WHERE name=%s
        """
        print(sql)
        print("Doing update name")
        print(name)
        print(value)
        print(updated)

        ret = await cur.execute(sql, 
            (
                value,
                int(af),
                ip_id,
                updated,
                name
            )
        )
        print(ret)

        row = (row[0], name, value, row[3], af, ip_id, updated)

    # Create a new name.
    if not name_exists:
        print("inserting new name")

        # Ensure name limit is respected.
        # [ ... active names, ? ]
        print("testing bump limit")

        will_bump = await will_bump_names(af, cur, serv, ip_id)
        if not will_bump:
            sql  = "SELECT COUNT(*) FROM names WHERE af=%s "
            sql += "AND ip_id=%s"
            await cur.execute(sql, (int(af), ip_id,))
            names_used = (await cur.fetchone())[0]
            name_limit = name_limit_by_af(af, serv)
            if names_used >= name_limit:
                raise Exception("insert name limit reached.")
        

        """
        will_bump = await will_bump_names(af, cur, serv, ip_id)
        if will_bump:
            raise Exception("Insert name for af over limit.")
        """
            
        sql = """
        INSERT INTO names
        (
            name,
            value,
            owner_pub,
            af,
            ip_id,
            timestamp
        )
        VALUES(%s, %s, %s, %s, %s, %s)
        """

        ret = await cur.execute(sql, 
            (
                name,
                value,
                owner_pub,
                int(af),
                ip_id,
                updated
            )
        )
        print("insert name ret ", ret)

    return row

async def verified_delete_name(db_con, cur, name, updated):
    row = await fetch_name(cur, name)
    if row is None:
        return
    
    if row[6] >= updated:
        raise Exception("Replay attack for name update.")
        
    sql = "DELETE FROM names WHERE name = %s"
    await cur.execute(sql, (name))
    await db_con.commit()

async def verified_write_name(db_con, cur, serv, behavior, updated, name, value, owner_pub, af, ip_str):
    # Convert ip_str into an IPRange instance.
    cidr = 32 if af == IP4 else 128
    ipr = IPRange(ip_str, cidr=cidr)

    # Record IP if needed and get its ID.
    # If it's V6 allocation limits are enforced on subnets.
    ip_id = await record_ip(af, (cur, ipr,), serv)

    # Polite mode: only insert if it doesn't bump others.
    if behavior == BEHAVIOR_DONT_BUMP:
        will_bump = await will_bump_names(af, cur, serv, ip_id)
        if will_bump:
            return

    # Record name if needed and get its ID.
    # Also supports transfering a name to a new IP.
    name_row = await record_name(cur, serv, af, ip_id, name, value, owner_pub, updated)

    # Save current changes so the bump check can prune the excess.
    await db_con.commit()

    # Prune any names over the limit for an IP.
    # - Prioritize removing the oldest first.
    # - V6 has 1 per IP (and multiple IPs per user.)
    # - V4 has multiple names per IP (and 1 IP per user.)
    if name_row is None or name_row[-1] != ip_id:
        await bump_name_overflows(af, cur, serv, ip_id)

    # Save current changes.
    await db_con.commit()

class PNPServer(Daemon):
    def __init__(self, v4_name_limit=V4_NAME_LIMIT, v6_name_limit=V6_NAME_LIMIT, min_name_duration=MIN_NAME_DURATION):
        self.v4_name_limit = v4_name_limit
        self.v6_name_limit = v6_name_limit
        self.min_name_duration = min_name_duration
        self.v6_subnet_limit = V6_SUBNET_LIMIT
        self.v6_iface_limit = V6_IFACE_LIMIT
        super().__init__()
        
    def set_v6_limits(self, v6_subnet_limit, v6_iface_limit):
        self.v6_subnet_limit = v6_subnet_limit
        self.v6_iface_limit = v6_iface_limit

    async def msg_cb(self, msg, client_tup, pipe):
        print("connected")
        print(client_tup)
        cidr = 32 if pipe.route.af == IP4 else 128
        db_con = None
        try:
            pkt = PNPPacket.unpack(msg)
            pnp_msg = pkt.get_msg_to_sign()
            print(pkt.vkc)
            print(pkt.name)
            print(pkt.value)
            print(pkt.sig)
            print(pkt.updated)
            print(msg)




            db_con = await aiomysql.connect(
                user=DB_USER, 
                password=DB_PASS,
                db=DB_NAME
            )
            print(db_con)

            async with db_con.cursor() as cur:
                #await cur.execute("SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                row = await fetch_name(cur, pkt.name)
                print("row = ")
                print(row)

                if row is not None:
                    # If no sig fetch name value.
                    if pkt.sig is None or not len(pkt.sig):
                        print("No sig for operation.")

                        resp = PNPPacket(
                            name=pkt.name,
                            value=row[2],
                            updated=row[6],
                            vkc=row[3]
                        ).get_msg_to_sign()
                        await proto_send(pipe, resp)
                        return

                    # Ensure valid sig for next delete op.
                    vk = VerifyingKey.from_string(row[3])
                    vk.verify(pkt.sig, pnp_msg)
                    print("Sig valid")

                    # Delete pre-existing value.
                    if not len(pkt.value):
                        await verified_delete_name(
                            db_con,
                            cur,
                            pkt.name,
                            pkt.updated
                        )
                        await proto_send(pipe, pnp_msg)
                        return

                # A fetch failed.
                if pkt.sig is None or not len(pkt.sig):
                    resp = PNPPacket(
                        name=pkt.name,
                        value=b"",
                        updated=0,
                        vkc=pkt.vkc
                    ).get_msg_to_sign()
                    await proto_send(pipe, resp)
                    return

                # Write to name.
                if not pkt.is_valid_sig():
                    print("pkt not valid sig for insert.")
                    print(pnp_msg)
                    return

                await verified_write_name(
                    db_con,
                    cur,
                    self,
                    pkt.behavior,
                    pkt.updated,
                    pkt.name,
                    pkt.value,
                    pkt.vkc,
                    pipe.route.af,
                    str(IPRange(client_tup[0], cidr=cidr))
                )
                await proto_send(pipe, pnp_msg)
                
                print("End verified write name")


            return
            await async_wrap_errors(
                pipe.send(msg, client_tup)
            )
        except:
            log_exception()
        finally:
            if db_con is not None:
                db_con.close()

async def main_workspace():
    return
    #sk = SigningKey.generate()

    # Just use a fixed key for testing.
    test_name = "pnp_name"
    test_val = "pnp_val"
    sk = SigningKey.from_string(
        string=(b"test" * 100)[:24],
        #hashfunc=hashlib.sha3_256,
        #curve=SECP256k1s
    )


    vk = sk.verifying_key
    vkc = vk.to_string("compressed")
    print(vkc)
    assert(len(vkc) == 25)

    i = await Interface().start_local()
    serv_v4 = await i.route(IP4).bind(PNP_PORT)
    serv_v6 = await i.route(IP6).bind(PNP_PORT)
    serv = await PNPServer().listen_all(
        [serv_v4, serv_v6],
        [PNP_PORT],
        [TCP, UDP]
    )
    dest = await Address('p2pd.net', PNP_PORT, i.route())
    client = PNPClient(sk, dest)
    #await client.delete(test_name)
    await client.push(test_name, test_val)
    out = await client.fetch(test_name)

    print("fetch result = ", out)

    while 1:
        await asyncio.sleep(1)

    await serv.close()

    #await verified_post_name('name', 'val', 'pub', IP6, '2001:4860:4860::8888')