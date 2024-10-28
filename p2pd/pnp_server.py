"""
This is a server that allows anyone to store key-value records.
    - Keys (or names) point to an ECDSA pub key (owner.)
    - Anyone who knows the key can read the value.
    - The owner can change the value with a signed request.
    - Only those with the private key can update the value.
    - There is a set number of names allocated per IP.
    - Since many people have dynamic IPs names must be
    periodically 'refreshed' which prevents expiry and ensures
    that they are associated with the right IP.
    - New names past the limit per IP bump off older names.
    - To prevent names being bumped before they can be refreshed
    each name is allowed to exist for a minimum period.
    - Thus, names are repeatedly migrated been IPs and refreshed
    as they are needed. Or allowed to expire automatically.

This is a registration-less, permissioned, key-value store
that uses IP limits to reduce spam.

Todo: test IPv6 works - setup home for it again.
"""

from .ecies import encrypt, decrypt
import os
import aiomysql
from ecdsa import VerifyingKey, SECP256k1, SigningKey
from .pnp_utils import *
from .net import *
from .ip_range import IPRange
from .daemon import *
from .clock_skew import SysClock

async def v6_range_usage(cur, v6_glob_main, v6_glob_extra, v6_lan_id, _):
    # Count number of subnets used.
    sql  = "SELECT COUNT(DISTINCT v6_lan_id) "
    sql += "FROM ipv6s WHERE v6_glob_main=%s AND v6_glob_extra=%s FOR UPDATE"
    await cur.execute(sql, (int(v6_glob_main), int(v6_glob_extra),))
    v6_subnets_used = (await cur.fetchone())[0]

    # Count number of interfaces used.
    sql  = "SELECT COUNT(id) FROM ipv6s "
    sql += "WHERE v6_glob_main=%s AND v6_glob_extra=%s "
    sql += "AND v6_lan_id=%s FOR UPDATE"
    sql_params = (int(v6_glob_main), int(v6_glob_extra), int(v6_lan_id),)
    await cur.execute(sql, sql_params)
    v6_ifaces_used = (await cur.fetchone())[0]

    # Return results.
    return v6_subnets_used, v6_ifaces_used

async def v6_exists(cur, v6_glob_main, v6_glob_extra, v6_lan_id, v6_iface_id):
    # Check if v6 subnet component exists.
    sql  = "SELECT id FROM ipv6s WHERE v6_glob_main=%s "
    sql += "AND v6_glob_extra=%s AND v6_lan_id=%s "
    sql_params = (int(v6_glob_main), int(v6_glob_extra), int(v6_lan_id),)
    await cur.execute(sql + " FOR UPDATE", sql_params)
    v6_lan_exists = (await cur.fetchone()) is not None

    # Check if IPv6 record exists.
    sql += "AND v6_iface_id=%s FOR UPDATE"
    await cur.execute(
        sql.replace(" COUNT(id) ", " id "), # Change count to select.
        (int(v6_glob_main), int(v6_glob_extra), int(v6_lan_id), int(v6_iface_id),)
    )
    v6_record = await cur.fetchone()

    # Return results.
    return v6_lan_exists, v6_record

async def v6_insert(cur, v6_glob_main, v6_glob_extra, v6_lan_id, v6_iface_id, sys_clock):
    # Insert a new IPv6 IP.
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
    sql_params = (int(v6_glob_main), int(v6_glob_extra), int(v6_lan_id),)
    sql_params += (int(v6_iface_id), int(sys_clock.time()),)
    await cur.execute(sql, sql_params)

    # Return the new row index.
    return cur.lastrowid

# Breaks down an IPv6 into fields for DB storage.
def get_v6_parts(ipr):
    ip_str = str(ipr) # Normalize IPv6.
    v6_glob_main = int(ip_str[:9].replace(':', ''), 16) # :
    v6_glob_extra = int(ip_str[10:14], 16)
    v6_lan_id = int(ip_str[15:19], 16)
    v6_iface_id = int(ip_str[20:].replace(':', ''), 16) # :
    v6_parts = (v6_glob_main, v6_glob_extra, v6_lan_id, v6_iface_id)

    return v6_parts

async def record_v6(params, serv, sys_clock):
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
        ip_id = await v6_insert(*params, sys_clock)
    else:
        # IP row ID.
        ip_id = v6_record[0]

    return ip_id

async def record_v4(params, serv, sys_clock):
    # Main params.
    cur, ipr = params

    # Check if IPv4 exists.
    sql = "SELECT id FROM ipv4s WHERE v4_val=%s FOR UPDATE"
    await cur.execute(sql, (int(ipr),))
    row = await cur.fetchone()
    if row is not None:
        # If it does return the ID.
        ip_id = row[0]
    else:
        # Otherwise insert the new IP and return its row ID.
        sql  = "INSERT INTO ipv4s (v4_val, timestamp) "
        sql += "VALUES (%s, %s)"
        await cur.execute(sql, (int(ipr), int(sys_clock.time()),))
        ip_id = cur.lastrowid

    return ip_id

async def record_ip(af, params, serv, sys_clock):
    if af == IP6:
        ip_id = await record_v6(params, serv, sys_clock)
    
    # Load existing ip_id or create it - V4.
    if af == IP4:
        ip_id = await record_v4(params, serv, sys_clock)

    return ip_id

# Each IP can own X names.
# Where X depends on the address family.
def name_limit_by_af(af, serv):
    if af == IP4:
        return serv.v4_name_limit
    if af == IP6:
        return serv.v6_name_limit

# Used to check if a new insert for an IP bumps old names.
async def will_bump_names(af, cur, serv, ip_id, sys_clock):
    current_time = sys_clock.time()
    min_name_duration = serv.min_name_duration
    sql = f"""
    SELECT COUNT(id)
    FROM names
    WHERE ip_id = %s
    AND af = %s
    AND ((%s - timestamp) >= %s)
    FOR UPDATE
    """

    name_limit = name_limit_by_af(af, serv)
    await cur.execute(sql, (int(ip_id), int(af), int(current_time), int(min_name_duration),))
    names_used = (await cur.fetchone())[0]
    if names_used >= name_limit:
        return True
    else:
        return False

async def bump_name_overflows(af, cur, serv, ip_id, sys_clock):
    # Set number of names allowed per IP.
    name_limit = name_limit_by_af(af, serv)
    current_time = sys_clock.time()
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
            AND ((%s - timestamp) >= %s)
            ORDER BY timestamp DESC 
            LIMIT 100 OFFSET %s
            FOR UPDATE
        ) AS rows_to_delete
    );
    """
    await cur.execute(sql, (int(ip_id), int(af), int(current_time), int(min_name_duration), int(name_limit),))

async def fetch_name(cur, name, lock=DB_WRITE_LOCK):
    # Does name already exist.
    sql = "SELECT * FROM names WHERE name=%s "
    if lock == DB_WRITE_LOCK:
        sql += "FOR UPDATE"

    await cur.execute(sql, (name,))
    row = await cur.fetchone()
    return row

async def record_name(cur, serv, af, ip_id, name, value, owner_pub, updated, sys_clock):
    # Does name already exist.
    row = await fetch_name(cur, name)
    name_exists = row is not None

    # Update an existing name.
    if name_exists:
        if row[6] >= updated:
            raise Exception("Replay attack for name update.")

        sql  = """
        UPDATE names SET 
        value=%s,
        af=%s,
        ip_id=%s,
        timestamp=%s
        WHERE name=%s 
        AND timestamp=%s
        """
        ret = await cur.execute(sql, 
            (
                value,
                int(af),
                int(ip_id),
                int(updated),
                name,
                int(row[6])
            )
        )
        if not ret:
            return None

        row = (row[0], name, value, row[3], af, ip_id, updated)
        return row

    # Create a new name.
    if not name_exists:
        # Ensure name limit is respected.
        # [ ... active names, ? ]
        penalty = 0
        will_bump = await will_bump_names(af, cur, serv, ip_id, sys_clock)
        if not will_bump:
            sql  = "SELECT COUNT(id) FROM names WHERE af=%s "
            sql += "AND ip_id=%s FOR UPDATE"
            await cur.execute(sql, (int(af), int(ip_id),))
            names_used = (await cur.fetchone())[0]
            name_limit = name_limit_by_af(af, serv)
            if names_used:
                penalty = ((names_used / name_limit) * MIN_NAME_DURATION) + 1
                penalty = max(penalty, MIN_DURATION_PENALTY)
            if names_used >= name_limit:
                raise Exception("insert name limit reached.")

        # Insert a brand new name.
        updated = int(updated)
        updated -= max(penalty, 0)
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
                int(ip_id),
                int(updated),
            )
        )

        # Fetch the new row (so we know the ID.)
        return await fetch_name(cur, name)

# Deletes a name if a signed request is more recent.
async def verified_delete_name(db_con, cur, name, updated):
    row = await fetch_name(cur, name)
    if row is None:
        return
    
    if row[6] >= updated:
        raise Exception("Replay attack for name update.")
        
    sql  = "DELETE FROM names WHERE "
    sql += "name = %s AND timestamp = %s"
    await cur.execute(sql, (name, int(row[6])))
    await db_con.commit()

# Prunes unneeded records from the DB.
async def verified_pruning(db_con, cur, serv, updated):
    # Delete all ipv6s that haven't been updated for X seconds.
    sql = """
    DELETE FROM ipv6s
    WHERE ((%s - timestamp) >= %s)
    """
    ret = await cur.execute(sql, (
        int(updated),
        int(serv.v6_addr_expiry),
    ))

    # Delete all names that haven't been updated for X seconds.
    sql = """
    DELETE FROM names
    WHERE ((%s - timestamp) >= %s)
    """
    ret = await cur.execute(sql, (
        int(updated),
        int(serv.min_name_duration),
    ))

    # Delete all IPs that don't have associated names.
    """
    This query uses a sub-query to select all names associated
    with a specific IP address family. The parent query deletes
    all records from the IP table if no names refer back to
    an IP row. Since the name row uses a different column name
    for the id field (ip_id) the field is given an alias (id.)
    The parent query can now delete all rows that don't have
    an ID in the sub query result set.

    Note: this query could get slow with many names.
    """
    for table, af in [["ipv4s", 2], ["ipv6s", 10]]:
        sql = f"""
        DELETE FROM {table} WHERE id NOT IN (
            SELECT ip_id as id
            FROM (
                SELECT ip_id
                FROM names 
                WHERE af=%s
            ) AS results
        );
        """
        ret = await cur.execute(sql, (
            af,
        ))

    await db_con.commit()


async def verified_write_name(db_con, cur, serv, behavior, updated, name, value, owner_pub, af, ip_str, sys_clock):
    # Convert ip_str into an IPRange instance.
    cidr = 32 if af == IP4 else 128
    ipr = IPRange(ip_str, cidr=cidr)

    # Record IP if needed and get its ID.
    # If it's V6 allocation limits are enforced on subnets.
    ip_id = await record_ip(af, (cur, ipr,), serv, sys_clock)
    if ip_id is None:
        return

    # Polite mode: only insert if it doesn't bump others.
    if behavior == BEHAVIOR_DONT_BUMP:
        will_bump = await will_bump_names(af, cur, serv, ip_id, sys_clock)
        if will_bump:
            return

    # Record name if needed and get its ID.
    # Also supports transferring a name to a new IP.
    name_row = await record_name(cur, serv, af, ip_id, name, value, owner_pub, updated, sys_clock)
    if name_row is None:
        return

    # Prune any names over the limit for an IP.
    # - Prioritize removing the oldest first.
    # - V6 has 1 per IP (and multiple IPs per user.)
    # - V4 has multiple names per IP (and 1 IP per user.)
    if name_row is None or name_row[-1] != ip_id:
        await bump_name_overflows(af, cur, serv, ip_id, sys_clock)

    # Save current changes.
    await db_con.commit()

class PNPServer(Daemon):
    def __init__(self, db_user, db_pass, db_name, reply_sk, reply_pk, sys_clock, v4_name_limit=V4_NAME_LIMIT, v6_name_limit=V6_NAME_LIMIT, min_name_duration=MIN_NAME_DURATION, v6_addr_expiry=V6_ADDR_EXPIRY):
        self.__name__ = "PNPServer"
        self.db_user = db_user
        self.db_pass = db_pass
        self.db_name = db_name
        self.reply_sk = SigningKey.from_string(reply_sk, curve=SECP256k1)
        self.reply_pk = reply_pk
        self.sys_clock = sys_clock
        self.v4_name_limit = v4_name_limit
        self.v6_name_limit = v6_name_limit
        self.min_name_duration = min_name_duration
        self.v6_addr_expiry = v6_addr_expiry
        self.v6_subnet_limit = V6_SUBNET_LIMIT
        self.v6_iface_limit = V6_IFACE_LIMIT
        self.debug = False
        super().__init__()

    def serv_resp(self, pkt):
        reply_pk = pkt.reply_pk

        # Replace received packet reply address with our own.
        pkt.reply_pk = self.reply_pk

        # Serialize updated response. 
        buf = pkt.get_msg_to_sign()

        # Send encrypted if supported.
        if reply_pk is not None:
            buf = encrypt(reply_pk, buf)

        return buf

    def set_debug(self, val):
        self.debug = val
        
    def set_v6_limits(self, v6_subnet_limit, v6_iface_limit):
        self.v6_subnet_limit = v6_subnet_limit
        self.v6_iface_limit = v6_iface_limit

    async def msg_cb(self, msg, client_tup, pipe):
        db_con = None
        try:
            pipe.stream.set_dest_tup(client_tup)
            msg = decrypt(self.reply_sk, msg)
            cidr = 32 if pipe.route.af == IP4 else 128
            pkt = PNPPacket.unpack(msg)
            pnp_msg = pkt.get_msg_to_sign()
            db_con = await aiomysql.connect(
                user=self.db_user, 
                password=self.db_pass,
                db=self.db_name
            )


            async with db_con.cursor() as cur:
                #await cur.execute("SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE")

                row = await fetch_name(cur, pkt.name, DB_READ_LOCK)
                if row is not None:
                    # If no sig fetch name value.
                    if pkt.sig is None or not len(pkt.sig):
                        resp = PNPPacket(
                            name=pkt.name,
                            value=row[2],
                            updated=row[6],
                            vkc=row[3],
                            pkid=pkt.pkid,
                            reply_pk=pkt.reply_pk,
                        )

                        buf = self.serv_resp(resp)
                        await proto_send(pipe, buf)
                        return

                    # Ensure valid sig for next delete op.
                    vk = VerifyingKey.from_string(
                        row[3],
                        curve=SECP256k1
                    )
                    vk.verify(pkt.sig, pnp_msg)

                    # Delete pre-existing value.
                    if not len(pkt.value):
                        await verified_delete_name(
                            db_con,
                            cur,
                            pkt.name,
                            pkt.updated
                        )
                        buf = self.serv_resp(pkt)
                        await proto_send(pipe, buf)
                        return

                # A fetch failed.
                if pkt.sig is None or not len(pkt.sig):
                    log(f"Error: fetch {pkt.name} failed!")
                    resp = PNPPacket(
                        name=pkt.name,
                        value=b"",
                        updated=0,
                        vkc=pkt.vkc,
                        pkid=pkt.pkid,
                        reply_pk=pkt.reply_pk,
                    )
                    buf = self.serv_resp(resp)
                    await proto_send(pipe, buf)
                    return

                # Check signature is valid.
                if not pkt.is_valid_sig():
                    raise Exception("pkt sig is invalid.")

                # Create a new name entry.
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
                    str(IPRange(client_tup[0], cidr=cidr)),
                    self.sys_clock
                )

                buf = self.serv_resp(pkt)
                await proto_send(pipe, buf)
        except:
            await db_con.rollback()
            log_exception()
        finally:
            if db_con is not None:
                db_con.close()

async def start_pnp_server(bind_port):
    i = await Interface()

    # Load mysql root password details.
    if "PNP_DB_PW" in os.environ:
        db_pass = os.environ["PNP_DB_PW"]
    else:
        db_pass = input("db pass: ")

    # Load server reply public key.
    if "PNP_ENC_PK" in os.environ:
        reply_pk_hex = os.environ["PNP_ENC_PK"]
    else:
        reply_pk_hex = input("reply pk: ")

    # Load server reply private key
    if "PNP_ENC_SK" in os.environ:
        reply_sk_hex = os.environ["PNP_ENC_SK"]
    else:
        reply_sk_hex = input("reply sk: ")

    # Load PNP server class with DB details.
    sys_clock = await SysClock(i).start()
    serv = PNPServer(
        "root",
        db_pass,
        "pnp",
        h_to_b(reply_sk_hex),
        h_to_b(reply_pk_hex),
        sys_clock,
    )

    # Start the server listening on public routes.
    print("Now starting PNP serv on ...")
    print(reply_pk_hex)

    for proto in [TCP, UDP]:
        await serv.listen_all(proto, bind_port, i)

    return serv

