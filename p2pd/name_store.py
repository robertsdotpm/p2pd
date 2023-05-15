import copy
import asyncio
import sqlite3
import binascii
from nacl.signing import SigningKey
from .address import *
from .interface import *
from .base_stream import *
from .http_client_lib import *

"""
Provides a simple async client for using a key-value database provided by a PHP script. Many useful services can be built
on top of such a construct. DNS is a perfect example.

By implementing the KV-store using PHP and doing auth with
signatures any client is free to use the DB without the 
tedious process of registration while the basic infrastructure
can be setup on any number of free hosts.

Note: Using the PHP name store script on free PHP web hosts like
000webhost may filter requests from the same IP that are made too
quickly. Hence it might be a good idea to throttle requests.
"""

KVS_MEM_DB = 0
class NameStore():
    def __init__(self, route, url, db_path=None, timeout=3, throttle=1):
        # Enable throttling for API calls.
        self.throttle = throttle

        # DNS, TCP CON, and RECV timeout for slow free hosts.
        self.timeout = timeout
        self.route = route
        self.url = url

        # Keep local copy of names and their update keys.
        if KVS_MEM_DB:
            self.db = {}
            self.cur = None
        else:
            self.db = sqlite3.connect(db_path)
            self.db.row_factory = sqlite_dict_factory
            self.cur = self.db.cursor()

    # Resolve domain from URL and split URL into parts.
    async def start(self):
        # Split URL into host and port.
        port = 80
        url_parts = urllib.parse.urlparse(self.url)
        host = netloc = url_parts.netloc
        self.path = url_parts.path

        # Overwrite default port 80.
        if ":" in netloc:
            host, port = netloc.split(":")
            port = int(port)

        # Resolve domain of URL.
        self.port = port
        self.host = host
        self.dest = await Address(
            self.host,
            self.port,
            self.route,
            timeout=self.timeout
        )

    # Make an API request against the provider.
    async def req(self, params, timeout=3):
        # Throttle request.
        if self.throttle:
            await asyncio.sleep(self.throttle)

        # Encode GET params.
        get_vars = ""
        for name in params:
            # Encode the value.
            v = to_s(
                urlencode(
                    params[name]
                )
            )

            # Pass the params in the URL.
            n = to_s(urlencode(name))
            get_vars += f"&{n}={v}"

        # Request path.
        path = f"{self.path}?{get_vars}"

        # Buld GET params.
        name = to_s(urlencode(name))

        # Make req.
        conf = copy.deepcopy(NET_CONF)
        conf["con_timeout"] = timeout
        conf["recv_timeout"] = timeout
        _, resp = await http_req(
            self.route,
            self.dest,
            path,

            # Specify the right sub/domain.
            headers=[[b"Host", to_b(self.host)]],
            conf=conf
        )

        # Return API output as string.
        return to_s(resp.out())

    # Nonce used to prevent replay attacks for updating keys.
    async def get_nonce(self, name):
        nonce = await self.req({
            "action": "get_nonce",
            "name": name
        })

        return int(nonce)
    
    # Sign a request to update a name.
    def sign_store(self, name, value, nonce, sign_key):
        msg = to_b(str(nonce)) + to_b(name) + to_b(value)
        signed = sign_key.sign(msg)
        sig_b = signed.signature # 64 bytes.
        return to_h(sig_b) # 128 bytes (hex).
    
    # Save details for a name locally.
    def db_save(self, name, nonce, sign_key):
        priv_key = to_h(sign_key.encode())
        if KVS_MEM_DB:
            self.db[name] = {
                "nonce": nonce,
                "priv_key": priv_key
            }
        else:
            sql = "INSERT INTO names (name, nonce, priv_key) "
            sql += "VALUES (?, ?, ?)"
            self.cur.execute(sql, (name, nonce, priv_key,))
            self.db.commit()

    # Get details for a name locally.
    def db_get(self, name):
        if KVS_MEM_DB:
            if name in self.db:
                return self.db[name]
        else:
            sql = "SELECT * FROM names WHERE name=?"
            res = self.cur.execute(sql, (name,))
            return self.cur.fetchone()

    # Increment nonce for replay protection.
    def db_nonce_plus(self, name):
        if KVS_MEM_DB:
            if name in self.db:
                self.db[name]["nonce"] += 1
        else:
            sql = "UPDATE names SET nonce = nonce + 1 WHERE name == ?"
            self.cur.execute(sql, (name,))
            self.db.commit()

    # Update value at a name.
    async def store(self, name, value):
        # Reload existing details.
        row = self.db_get(name)
        if row is not None:
            sign_key = SigningKey(
                binascii.unhexlify(row["priv_key"])
            )

            nonce = row["nonce"]
            if nonce == 0:
                nonce = await self.get_nonce(name) or 1

        # Otherwise get needed details.
        if row is None:
            # Generate key pairs.
            sign_key = SigningKey.generate()

            # Record these details.
            nonce = 1
            self.db_save(name, nonce, sign_key)

        # Sign API request.
        verify_key = sign_key.verify_key
        pub_hex = to_h(verify_key.encode())
        sig_hex = self.sign_store(name, value, nonce, sign_key)

        # Make API request to update value.
        out = await self.req({
            "action": "set_val",
            "name": name,
            "value": value,
            "nonce": str(nonce),
            "pub_key": pub_hex,
            "sig": sig_hex
        })

        # Return results from API.
        if out == "1":
            # Increment nonce for next call.
            self.db_nonce_plus(name)
            return True
        else:
            raise Exception(out)

    # Get value at a name.
    async def get(self, name):
        out = await self.req({
            "action": "get_val",
            "name": name
        })

        if "KVS_ERROR" in out:
            raise Exception(out)
        else:
            return out

if __name__ == '__main__':
    async def test_name_store():
        await init_p2pd()
        i = await Interface().start_local()
        route = i.route()
        url = "http://net-debug.000webhostapp.com/name_store.php"
        db_path = "/home/lounge-linux-vm/Desktop/kvs.db"
        kvs = NameStore(route, url, db_path)
        await kvs.start()

        name = "test51"
        val = "val"


        try:
            out = await kvs.store(name, val)
            print(out)

            out = await kvs.store(name, "val2")
            print(out)

            print("get results")
            out = await kvs.get(name)
            print(out)
        except:
            what_exception()
            pass


    async_test(test_name_store)

