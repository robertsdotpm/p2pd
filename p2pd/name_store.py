import asyncio
from nacl.signing import SigningKey
from nacl.signing import VerifyKey
from .address import *
from .interface import *
from .base_stream import *
from .http_client_lib import *

class NameStore():
    def __init__(self, route, url, db_path, timeout=3):
        # DNS, TCP CON, and RECV timeout for slow free hosts.
        self.timeout = 3
        self.route = route
        self.url = url
        self.db = {}

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

        # Buld 
        name = to_s(urlencode(name))

        # Make req.
        conf = NET_CONF
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

        # Return API output as srting.
        return to_s(resp.out())

    async def get_nonce(self, name):
        nonce = await self.req({
            "action": "get_nonce",
            "name": name
        })

        return int(nonce)
    
    def sign_store(self, name, value, nonce, sign_key):
        msg = to_b(str(nonce)) + to_b(name) + to_b(value)
        signed = sign_key.sign(msg)
        sig_b = signed.signature # 64 bytes.
        return to_h(sig_b) # 128 bytes (hex).
    
    def db_save(self, name, nonce, priv_key):
        self.db[name] = {
            "nonce": nonce,
            "priv_key": priv_key
        }

    def db_get(self, name):
        if name in self.db:
            return self.db[name]
        
    def db_nonce_plus(self, name):
        if name in self.db:
            self.db[name]["nonce"] += 1

    async def store(self, name, value):
        # Reload existing details.
        row = self.db_get(name)
        if row is not None:
            nonce = row["nonce"]
            sign_key = SigningKey(row["priv_key"])

        # Otherwise get needed details.
        if row is None:
            # Used to prevent replay attacks for name updates.
            nonce = await self.get_nonce(name)
            if nonce != 0:
                raise Exception("Name already claimed.")
            else:
                nonce = 1

            # Generate key pairs.
            sign_key = SigningKey.generate()
            priv_key = sign_key.encode()

            # Record these details.
            self.db_save(name, nonce, priv_key)

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





if __name__ == '__main__':
    async def test_name_store():
        # Generate a new random signing key (32)
        signing_key = SigningKey.generate()
        priv_key = signing_key.encode()
        signing_key = SigningKey(priv_key)

        # Sign a message with the signing key (64)
        signed = signing_key.sign(b"Attack at Dawn")

        # Obtain the verify key for a given signing key
        verify_key = signing_key.verify_key

        # Serialize the verify key to send it to a third party (32)
        verify_key_bytes = verify_key.encode()

        # Create a VerifyKey object from a hex serialized public key
        verify_key = VerifyKey(verify_key_bytes)

        # Check the validity of a message's signature
        # The message and the signature can either be passed together, or
        # separately if the signature is decoded to raw bytes.
        # These are equivalent:
        verify_key.verify(signed.message, signed.signature)

        await init_p2pd()
        i = await Interface().start_local()
        route = i.route()
        name = "test"
        url = "http://net-debug.000webhostapp.com/name_store.php"
        db_path = "/home/lounge-linux-vm/Desktop/kvs.db"
        kvs = NameStore(route, url, db_path)
        await kvs.start()
        #nonce = await kvs.get_nonce(name)
        #print(nonce)

        name = "test25"
        val = "val"
        try:
            out = await kvs.store(name, val)
            print(out)

            out = await kvs.store(name, val)
            print(out)
        except:
            pass


    async_test(test_name_store)