"""
This module is a simple port of the Sqlite-based key-value store
described in this Stackoverflow answer:
https://stackoverflow.com/questions/47237807/use-sqlite-as-a-keyvalue-store

The port simply replaces blocking functions with async calls using aiosqlite.
This offers a few benefits over existing open source modules:

    - It works on very old versions of Python (>= 3.6)
    - It plays well with concurrency and asyncio. 
    - It's simpler than having to define a schema.
    - And finally: it automatically converts Python data types.

Using Sqlite as the underlying library also makes the database highly reliable,
resistent to corruption, and probably has safe-guards for multi-process access.
"""

import asyncio
from collections import OrderedDict
import aiosqlite

class SqliteKVS():
    def __init__(self, file_path):
        self.file_path = file_path

    # Scheme has a text key and value.
    async def start(self):
        query = "CREATE TABLE IF NOT EXISTS kv" + \
                "(key text unique, value text)"
        
        self.db = await aiosqlite.connect(self.file_path)
        await self.db.execute(query)
        await self.db.commit()
        return self

    # Ensure the DB is closed to avoid corruption.
    async def close(self):
        await self.db.close()
        self.db = None

    def __del__(self):
        if self.db is not None:
            asyncio.create_task(
                self.close()
            )

    async def __aenter__(self):
        return await self.start()
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def len(self):
        query = 'SELECT COUNT(*) FROM kv'
        cursor = await self.db.execute(query)
        rows = (await cursor.fetchone())[0]
        await cursor.close()
        return rows if rows is not None else 0

    # Overwrite a row attached to a key.
    # Create it if it doesn't exist.
    # Store complex objects as text.
    async def put(self, key, value):
        query = 'REPLACE INTO kv (key, value) VALUES (?,?)'
        value = repr(value)
        await self.db.execute(query, (key, value))
        await self.db.commit()

    # Select values by key name.
    # Decode any complex values back to Python types.
    async def get(self, key, default=None):
        query = 'SELECT value FROM kv WHERE key = ?'
        cursor = await self.db.execute(query, (key,))
        item = await cursor.fetchone()
        await cursor.close()

        # No entry by that key exists.
        if item is None:
            if default is not None:
                return default
            raise KeyError(key)
        
        return eval(item[0])
    
    # Delete key entry in DB.
    async def unset(self, key):
        # Raise exception if it doesn't exist.
        await self.get(key)

        # Delete the key.
        query = 'DELETE FROM kv WHERE key = ?'
        await self.db.execute(query, (key,))
        await self.db.commit()

    async def iterkeys(self):
        query = 'SELECT key FROM kv'
        async with self.db.execute(query) as cursor:
            async for row in cursor:
                yield row[0]

    async def itervalues(self):
        query = 'SELECT value FROM kv'
        async with self.db.execute(query) as cursor:
            async for row in cursor:
                yield eval(row[0])

    async def iteritems(self):
        query = 'SELECT key, value FROM kv'
        async with self.db.execute(query) as cursor:
            async for row in cursor:
                yield row[0], eval(row[1])

    async def keys(self):
        key_list = []
        async for key in self.iterkeys():
            key_list.append(key)

        return key_list
    
    async def values(self):
        value_list = []
        async for value in self.itervalues():
            value_list.append(value)

        return value_list
    
    async def items(self):
        item_list = []
        async for item in self.iteritems():
            item_list.append(item)

        return item_list
    
    async def contains(self, key):
        query = 'SELECT 1 FROM kv WHERE key = ?'
        cursor = await self.db.execute(query, (key,))
        ret = await cursor.fetchone()
        await cursor.close()
        return ret is not None
    
    async def __aiter__(self):
        return self.iterkeys()

async def test_sqlite_kvs():
    kvs = SqliteKVS("test_sqlite_db.sqlite")
    await kvs.start()

    await kvs.put("my_test_key", [("test"), {'a': b'b'}])
    await kvs.put("another key", 2)

    #ret = await kvs.get("my_test_key")
    #print(ret)

    async for row in kvs.iterkeys():
        print(row)

    l = await kvs.len()
    print(l)

    r = await kvs.keys()
    print(r)

    r = await kvs.values()
    print(r)

    i = await kvs.items()
    print(i)

    await kvs.put("key_to_dele", 1000)
    print(await kvs.items())
    await kvs.unset("key_to_dele")
    print(await kvs.items())

    print(await kvs.contains("some bs"))
    print(await kvs.contains("my_test_key"))

    async for row in kvs:
        print(row)

    await kvs.close()

    async with SqliteKVS("test_sqlite_db.sqlite") as kvs:
        ret = await kvs.get("my_test_key")
        print(ret)

#async_test(test_sqlite_kvs)