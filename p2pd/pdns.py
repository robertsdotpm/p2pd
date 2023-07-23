from .name_store import *
from .settings import *
from .install import *

class PDNS():
    def __init__(self, name, registrar_id="000webhost"):
        self.name = name
        self.registrar_id = registrar_id
        if self.registrar_id not in PDNS_REGISTRARS:
            raise Exception("Registrar ID not found.")
        
        self.name_url = PDNS_REGISTRARS[registrar_id]

    async def res(self, route):
        # Resolve registrar domain.
        ns = NameStore(route, self.name_url)
        await ns.start()

        # Return a name result
        return await ns.get_val(self.name)
    
    async def register(self, route, value):
        # Makes sure that the SQLITE3 db is available
        # for storing PDNS names.
        copy_p2pd_install_files_as_needed()
        install_root = get_p2pd_install_root()
        db_path = get_kvs_db_install_path(install_root)

        # Resolve key value script domain.
        ns = NameStore(route, self.name_url, db_path)
        await ns.start()

        # Store a value at name.
        # If it's a name we've previously used then update it.
        out = await ns.store_val(self.name, value)

        # Close DB writing changes to disk.
        ns.close()
        return out

if __name__ == '__main__':
    async def test_pdns():
        print("yes")

    async_test(test_pdns)