import asyncio, asyncssh, sys
from posixpath import join as nix_join  # always use POSIX style
from ntpath import join as nt_join     # always use Windows style
from servers import SSH_SERVERS

async def run_client():
    for server in SSH_SERVERS:
        path_join = nix_join
        if "windows" in server["os"]:
            path_join = nt_join

        p2pd_dir = path_join(*server["home"], "p2pd_dev", "p2pd")
        port = 22
        if "port" in server:
            port = server["port"]

        async with asyncssh.connect(server["ip"], username=server["user"], client_keys=['~/.ssh/id_rsa'], port=port) as conn:
            #print(conn)
            #result = await conn.run("echo hello", check=True)
            #print(result.stdout, end='')
            #return
            if "cmd" in server:
                cmd = server["cmd"]
                print(cmd)
                result = await conn.run(cmd)
                print(result.stdout, end='')

            cmd = f"""cd "{p2pd_dir}" && git pull"""
            print(cmd)
            result = await conn.run(cmd, check=True)
            print(result.stdout, end='')

try:
    asyncio.get_event_loop().run_until_complete(run_client())
except (OSError, asyncssh.Error) as exc:
    sys.exit('SSH connection failed: ' + str(exc))