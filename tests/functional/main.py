import asyncio, asyncssh, sys
from servers import SSH_SERVERS
from utils import *
from error import *

"""
#not found
# maybe log if this string occurs from running a command to avoid hiding errrors
p2pd uses home for everything, allow install to the pyenv sub dir or its
going to have conflicts so needs an install_dir cmd
"""

async def git_pull_latest(servers):
    for server in servers:
        print(f"{server['os']}> Git pull latest code.")

        """
        Change to the P2PD code dir and then git pull the latest code
        on the folders branch.
        """
        p2pd_dir = get_p2pd_code_path(server)
        async with ssh_connect(server) as con:
            cmd = f"""cd "{p2pd_dir}" && git pull"""
            await con.run(cmd, check=True)

def pyenv_install_p2pd(py_ver, server):
    p2pd_dir = get_p2pd_code_path(server)
    pip_install = f'-m pip install "{p2pd_dir}"'
    return pyenv_run(py_ver, server, pip_install)

async def run_client():
    # Freebsd and fedora, chosen arbitrary to start testing with.
    servers = (SSH_SERVERS[3], SSH_SERVERS[4],)
    #await git_pull_latest(servers)
    cmd = pyenv_install_p2pd("3.5.10", servers[0])
    print(cmd)
    async with (ssh_connect(servers[0])) as con:
        """
        result = await con.run('echo $PATH', check=True)
        print(result.stdout)

        result = await con.run("echo hello")
        print(result)
        """
        #print(await con.run("whoami", check=True))
        print(await con.run('bash -lc "PYENV_VERSION=3.5.10 pyenv exec python -m pip install /root/p2pd_dev/p2pd"', check=True))

        return
        result = await con.run(cmd, check=True)
        print(result)
        

try:
    asyncio.get_event_loop().run_until_complete(run_client())
except (OSError, asyncssh.Error) as exc:
    sys.exit('SSH connection failed: ' + str(exc))