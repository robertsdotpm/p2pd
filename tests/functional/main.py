import asyncio, asyncssh, sys
from servers import SSH_SERVERS
from utils import *
from error import *

"""
#not found
# maybe log if this string occurs from running a command to avoid hiding errrors
p2pd uses home for everything, allow install to the pyenv sub dir or its
going to have conflicts so needs an install_dir cmd

the bash -l pattern is stupid, launch a new, clean shell with -c
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

async def pyenv_install_latest(servers):
    for server in servers:
        print(f"{server['os']}> Installing latest P2PD.")
        async with ssh_connect(server) as con:
            # Start a persistent shell
            async with con.create_process(server["shell"]) as shell:
                print(shell)
                await init_shell_env(shell, server)

                py_ver = choose_first_py_ver(server)
                pyenv_cmd = pyenv_install_p2pd(py_ver, server)
                print(pyenv_cmd)
                shell.stdin.write(pyenv_cmd)

                # Collect stdout/stderr
                while 1:
                    stdout = await shell.stdout.readline()
                    if not stdout:
                        break

                    print(stdout)

async def tunnel_test(active, passive):
    # Get PNP address of the passive node.
    passive_con = await ssh_connect(passive)
    return


    cmd = "-m p2pd.demo --pnp_server 0,4,10.0.1.204,5300 --cmd get_nickname"
    py_ver = choose_first_py_ver(passive)
        # Initialize pyenv once if needed
    
    #cmd = pyenv_run(py_ver, passive, cmd)
    print(cmd)
    passive_addr = await passive_con.run(cmd, check=True)
    print(passive_addr)

async def run_client():
    # Freebsd and fedora, chosen arbitrary to start testing with.
    servers = (SSH_SERVERS[3], SSH_SERVERS[4],)
    await git_pull_latest(servers)
    await pyenv_install_latest(servers)
    #await tunnel_test(*servers)
    

try:
    asyncio.get_event_loop().run_until_complete(run_client())
except (OSError, asyncssh.Error) as exc:
    sys.exit('SSH connection failed: ' + str(exc))