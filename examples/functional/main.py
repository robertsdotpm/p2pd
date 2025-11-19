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

direct and reverse working on nix 3.5
    -- not liking that when pyenv has an error the command just returns nothing

i dont think forked processes (for the process pool in
punching are being closed properly?)

pkill -9 -f 'p2pd'
disabling pp_executors for now as a test
"""

PY_VER = "3.7.9"

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
        # For now just choose any Python version.
        pyver = PY_VER or choose_first_py_ver(server)

        print(f"{server['os']}> Installing latest P2PD ({pyver}).")
        shell = await Shell(server).start()

        # Install this module through pyenv version.
        pyenv_cmd = pyenv_install_p2pd(pyver, server)

        # Waits for the command to be done in the active shell session.
        await shell.await_cmd(pyenv_cmd)
        await shell.close()

async def tunnel_test(active, passive):
    """
    If running script in rapid succession against same node pairs
    at least give them time to clean up...
    """
    await asyncio.sleep(2)
    passive_shell = active_shell = None
    try:

        # Use local machines PNP server so names have no limits.
        p2pd_cmd  = "-m p2pd.demo --pnp_server 0,4,10.0.1.204,5300 "
        p2pd_cmd += "--disable_upnp 1 --run_time 120 --cmd "

        # Setup shell and env for passive server.
        print(f"{passive['os']} (p)> Starting passive shell.")
        passive_shell = await Shell(passive).start()

        # Get PNP address of the passive node.
        print(f"{passive['os']} (p)> Getting passive node address.")
        py_ver = PY_VER or choose_first_py_ver(passive)
        cmd = p2pd_cmd + "get_nickname"
        cmd = pyenv_run_cmd(py_ver, passive, cmd)
        print(cmd)
        results = await passive_shell.await_cmd(cmd, timeout=20)
        print(results)
        passive_pnp = results.strip()
        print("\t", passive_pnp)

        # Start passive node listening for cons.
        print(f"{passive['os']} (p)> Starting passive node.")
        cmd = p2pd_cmd + "1"
        cmd = pyenv_run_cmd(py_ver, passive, cmd) + "\n" # TODO: background on win?
        print(cmd)
        cmd = "cmd.exe /k " + cmd
        passive_proc = await passive_shell.write(cmd, long_running=True)
        await asyncio.sleep(5)

        # Setup shell and env for active server.
        print(f"{active['os']} (a)> Starting active shell.")
        active_shell = await Shell(active).start()

        # Start active node -- connect to passive node (local con)
        # Echo down the returned pipe and get the output.
        # (0) connect (d)irect (l)an ipv(4)
        # NOTE: changed to (r) to test reverse con
        print(f"{active['os']} (a)> Try connect and echo to passive node.")
        cmd = f'{p2pd_cmd}0pl4 --echo "CLEAN_SHUTDOWN" --dest_addr {passive_pnp}'
        #print(cmd)
        cmd = pyenv_run_cmd(py_ver, active, cmd)
        #cmd = "start " + cmd
        print(cmd)
        cmd = "cmd.exe /k " + cmd
        proc = await active_shell.write(cmd + "\n", timeout=120)
        print("try read return.")
        print(active_shell.stdout)
        #results = await active_shell.readline()
        #results = await passive_shell.readline()
        print(results)
    finally:
        shells = (active_shell, passive_shell,)
        for shell in shells:
            if shell is not None:
                await shell.close()

async def windows_test(node):
    con = await ssh_connect(node)
    result = await con.run('dir', check=True)
    print(result.stdout, end='')

async def run_client():
    # Freebsd and fedora, chosen arbitrary to start testing with.
    servers = (SSH_SERVERS[0], SSH_SERVERS[1],)
    #servers = (SSH_SERVERS[5], SSH_SERVERS[6],)
    await git_pull_latest(servers)
    await pyenv_install_latest(servers)

    #await windows_test(servers[0])
    await tunnel_test(*servers)
    

try:
    asyncio.get_event_loop().run_until_complete(run_client())
except (OSError, asyncssh.Error) as exc:
    sys.exit('SSH connection failed: ' + str(exc))