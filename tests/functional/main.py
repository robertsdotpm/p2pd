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
        pyver = choose_first_py_ver(server)

        print(f"{server['os']}> Installing latest P2PD ({pyver}).")
        chain_cmds = get_chain_cmds(server)
        async with ssh_connect(server) as con:
            # Start a persistent shell
            async with con.create_process(server["shell"]) as shell:
                # Set paths to pyenv tool.
                init_cmd = init_pyenv_vars_cmd(server)
                shell.stdin.write(init_cmd)

                # Install this module through pyenv version.
                pyenv_cmd = pyenv_install_p2pd(pyver, server)

                # Waits for the command to be done in the active shell session.
                await ssh_await_cmd(pyenv_cmd, shell, chain_cmds)

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
        chain_cmds = get_chain_cmds(active)

        # Setup shell and env for passive server.
        print(f"{passive['os']}> Starting passive shell.")
        passive_con = await ssh_connect(passive)
        passive_shell = await passive_con.create_process("bash -l")
        #await shell_write("pkill -f p2pd\n", passive_shell) # TODO: win
        await shell_write("export P2PD_DEBUG=1\n", passive_shell)
        init_cmd = init_pyenv_vars_cmd(passive)
        await shell_write(init_cmd, passive_shell)

        # Get PNP address of the passive node.
        print(f"{passive['os']}> Getting passive node address.")
        py_ver = choose_first_py_ver(passive)
        cmd = p2pd_cmd + "get_nickname"
        cmd = pyenv_run_cmd(py_ver, passive, cmd)
        print(cmd)
        results = await ssh_await_cmd(cmd, passive_shell, chain_cmds, timeout=20)
        print(results)
        passive_pnp = results.strip()
        print("\t", passive_pnp)

        # Start passive node listening for cons.
        print(f"{passive['os']}> Starting passive node.")
        cmd = p2pd_cmd + "1"
        cmd = pyenv_run_cmd(py_ver, passive, cmd) + "\n" # TODO: background on win?
        await shell_write(cmd, passive_shell)
        await asyncio.sleep(5)

        # Setup shell and env for active server.
        print(f"{active['os']}> Starting active shell.")
        active_con = await ssh_connect(active)
        active_shell = await active_con.create_process("bash -l")
        await shell_write("export P2PD_DEBUG=1\n", active_shell)
        #await shell_write("pkill -f p2pd\n", active_shell) # TODO: win?
        init_cmd = init_pyenv_vars_cmd(active)
        await shell_write(init_cmd, active_shell)

        # Start active node -- connect to passive node (local con)
        # Echo down the returned pipe and get the output.
        # (0) connect (d)irect (l)an ipv(4)
        # NOTE: changed to (r) to test reverse con
        print(f"{active['os']}> Try connect and echo to passive node.")
        cmd = f'{p2pd_cmd}0dl4 --echo "CLEAN_SHUTDOWN" --dest_addr {passive_pnp}'
        #print(cmd)
        cmd = pyenv_run_cmd(py_ver, active, cmd)
        await shell_write(cmd + "\n", active_shell)
        print(cmd)
        results = await active_shell.stdout.readline()
        print(results)

        # Close long-running processes.
        # TODO: task kill on win?
        #cmd = "pkill -15 p2pd\n"
        #await shell_write(cmd, active_shell)
        #await shell_write(cmd, passive_shell)
    finally:
        shells = (active_shell, passive_shell,)
        for shell in shells:
            if shell is not None:
                shell.close()

    # Close cons and active programs.
    passive_con.close()
    active_con.close()

async def run_client():
    # Freebsd and fedora, chosen arbitrary to start testing with.
    servers = (SSH_SERVERS[3], SSH_SERVERS[4],)
    await git_pull_latest(servers)
    await pyenv_install_latest(servers)
    await tunnel_test(*servers)
    

try:
    asyncio.get_event_loop().run_until_complete(run_client())
except (OSError, asyncssh.Error) as exc:
    sys.exit('SSH connection failed: ' + str(exc))