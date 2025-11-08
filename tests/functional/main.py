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
    # Use local machines PNP server so names have no limits.
    p2pd_cmd = "-m p2pd.demo --pnp_server 0,4,10.0.1.204,5300 --cmd"
    chain_cmds = get_chain_cmds(active)

    # Setup shell and env for passive server.
    passive_con = await ssh_connect(passive)
    passive_shell = await passive_con.create_process(passive["shell"])
    init_cmd = init_pyenv_vars_cmd(passive)
    passive_shell.stdin.write(init_cmd)

    # Get PNP address of the passive node.
    py_ver = choose_first_py_ver(passive)
    cmd = p2pd_cmd + " get_nickname"
    cmd = pyenv_run_cmd(py_ver, passive, cmd)
    results = await ssh_await_cmd(cmd, passive_shell, chain_cmds, timeout=10)
    passive_pnp = results.strip()

    # Start passive node listening for cons.
    cmd = p2pd_cmd + "1"
    cmd = pyenv_run_cmd(py_ver, passive, cmd)
    passive_shell.stdin.write(cmd)

    # Setup shell and env for passive server.
    active_con = await ssh_connect(active)
    active_shell = await active_con.create_process(active["shell"])
    init_cmd = init_pyenv_vars_cmd(active)
    active_shell.stdin.write(init_cmd)

    # Start active node -- connect to passive node (local con)
    # Echo down the returned pipe and get the output.
    # (0) connect (d)irect (l)an ipv(4)
    cmd = f'{p2pd_cmd} 0dl4 --echo "hello world" --dest_addr {passive_pnp}'
    cmd = pyenv_run_cmd(py_ver, passive, cmd)
    results = await ssh_await_cmd(cmd, passive_shell, chain_cmds, timeout=10)
    print(results)

    # Close cons and active programs.
    await passive_con.close()
    await active_con.close()

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