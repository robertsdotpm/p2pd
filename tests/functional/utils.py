import asyncio
import asyncssh
import shlex
from posixpath import join as nix_join
from ntpath import join as nt_join
from defs import *
from error import *

def get_chain_cmds(server):
    def chain_cmds(*args):
        assert("\n" not in args)
        out = " && ".join(args)
        out += "\n"
        return out
    
    return chain_cmds

def get_path_join(server):
    """
    Set the function used to join paths on different operating systems.
    Avoiding the os.path funcs because that runs relative to the OS
    that the code runs on which isn't useful here.
    """
    path_join = nix_join
    if "windows" in server["os"]:
        path_join = nt_join

    return path_join

def get_p2pd_code_path(server):
    path_join = get_path_join(server)
    p2pd_dir = path_join(*server["home"], "p2pd_dev", "p2pd")
    return p2pd_dir

def ssh_connect(server):
    port = 22
    if "port" in server:
        port = server["port"]

    opts = asyncssh.SSHClientConnectionOptions(request_pty=True)
    return asyncssh.connect(
        server["ip"],
        username=server["user"],
        client_keys=[ID_RSA_PATH],
        port=port,
        #options=opts,
    )

def server_has_py_ver(py_ver, server):
    if "pyenv" in server:
        if py_ver in server["pyenv"]:
            return True
        
    if "py" in server:
        if py_ver == server["py"]:
            return True
        
    return False


def pyenv_run_cmd(py_ver, server, cmd):
    # Ensure server supports requested Python version.
    if not server_has_py_ver(py_ver, server):
        raise PythonVersionNotSupported(py_ver, server)
    
    # Run the next command with a given env set.
    if "windows" in server["os"]:
        sep = " && "
    else:
        sep = " "

    # Full command looks like this with some edge-cases.
    out = f"PYENV_VERSION={py_ver}{sep}pyenv exec python {cmd}\n"
    if "windows" in server["os"]:
        out = "set " + out

    return out

def pyenv_install_p2pd(py_ver, server):
    p2pd_dir = get_p2pd_code_path(server)
    pip_install = f'-m pip install --force-reinstall -e "{p2pd_dir}"'
    return pyenv_run_cmd(py_ver, server, pip_install)

def choose_first_py_ver(server):
    if "pyenv" in server:
        return server["pyenv"][0]
    else:
        return server["py"]
    
def init_pyenv_vars_cmd(server):
    if "windows" in server["os"]:
        buf  = "set PYENV_ROOT=%USERPROFILE%\\.pyenv"
        buf += "set PATH=%PYENV_ROOT%\\bin;%PATH%"
    else:
        buf  = 'export PYENV_ROOT="$HOME/.pyenv"; '
        buf += 'export PATH="$PYENV_ROOT/bin:$PATH"; '
        buf += 'eval "$(pyenv init -)"\n'

    return buf

async def ssh_await_cmd(cmd, shell, chain_cms, timeout=2):
    # Write command with marker to shell.
    marker = "__CMD_DONE_MARKER__"
    cmd = chain_cms(cmd, f"echo {marker}")
    shell.stdin.write(cmd)

    # Fetch results and check for marker.
    lines = []
    while 1:
        """
        If a command has no output or has hung prevent endless loop.
        """
        try:
            line = await asyncio.wait_for(
                shell.stdout.readline(),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            break

        # Invalid line.
        if not line:
            break

        # If the end of the cmd segment was found -- quit while.
        if marker in line:
            break

        lines.append(line.strip())

    # Return results as a single str.
    return "\n".join(lines)