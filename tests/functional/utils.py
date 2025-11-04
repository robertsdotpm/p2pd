import asyncssh
from posixpath import join as nix_join
from ntpath import join as nt_join
from defs import *
from error import *

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
        options=opts,
    )

def server_has_py_ver(py_ver, server):
    if "pyenv" in server:
        if py_ver in server["pyenv"]:
            return True
        
    if "py" in server:
        if py_ver == server["py"]:
            return True
        
    return False

def pyenv_run(py_ver, server, cmd):
    # Ensure server supports requested Python version.
    if not server_has_py_ver(py_ver, server):
        raise PythonVersionNotSupported(py_ver, server)
    
    # Run the next command with a given env set.
    if "windows" in server["os"]:
        sep = " && "
    else:
        sep = " "

    # Full command looks like this with some edge-cases.
    out = f"PYENV_VERSION={py_ver}{sep}pyenv exec python {cmd}"
    if "windows" in server["os"]:
        out = "set " + out

    return out