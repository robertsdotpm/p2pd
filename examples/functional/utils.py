import asyncio
import asyncssh
import shlex
from posixpath import join as nix_join
from ntpath import join as nt_join
from defs import *
from error import *

def chain_cmds(*args):
    assert("\n" not in args)
    out = " && ".join(args)
    return out

def get_chain_cmds(server):
    def chain_cmds(*args):
        assert("\n" not in args)
        out = " && ".join(args)
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
    out = f"PYENV_VERSION={py_ver}{sep}pyenv exec python -u {cmd}"
    if "windows" in server["os"]:
        out = "set " + out

    return out

def pyenv_install_p2pd(py_ver, server):
    p2pd_dir = get_p2pd_code_path(server)
    assert("\n" not in p2pd_dir)
    pip_install = f'-m pip install --force-reinstall -e "{p2pd_dir}"'
    return pyenv_run_cmd(py_ver, server, pip_install)

def choose_first_py_ver(server):
    if "pyenv" in server:
        return server["pyenv"][0]
    else:
        return server["py"]
    
def init_pyenv_vars_cmd(server):
    if "windows" in server["os"]:
        buf  = 'set PYENV_ROOT="%USERPROFILE%\\.pyenv" && '
        buf += 'set PATH="%PYENV_ROOT%\\bin;%PATH%"\n'
    else:
        buf  = 'export PYENV_ROOT="$HOME/.pyenv"; '
        buf += 'export PATH="$PYENV_ROOT/bin:$PATH"; '
        buf += 'eval "$(pyenv init -)"\n'

    return buf

class Shell():
    def __init__(self, node):
        self.node = node
        self.con = None
        self.process = None
        self.stdout = ""
        self.chaincmds = chain_cmds

    async def start(self):
        self.con = await ssh_connect(self.node)
        if not "windows" in self.node["os"]:
            self.process = await self.con.create_process(
                self.node["shell"]
            )

        return self

    async def write(self, cmd):
        if not cmd or cmd[-1] != "\n":
            raise UnterminatedShellCmd(cmd)
        
        if "\n" in cmd[:-1]:
            raise MalformedShellCmd(cmd)

        if self.process:
            self.process.stdin.write(cmd)
            await self.process.stdin.drain()
        else:
            self.stdout += (await self.con.run(cmd, check=True)).stdout

    async def readline(self, timeout=2):
        if self.process:
            return await asyncio.wait_for(
                self.process.stdout.readline(),
                timeout=timeout
            )
        else:
            sleep_step = 0.1
            for _ in range(0, int(timeout / sleep_step)):
                if '\n' not in self.stdout:
                    await asyncio.sleep(sleep_step)
                    continue

                index = self.stdout.find('\n')
                extracted = self.stdout[:index + 1]
                self.stdout = index[index + 1:]
                return extracted
            
    async def await_cmd(self, cmd, timeout=2):
        marker = "__CMD_DONE_MARKER__"
        cmd = self.chain_cms(cmd, f"echo {marker}") + "\n"
        await self.write(cmd)

        lines = []
        try:
            while True:
                try:
                    line = await self.readline(timeout=timeout)
                except asyncio.TimeoutError:
                    lines.append(f"[timeout after {timeout}s]")
                    break

                if not line:
                    break
                if marker in line:
                    break
                lines.append(line.strip())

        except Exception as e:
            output = "\n".join(lines).strip()
            raise Exception(output + f"[error: {e}]")

        output = "\n".join(lines).strip()
        return output if output else "[no output]"
    
    async def close(self):
        if self.process:
            self.process.close()

        if self.con:
            self.con.close()