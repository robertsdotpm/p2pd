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
        buf  = 'set P2PD_DEBUG=1 && '
        buf += 'set PYENV_ROOT="%USERPROFILE%\\.pyenv" && '
        buf += 'set PATH="%PYENV_ROOT%\\bin;%PATH%"\n'
    else:
        buf  = 'export P2PD_DEBUG=1; '
        buf += 'export PYENV_ROOT="$HOME/.pyenv"; '
        buf += 'export PATH="$PYENV_ROOT/bin:$PATH"; '
        buf += 'eval "$(pyenv init -)"\n'

    return buf

class Shell():
    def __init__(self, node):
        self.node = node
        self.con = None
        self.process = None
        self.stdout = ""
        self.long_running = []

    async def init_env(self):
        init_cmd = init_pyenv_vars_cmd(self.node)
        await self.write(init_cmd)

    async def start(self):
        self.con = await ssh_connect(self.node)
        if not "windows" in self.node["os"]:
            self.process = await self.con.create_process(
                self.node["shell"]
            )

        # Setup pyenv paths.
        await self.init_env()
        return self

    async def write(self, cmd, long_running=False, timeout=30):
        if not cmd or cmd[-1] != "\n":
            raise UnterminatedShellCmd(cmd)
        
        if "\n" in cmd[:-1]:
            raise MalformedShellCmd(cmd)

        if self.process:
            self.process.stdin.write(cmd)
            await self.process.stdin.drain()
        else:
            if long_running:
                process = await self.con.create_process(cmd)
                self.long_running.append(process)
            else:
                self.stdout += (await self.con.run(cmd, check=True, timeout=timeout)).stdout

    async def readline(self, process=None, timeout=2):
        process = process or self.process
        if process:
            return await asyncio.wait_for(
                process.stdout.readline(),
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
                self.stdout = self.stdout[index + 1:]
                return extracted
            
    async def await_cmd(self, cmd, process=None, timeout=2):
        marker = "__CMD_DONE_MARKER__"
        cmd = chain_cmds(cmd, f"echo {marker}") + "\n"
        await self.write(cmd)

        lines = []
        try:
            while True:
                try:
                    line = await self.readline(process=process, timeout=timeout)
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

        for process in self.long_running:
            process.close()

        if self.con:
            self.con.close()