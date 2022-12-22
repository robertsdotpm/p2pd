import ctypes
import shlex
import asyncio
import tempfile
import os
import uuid
import platform
import sys
import subprocess
from .utils import *

"""
This requires the process to have been run as administrator
or with a UAC prompt. However, by using the technique of
writing self-contained Python files to disk that accomplish
privileged operations and then restart themselves as admin
it becomes trivial to do the whole process at run time.

E.g. use run_py_script with a script that calls
pyuac.runAsAdmin() if it's not an admin and is designed
to complete the privileged call - all as an external,
new, python process, while the original continues to
run with its original privileges.

My function nt_pshell already checks if powershell can
run scripts and if not -- automatically unrestricts
powershell and continues running the script.
"""
async def nt_set_pshell_unrestricted():
    import winreg

    def mk_unrestricted(path):
        # Open path to key for 'writing.'
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            access=winreg.KEY_SET_VALUE
        )

        # Set the sub key.
        # Create it if it doesn't exist.
        winreg.SetValueEx(
            key,
            "ExecutionPolicy",
            0,
            winreg.REG_SZ,
            "Unrestricted"
        )

        # We want to be certain the registry
        # has been updated before proceeding.
        winreg.FlushKey(key)

        # Cleanup.
        winreg.CloseKey(key)

    base_path = "SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds"
    pshell_path = base_path + "\\Microsoft.PowerShell"
    nostics_path = base_path + "\\ScriptedDiagnostics"
    mk_unrestricted(nostics_path)
    mk_unrestricted(pshell_path)

def nt_is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Surrounds with DOUBLE quotes.
def mac_arg_escape(arg):
    black_list = "\"\\"
    buf = ""
    for ch in arg:
        if ch in black_list:
            buf += "\\" + ch
        else:
            buf += ch

    return '"' + buf + '"'

"""
Note: this function escapes an argument string
for Unix shell but surrounds it by single quotes.
It returns a single quoted string with the result.
Hence the surrounding quotes APPEAR escaped when
printing them.
"""
# Surrounds with SINGLE quotes.
def nix_arg_escape(arg):
    return shlex.quote(arg)

# Surrounds with DOUBLE quotes.
def win_arg_escape(arg, allow_vars=0):
    # Symbol table for NT.
    allowed_list = """&%!^ :'"/\\abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.(),;=><|\t"""
    if allow_vars:
        allowed_list += "~%$"

    # Filter out anything that isn't a
    # standard character.
    buf = ""
    for ch in arg:
        # Check if white list is valid.
        if ch in allowed_list:
            buf += ch

        # Otherwise ignore character.

    # Edge-case escaping with doubling-up.
    buf = buf.replace('"', '""')
    buf = buf.replace("\\", "\\\\")

    # Souround entire arg with quotes.
    # This avoids spaces breaking a command.
    buf = '"%s"' % (buf)

    return buf

"""
There is an issue with create_subprocess_shell on Windows 10
with the latest Python versions. When you try use this code
a window will pop up asking you how you want to open this
file. A hack I've found that works is to pass the command
you want to execute to powershell.

Example: 'powershell "route print"'
"""
async def cmd(value, io=None, timeout=10):
    # Setup STDIN pipes.
    in_val = None
    if io is not None:
        in_val = asyncio.subprocess.PIPE
        io = to_b(io)

    this_dir = os.path.dirname(__file__)
    try:
        proc = await asyncio.create_subprocess_shell(
            value,
            stdin=in_val,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=this_dir,
            shell=True
        )

        if timeout:
            try:
                task = proc.communicate(input=io)
                stdout, stderr = await asyncio.wait_for(task, timeout)
            except asyncio.TimeoutError:
                log(f"command {value} timed out")
                return ''
        else:
            stdout, stderr = await proc.communicate(input=io)
    except NotImplementedError:
        # Backup function for old Python versions.
        @run_in_executor
        def blocking_cmd():
            try:
                proc = subprocess.run(value, stdout=subprocess.PIPE, shell=True, timeout=timeout)
                stdout = proc.stdout
                stderr = proc.stderr
            except subprocess.TimeoutExpired:
                log(f"command {value} timed out")
                return ''

            return stdout, stderr
        
        # Use an executor to run the blocking command so the event loop isn't wrekt.
        stdout, stderr = await blocking_cmd()

    # Log any visible errors.
    if stderr is not None and len(stderr):
        log(f"cmd {value} stderr = {stderr}")

    # Return command output.
    if stdout is None:
        return ""
    else:
        return to_s(stdout)

async def is_pshell_restricted():
    out = await cmd("powershell Get-ExecutionPolicy", timeout=None)
    return not "Unrestricted" in out

async def nt_pshell(value, timeout=10):
    # Allow powershell scripts to be run
    # by modifying registry if needed.
    if(await is_pshell_restricted()):
        await nt_set_pshell_unrestricted()

    # Write a temp file into the temp dir
    # with the script to execute.
    tmp_dir = tempfile.gettempdir()
    cmd_path = os.path.join(tmp_dir, str(uuid.uuid4()) + ".ps1")
    with open(cmd_path, 'w') as f:
        f.write(value)
        f.flush()
        f.close()

    # Command to tell powershell to run the script.
    cmd_str = 'powershell.exe -file %s' % (
        win_arg_escape(cmd_path)
    )

    # Wait for powershell to execute the script.
    if timeout:
        out = await cmd(cmd_str, timeout=timeout)
    else:
        out = await cmd(cmd_str, timeout=None)

    # Delete the old script file.
    if os.path.exists(cmd_path):
        os.remove(cmd_path)

    return out

def get_arg_escape_func():
    if platform.system() == "Linux":
        return nix_arg_escape

    if platform.system() == "Windows":
        return win_arg_escape

    if platform.system() in ["Darwin", "FreeBSD"]:
        return mac_arg_escape

    return None

async def run_py_script(script, root_pw=None, cleanup=False):
    # Write a temp file into the temp dir
    # with the script to execute.
    out = None
    tmp_dir = tempfile.gettempdir()
    cmd_path = os.path.join(tmp_dir, str(uuid.uuid4()) + ".py")
    escape_arg = get_arg_escape_func()
    with open(cmd_path, 'w') as f:
        f.write(script)
        f.flush()
        f.close()

        # Sudo prefix.
        prefix = ""
        if platform.system() != "Windows":
            if root_pw != None:
                prefix = "{ echo %s; } | sudo -k -S " % (
                    escape_arg(root_pw)
                )

        # Build cmd to execute the new script.
        exe_cmd = '%s%s %s' % (
            prefix,
            escape_arg(sys.executable),
            escape_arg(cmd_path)
        )
        
        # Execute the command.
        out = await cmd(exe_cmd, timeout=None)

        # Delete the script file.
        if cleanup:
            if os.path.exists(cmd_path):
                os.remove(cmd_path)

    return out

def is_root():
    if platform.system() == "Windows":
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            return False
    else:
        if os.geteuid() != 0:
            return False

    return True

def win_uac():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

def ensure_root():
    if not is_root():
        raise Exception("root required for this code.")