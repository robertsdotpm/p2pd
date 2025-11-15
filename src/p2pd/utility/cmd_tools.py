import ctypes
import shlex
import asyncio
import tempfile
import os
import uuid
import platform
import sys
import subprocess
import base64
from ..utility.utils import *

"""
Windows doesn't always use UTF-8 for string encoding.
Depending on which functions you're using.
This completely screws encoding and decoding bytes / strs.
"""
os.environ["PYTHONIOENCODING"] = "utf-8"

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
    except Exception:
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

def win_arg_escape(arg, allow_vars=0):
    # Double all the backslashes before a double quote.
    # Then ensure the double quote is escaped.
    # Doubling up neutralizes double quotes that may be unbalanced.
    # Since this is done you ensure quotes are all escaped properly.
    arg = re.sub(r'(\\*)"', r'\1\1\\"', arg)

    # Double up continuous backslashes at the end of the string.
    arg = re.sub(r'(\\*)$', r'\1\1', arg)

    # Replace special characters.
    arg = re.sub('([()%!^<>&|;,])', r'^\1', arg)

    # Surround entire arg with quotes.
    # This avoids spaces breaking a command.
    arg = '"%s"' % (arg)

    return arg

def get_powershell_path():
    ps_dir = "%WINDIR%\\System32\\WindowsPowerShell"
    ps_dir = os.path.expandvars(ps_dir)
    dir_list = os.listdir(ps_dir)

    version_dir = None
    version_info = None
    for sub_dir in dir_list:
        p = "v([0-9]+)(?:[.]([0-9]+))?"
        out = re.findall(p, sub_dir)
        if not len(out):
            continue
        out = out[0]

        if version_dir is None:
            version_dir = sub_dir
            version_info = out
            continue

        big_version, little_version = out
        if big_version > version_info[0]:
            version_dir = sub_dir
            version_info = out
            continue

        if big_version == version_info[0]:
            if little_version > version_info[1]:
                version_dir = sub_dir
                version_info = out
                continue

    if version_dir is None:
        raise Exception("Cannot find powershell dir.")
    
    ps_dir = os.path.join(ps_dir, version_dir, "powershell.exe")
    return ps_dir

"""
There is an issue with create_subprocess_shell on Windows 10
with the latest Python versions. When you try use this code
a window will pop up asking you how you want to open this
file. A hack I've found that works is to pass the command
you want to execute to powershell.

Example: 'powershell "route print"'
"""
async def cmd(value, io=None, er=True, timeout=10):
    # Output type.
    out_type = value
    null_out = to_type('', out_type)

    # Setup STDIN pipes.
    in_val = None
    if io is not None:
        in_val = asyncio.subprocess.PIPE

    this_dir = os.path.dirname(__file__)
    try:
        if er is None:
            er = asyncio.subprocess.DEVNULL
        else:
            er = None

        proc = await asyncio.create_subprocess_shell(
            value,
            stdin=in_val,
            stdout=asyncio.subprocess.PIPE,
            stderr=er,
            cwd=this_dir,
            shell=True
        )

        if timeout:
            try:
                task = proc.communicate(input=io)
                stdout, stderr = await asyncio.wait_for(task, timeout)
            except asyncio.TimeoutError:
                log(fstr("command {0} timed out", (value,)))
                return null_out
        else:
            stdout, stderr = await proc.communicate(input=io)
    except NotImplementedError:
        # Backup function for old Python versions.
        @run_in_executor
        def blocking_cmd(er):
            try:
                if er is None:
                    er = subprocess.DEVNULL
                else:
                    er = None

                proc = subprocess.run(value, stdout=subprocess.PIPE, shell=True, stderr=er, timeout=timeout)
                stdout = proc.stdout
                stderr = proc.stderr
            except subprocess.TimeoutExpired:
                log(fstr("command {0} timed out", (value,)))
                return null_out

            return stdout, stderr
        
        # Use an executor to run the blocking command so the event loop isn't wrekt.
        stdout, stderr = await blocking_cmd(er)

    # Log any visible errors.
    if stderr is not None and len(stderr):
        log(fstr("cmd {0} stderr = {1}", (value, stderr,)))

    # Return command output.
    if stdout is None:
        return null_out
    else:
        return to_type(stdout, out_type)
    
def powershell_encoded_cmd(ps1):
    unicode_bytes = ps1.encode("utf-16le")
    param = base64.b64encode(unicode_bytes)
    return to_s(param)

async def ps1_exec_trick(ps1):
    param = powershell_encoded_cmd(ps1)
    ps_path = get_powershell_path()
    out = await cmd(fstr("{0} -encodedCommand {1}", (ps_path, param,)), timeout=None)
    log(out)
    return out

async def is_pshell_restricted():
    out = await cmd("powershell Get-ExecutionPolicy", timeout=None)
    return not "Unrestricted" in out

async def nt_pshell(value, timeout=10, is_unrestricted=None):
    # Allow powershell scripts to be run
    # by modifying registry if needed.
    if is_unrestricted is None:
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