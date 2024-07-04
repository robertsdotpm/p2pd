"""
py-machineid
~~~~~~~~~~~~

Get the unique machine ID of any host (without admin privileges).

Basic usage:

>>> import machineid
>>> machineid.id()
17A28A73-BEA9-4D4B-AF5B-03A5AAE9B92C

You can anonymize the ID like so, with an optional app ID:

>>> machineid.hashed_id('myappid')
366048092ef4e7db53cd7adec82dcab15ab67ac2a6b234dc6a69303a4dd48e83
>>> machineid.hashed_id()
ce2127ade536eaa9529f4a7b73141bbc2f094c46e32742c97679e186e7f13fde

Special thanks to Denis Brodbeck for his Go package, machineid (https://github.com/denisbrodbeck/machineid).

:license: MIT, see LICENSE for more details.
"""

__version__ = '0.5.1'
__author__  = 'Zeke Gabrielse'
__credits__ = 'https://github.com/denisbrodbeck/machineid'

from platform import uname
from sys import platform
import subprocess
import hashlib
import hmac
import re
import socket


def __sanitize__(s):
    return re.sub(r'[\x00-\x1f\x7f-\x9f\s]', '', s).strip()

def __exec__(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, check=True, encoding='utf-8') \
                .stdout \
                .strip()
    except:
        return None

def __read__(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except:
        return None

def __reg__(registry, key):
    try:
        from winregistry import WinRegistry
        with WinRegistry() as reg:
            return reg.read_entry(registry, key).value.strip()
    except:
        return None

def get_machine_id(winregistry=True):
    """
    id returns the platform specific device GUID of the current host OS.
    """
    x = None

    # Mac support.
    if platform == 'darwin':
        x = __exec__("ioreg -d2 -c IOPlatformExpertDevice | awk -F\\\" '/IOPlatformUUID/{print $(NF-1)}'")

    # Windows.
    if platform in ('win32', 'cygwin', 'msys'):
        if winregistry:
            x = __reg__(r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography', 'MachineGuid')
        else:
            x = __exec__("powershell.exe -ExecutionPolicy bypass -command (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID")

        if not x:
            x = __exec__('wmic csproduct get uuid').split('\n')[2].strip()

    # Linux and possibly Android.
    if platform.startswith('linux'):
        x = __read__('/var/lib/dbus/machine-id')
        if not x:
            x = __read__('/etc/machine-id')

        if not x:
            cgroup = __read__('/proc/self/cgroup')
            if cgroup and 'docker' in cgroup:
                x = __exec__('head -1 /proc/self/cgroup | cut -d/ -f3')

        if not x:
            mountinfo = __read__('/proc/self/mountinfo')
            if mountinfo and 'docker' in mountinfo:
                x = __exec__("grep -oP '(?<=docker/containers/)([a-f0-9]+)(?=/hostname)' /proc/self/mountinfo")

        if not x and 'microsoft' in uname().release: # wsl
            x = __exec__("powershell.exe -ExecutionPolicy bypass -command '(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID'")

    # BSD.
    if platform.startswith(('openbsd', 'freebsd')):
        x = __read__('/etc/hostid')
        if not x:
            x = __exec__('kenv -q smbios.system.uuid')

    if not x:
        raise Exception(f'failed to obtain id on {platform}')

    return __sanitize__(x)

def hashed_machine_id(app_id="", **kwargs):
    """
    hashed_id returns the device's native GUID, hashed using HMAC-SHA256 with an optional application ID.
    """

    return hmac.new(
        bytes(app_id.encode()),
        get_machine_id(**kwargs).encode(),
        hashlib.sha256,
    ).hexdigest()
