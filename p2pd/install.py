import os
import pathlib
import inspect
import shutil
import psutil

# Path to where the script is running from.
def get_script_parent():
    filename = inspect.getframeinfo(inspect.currentframe()).filename
    parent = pathlib.Path(filename).resolve().parent
    return os.path.realpath(parent)

# Home dir / p2pd.
def get_p2pd_install_root():
    return os.path.realpath(
        os.path.join(
            os.path.expanduser("~"),
            "p2pd"
        )
    )

# Home dir / p2pd / kvs.sqlite3.
# Used to store ECDSA key pairs that own PDNS names.
def get_kvs_db_install_path(install_root):
    return os.path.realpath(
        os.path.join(
            install_root,
            "kvs.sqlite3"
        )
    )

# Location in p2pd install where the blank KVS db lives.
def get_kvs_db_copy_path(script_parent):
    return os.path.realpath(
        os.path.join(
            script_parent,
            "scripts",
            "kvs_schema.sqlite3"
        )
    )

# Installs P2PD files into home dir.
# The software only needs this for using PDNS functions.
def copy_p2pd_install_files_as_needed():
    # Make install dir if needed.
    install_root = get_p2pd_install_root()
    pathlib.Path(install_root).mkdir(parents=True, exist_ok=True)

    # Copy KVS db if needed.
    script_parent = get_script_parent()
    kvs_db_copy_path = get_kvs_db_copy_path(script_parent)
    kvs_db_install_path = get_kvs_db_install_path(install_root)
    if not os.path.isfile(kvs_db_install_path):
        shutil.copy(kvs_db_copy_path, kvs_db_install_path)

def p2pd_detect_zombie_serv(serv_port):
    already_running = True
    my_pid = os.getpid()
    pidfile_path = os.path.realpath(
        os.path.join(
            get_p2pd_install_root(),
            f"{serv_port}_pid.txt"
        )
    )

    # If file exists and contains our id.
    # It's this process and isn't already running.
    if os.path.exists(pidfile_path):
        with open(pidfile_path) as f:
            pid = f.read()
            pid = int(pid) if pid.isnumeric() else None
        
        if pid is not None:
            if psutil.pid_exists(pid):
                found_pid = psutil.Process(pid).cmdline()
                expected_pid = psutil.Process(my_pid).cmdline()
                if found_pid == expected_pid:
                    already_running = False
    
    # If no file previously exists then it can't already be running.
    if not os.path.exists(pidfile_path):
        already_running = False
        
    # Update the PID file.
    if not already_running:
        with open(pidfile_path, 'w') as f:
            f.write(str(my_pid))

    return already_running

    

if __name__ == '__main__':
    pass