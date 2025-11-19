"echo $SHELL"

SSH_SERVERS = [
    {
        "os": "windows server 2022",
        "ip": "10.0.1.248",
        "shell": "powershell.exe -NoLogo -NoProfile",
        "user": "administrator",
        "home": ["C:\\", "Users", "Administrator"],
        "pyenv": ["3.5.4", "3.7.9", "3.9.13", "3.13.1"]
    },


    {
        "os": "windows 10",
        "ip": "10.0.1.199",
        "shell": "powershell.exe -NoLogo -NoProfile",
        "user": "matth",
        "home": ["C:\\", "Users", "matth"],
        "pyenv": ["3.5.4", "3.7.9", "3.9.13", "3.13.1"]
    },

    {
        "os": "debian",
        "ip": "110.0.1.251",
        "shell": "bash -l",
        "user": "x",
        "home": ["/", "home", "x"],
        "pyenv": ["3.5.10", "3.7.10", "3.9.10", "3.12.10"]
    },

    {
        "os": "mac os x big sur",
        "ip": "10.0.1.158",
        "shell": "bash -l", # installed bash but uses zsh but default.
        "user": "xx",
        "home": ["/", "Users", "xx"],
        "pyenv": ["3.5.10", "3.7.10", "3.9.10", "3.12.10"]
    },

    {
        "os": "android pixel 9a",
        "ip": "10.0.1.123",
        "shell": "bash -l",
        "user": "x",
        "home": ["/", "data", "data", "com.termux", "files", "home"],
        "port": 8022,
        "py": "3.12.12"
        #"cmd": "proot-distro login debian"
    },

    {
        "os": "freebsd",
        "ip": "10.0.1.225",
        "shell": "bash -l",
        "user": "root",
        "home": ["/", "root"],
        "pyenv": ["3.5.10", "3.7.10", "3.9.10", "3.12.0"]
    },

    {
        "os": "fedora",
        "ip": "10.0.1.224",
        "shell": "bash -l",
        "user": "x",
        "home": ["/", "home", "x"],
        "pyenv": ["3.5.10", "3.7.10", "3.9.10", "3.12.0"]
    },

    {
        "os": "ghostbsd",
        "ip": "10.0.1.152",
        "shell": "bash -l",
        "user": "x",
        "home": ["/", "home", "x"],
        "pyenv": ["3.5.10", "3.7.10", "3.9.10", "3.12.10"]
    },

    {
        "os": "windows 11",
        "ip": "10.0.1.123",
        "shell": "cmd.exe",
        "user": "matth",
        "home": ["C:\\", "Users", "matth"],
        "pyenv": ["3.5.4", "3.7.9", "3.9.13", "3.12.10"]
    },

    {
        "os": "windows xp pro",
        "ip": "10.0.1.132",
        "shell": "cmd.exe",
        "user": "matthew",
        "home": ["C:\\", "Documents and Settings", "matthew"],
        "py": "3.5.0"
    },

    {
        "os": "windows 8.1 pro",
        "ip": "10.0.1.165",
        "shell": "cmd.exe",
        "user": "x",
        "home": ["C:\\", "Users", "x"],
        "pyenv": ["3.5.4", "3.7.9", "3.9.13", "3.12.0"]
    },



    {
        "os": "windows vista",
        "ip": "10.0.1.167",
        "shell": "cmd.exe",
        "user": "x",
        "home": ["C:\\", "Users", "x"],
        "py": "3.7.0"
    },


    {
        "os": "windows 7",
        "ip": "10.0.1.231",
        "shell": "cmd.exe",
        "user": "x",
        "home": ["C:\\", "Users", "x"],
        "pyenv": ["3.5.0", "3.7.0"]
    },
]

