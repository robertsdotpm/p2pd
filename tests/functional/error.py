class PythonVersionNotSupported(Exception):
    def __init__(self, py_ver, server):
            self.server = server
            self.py_ver = py_ver
            self.msg = f"{server['os']} does not support Python version '{py_ver}'"
            super().__init__(self.msg)

"""
All shell commands need to end with a new line
to indicate the end of the command otherwise
the shell blocks forever.
"""
class UnterminatedShellCmd(Exception):
    pass

"""
Raised if a shell command has a new line anywhere that
isn't at the end indicating an invalid command.
"""
class MalformedShellCmd(Exception):
    pass