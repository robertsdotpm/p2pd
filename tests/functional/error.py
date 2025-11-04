class PythonVersionNotSupported(Exception):
    def __init__(self, py_ver, server):
            self.server = server
            self.py_ver = py_ver
            self.msg = f"{server['os']} does not support Python version '{py_ver}'"
            super().__init__(self.msg)