class PortAlloc():
    def __init__(self, src_port, dest_port):
        self.src_port = src_port
        self.dest_port = dest_port

    def __iter__(self):
        yield self.src_port
        yield self.dest_port