import signal

def install_signal_handlers(stop_event):
    def handler(signame, *_):
        stop_event.set()

    # Works everywhere; SIGTERM may not exist on Windows
    signal.signal(signal.SIGINT, lambda s, f: handler("SIGINT"))
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda s, f: handler("SIGTERM"))