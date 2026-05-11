"""Machine-readable per-attempt telemetry for offline NAT-pair failure analysis.

Usage (opt-in):
    node = await Node().start()
    node.telemetry = TelemetryWriter()   # defaults to ~/.p2pd/telemetry.jsonl

Each successful or failed phase boundary in auto_connect emits one JSON object:
    {"ts": 1234567890.1, "phase": "phase1_direct", "plugin": "direct_connect",
     "outcome": true, "elapsed_ms": 340, "src_nat": 2, "dest_nat": 5}

Writes are guarded with try/except so a telemetry bug never breaks a real
connection.  The file rotates at 10 MB, keeping 3 backups.
"""
import json
import os
import time


MAX_BYTES = 10 * 1024 * 1024
BACKUP_COUNT = 3


class TelemetryWriter(object):
    """Write one JSON-lines record per auto_connect phase boundary to a rotating file."""

    def __init__(self, path=None):
        if path is None:
            home = os.path.expanduser("~")
            path = os.path.join(home, ".p2pd", "telemetry.jsonl")
        self.path = path
        self.fh = None
        self._open()

    def _open(self):
        try:
            d = os.path.dirname(self.path)
            if d and not os.path.exists(d):
                os.makedirs(d)
            self.fh = open(self.path, "a", encoding="utf-8")
        except Exception:
            self.fh = None

    def _rotate_if_needed(self):
        try:
            if self.fh is None:
                return
            self.fh.flush()
            size = os.path.getsize(self.path)
            if size < MAX_BYTES:
                return
            self.fh.close()
            self.fh = None
            for i in range(BACKUP_COUNT - 1, 0, -1):
                src = self.path + "." + str(i)
                dst = self.path + "." + str(i + 1)
                if os.path.exists(src):
                    if os.path.exists(dst):
                        os.remove(dst)
                    os.rename(src, dst)
            backup = self.path + ".1"
            if os.path.exists(backup):
                os.remove(backup)
            os.rename(self.path, backup)
            self._open()
        except Exception:
            pass

    def record(self, phase, plugin, outcome, elapsed_ms, src_nat, dest_nat):
        """Append one JSON record for a completed phase boundary."""
        try:
            if self.fh is None:
                return
            rec = {
                "ts": time.time(),
                "phase": phase,
                "plugin": plugin,
                "outcome": outcome,
                "elapsed_ms": elapsed_ms,
                "src_nat": src_nat,
                "dest_nat": dest_nat,
            }
            self.fh.write(json.dumps(rec) + "\n")
            self._rotate_if_needed()
        except Exception:
            pass

    def close(self):
        """Flush and close the underlying file handle."""
        try:
            if self.fh is not None:
                self.fh.flush()
                self.fh.close()
                self.fh = None
        except Exception:
            pass
