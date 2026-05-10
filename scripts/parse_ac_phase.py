"""Parse [AC-PHASE] log lines and print a NAT-pair pivot table.

Usage:
    python scripts/parse_ac_phase.py <log_file>
    cat sweep.log | python scripts/parse_ac_phase.py

Each [AC-PHASE] line must have the format emitted by auto_connect.py:
    [AC-PHASE] <phase_fn> -> pipe=<True|False> plugin=<name> src_nat=<int|None> dest_nat=<int|None> elapsed=<int>ms

Output: table of (phase, src_nat, dest_nat) -> ok_count, fail_count, pct, avg_elapsed_ms
sorted by fail_count descending so the worst combinations appear first.
"""
import re
import sys
import collections

NAT_NAMES = {
    1: "OPEN",
    2: "FULL_CONE",
    3: "RESTRICT_ADDR",
    4: "RESTRICT_PORT",
    5: "SYMMETRIC",
    6: "BLOCKED",
}

PATTERN = re.compile(
    r"\[AC-PHASE\]\s+(\S+)\s+->\s+pipe=(\S+)\s+plugin=(\S+)\s+"
    r"src_nat=(\S+)\s+dest_nat=(\S+)\s+elapsed=(\d+)ms"
)


def nat_label(raw):
    try:
        v = int(raw)
        return NAT_NAMES.get(v, str(v))
    except (TypeError, ValueError):
        return str(raw)


def main():
    if len(sys.argv) > 1:
        fh = open(sys.argv[1], "r")
    else:
        fh = sys.stdin

    Row = collections.namedtuple("Row", ["ok", "fail", "elapsed_total"])
    counts = collections.defaultdict(lambda: Row(0, 0, 0))

    total = 0
    matched = 0
    with fh:
        for raw_line in fh:
            total += 1
            m = PATTERN.search(raw_line)
            if not m:
                continue
            matched += 1
            phase, pipe_s, plugin, src_nat_s, dest_nat_s, elapsed_s = m.groups()
            ok = pipe_s.lower() == "true"
            elapsed = int(elapsed_s)
            key = (phase, nat_label(src_nat_s), nat_label(dest_nat_s))
            r = counts[key]
            if ok:
                counts[key] = Row(r.ok + 1, r.fail, r.elapsed_total + elapsed)
            else:
                counts[key] = Row(r.ok, r.fail + 1, r.elapsed_total + elapsed)

    print("Scanned {0} lines, matched {1} [AC-PHASE] entries.".format(total, matched))
    print()

    if not counts:
        print("No [AC-PHASE] lines found.")
        return

    header = "{:<28} {:<18} {:<18} {:>6} {:>6} {:>7} {:>12}".format(
        "phase", "src_nat", "dest_nat", "ok", "fail", "pct_ok", "avg_elapsed"
    )
    print(header)
    print("-" * len(header))

    sorted_keys = sorted(
        counts.keys(),
        key=lambda k: -counts[k].fail,
    )
    for key in sorted_keys:
        r = counts[key]
        n = r.ok + r.fail
        pct = "{0:.0f}%".format(100.0 * r.ok / n) if n else "-"
        avg_ms = "{0}ms".format(r.elapsed_total // n) if n else "-"
        print("{:<28} {:<18} {:<18} {:>6} {:>6} {:>7} {:>12}".format(
            key[0], key[1], key[2], r.ok, r.fail, pct, avg_ms,
        ))


if __name__ == "__main__":
    main()
