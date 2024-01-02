import re

class NetshParse():
    def __init__(self, af):
        self.af = af

    def show_interfaces(self, msg):
        p = "([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([a-z0-9]+)\s+([^\r\n]+)"
        out = re.findall(p, msg)
        results = []
        for match_group in out:
            if_index, metric, mtu, state, name = match_group
            results.append({
                "if_index": if_index,
                "metric": metric,
                "mtu": mtu,
                "state": state,
                "name": name
            })

        return results
    
    def show_addresses(self, msg):
        msg = re.sub("%[0-9]+", "", msg)

        # Regex patterns that can match address information.
        # The pattern looks for the start of the interface line.
        # To tether it so it doesn't just match all text.
        p = "[Ii]nterface\s+([0-9]+)[\s\S]+?[\r\n]([a-zA-Z0-9]+)\s+([a-zA-Z0-9]+)\s+([a-zA-Z0-9]+)\s+([a-zA-Z0-9]+)\s+((?=\S*[0-9]+\S*)([a-fA-F0-9:.]+))"

        # Build a table of all address info for each interface.
        # The table is indexed by interface no / if_index.
        results = {}
        while 1:
            # Find a valid address line for an interface
            addr_infos = re.findall(p, msg)
            if not len(addr_infos):
                break

            for addr_info in addr_infos:
                # Unpack the result.
                if_index, addr_type, dad_state, valid_life, pref_life, addr = addr_info[:6]
                if if_index not in results:
                    results[if_index] = []

                # Record details as a keyed record.
                results[if_index].append({
                    "addr_type": addr_type,
                    "dad_state": dad_state,
                    "valid_life": valid_life,
                    "pref_life": pref_life,
                    "addr": addr
                })

                # Remove the interface address line from the string.
                # Otherwise the regex will match the same result.
                #print(msg)
                msg = re.sub(p, f"Interface {if_index}\r\n", msg, count=1)

        return results


p = NetshParse(None)
m = """


"""

out = p.show_addresses(m)
print(out)