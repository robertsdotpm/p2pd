from ..errors import *
from ..settings import *
from .route.route_pool import *
from .route.route_utils import *
from .route.route_load import *
from .netifaces.netiface_fallback import *
from .nat.nat_utils import *
from .route.route_table import *
from ..protocol.stun.stun_client import *
from ..entrypoint import *

# Load mac, nic_no, and process name.
def load_if_info(nic):
    # Assume its an AF.
    if isinstance(nic.name, int):
        if nic.name not in [IP4, IP6, AF_ANY]:
            raise InterfaceInvalidAF

        nic.name = get_default_iface(nic.netifaces, afs=[nic.name])

    # No name specified.
    # Get name of default interface.
    log(fstr("Load if info = {0}", (nic.name,)))
    if nic.name is None or nic.name == "":
        # Windows -- default interface name is a GUID.
        # This is ugly AF.
        iface_name = get_default_iface(nic.netifaces)
        iface_af = get_interface_af(nic.netifaces, iface_name)
        if iface_name is None:
            raise InterfaceNotFound
        else:
            nic.name = iface_name

        # Allow blank interface names to be used for testing.
        log(fstr("> default interface loaded = {0}", (iface_name,)))

        # May not be accurate.
        # Start() is the best way to set this.
        if nic.stack == DUEL_STACK:
            nic.stack = iface_af
            log(fstr("if load changing stack to {0}", (nic.stack,)))

    # Windows NIC descriptions are used for the name
    # if the interfaces are detected as all hex.
    # It's more user friendly.
    nic.name = to_s(nic.name)

    # Check ID exists.
    if nic.netifaces is not None:
        if_names = nic.netifaces.interfaces()
        if nic.name not in if_names:
            log(fstr("interface name {0} not in {1}", (nic.name, if_names,)))
            raise InterfaceNotFound
        nic.type = get_interface_type(nic.name)
        nic.nic_no = 0
        if hasattr(nic.netifaces, 'nic_no'):
            nic.nic_no = nic.netifaces.nic_no(nic.name)
            nic.id = nic.nic_no
        else:
            nic.id = nic.name

        nic.netiface_index = if_names.index(nic.name)

    return nic

async def load_interface(nic, netifaces, min_agree, max_agree, timeout):
    stack = nic.stack
    log(fstr("Starting resolve with stack type = {0}", (stack,)))
    
    # Load internal interface details.
    nic.netifaces = await p2pd_setup_netifaces()

    # Process interface name in right format.
    try:
        load_if_info(nic)
    except InterfaceNotFound:
        raise InterfaceNotFound
    except Exception:
        log_exception()
        load_if_info_fallback(nic)

    # This will be used for the routes call.
    # It's only purpose is to pass in a custom netifaces for tests.
    netifaces = netifaces or nic.netifaces

    # Get routes for AF.
    tasks = []
    for af in VALID_AFS:
        log(fstr("Attempting to resolve {0}", (af,)))

        # Initialize with blank RP.
        nic.rp[af] = RoutePool()

        # Used to resolve nic addresses.
        servs = STUN_MAP_SERVERS[UDP][af][:max(20, max_agree)]
        random.shuffle(servs)
        stun_clients = await get_stun_clients(
            af,
            max_agree,
            nic,
            servs=servs
        )

        assert(len(stun_clients) <= max_agree)

        # Is this default iface for this AF?
        try:
            if nic.is_default(af):
                enable_default = True
            else:
                enable_default = False
        except Exception:
            # If it's poorly supported allow default NIC behavior.
            log_exception()
            enable_default = True
        log(fstr("{0} {1} {2}", (nic.name, af, enable_default,)))

        # Use a threshold of pub servers for res.
        tasks.append(
            async_wrap_errors(
                discover_nic_wan_ips(
                    af,
                    min_agree,
                    enable_default,
                    nic,
                    stun_clients,
                    netifaces,
                    timeout=timeout,
                )
            )
        )

    # Get all the routes concurrently.
    results = await asyncio.gather(*tasks)
    results = [r for r in results if r is not None]
    for af, routes, link_locals in results:
        nic.rp[af] = RoutePool(routes, link_locals)

    # Update stack type based on routable.
    nic.stack = get_interface_stack(nic.rp)
    assert(nic.stack in VALID_STACKS)
    nic.resolved = True

    # Set MAC address of Interface.
    nic.mac = await get_mac_address(nic.name, nic.netifaces)
    if nic.mac is None:
        # Currently not used for anything important.
        # Might as well not crash if not needed.
        log("Could not load mac. Setting to blank.")
        nic.mac = ""

    # If there's only 1 interface set is_default.   
    ifs = clean_if_list(nic.netifaces.interfaces())
    if len(ifs) == 1:
        nic.is_default = nic.is_default_patch

    return nic