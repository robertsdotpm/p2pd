from ..errors import *
from ..settings import *
from .route.route_defs import *
from .route.route_utils import *
from .nat.nat_utils import *
from .route.route_table import *
from ..protocol.stun.stun_client import *
from ..entrypoint import *

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
    except:
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
        servs = STUN_MAP_SERVERS[UDP][af]
        random.shuffle(servs[:max(20, max_agree)])
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
        except:
            # If it's poorly supported allow default NIC behavior.
            log_exception()
            enable_default = True
        log(fstr("{0} {1} {2}", (nic.name, af, enable_default,)))

        # Use a threshold of pub servers for res.
        main_res = get_routes_with_res(
            af,
            min_agree,
            enable_default,
            nic,
            stun_clients,
            netifaces,
            timeout=timeout,
        )

        # If it fails use 'official' servers.
        tasks.append(
            async_wrap_errors(
                route_res_with_fallback(
                    af,
                    enable_default,
                    nic,
                    main_res
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