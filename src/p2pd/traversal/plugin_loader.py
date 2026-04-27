"""Dynamic traversal plugin loader.

Scans the plugins/ directory for sub-packages that expose either a
PLUGIN_CLASS attribute or an async setup_plugin(node) function and
registers them with the node's TraversalManager.

Convention for each plugin's main.py
-------------------------------------
PLUGIN_NAME      (str, optional)        name under which the plugin is
                                        installed; defaults to the directory
                                        name
PLUGIN_CONF      (dict, optional)       overrides for timeout / max_pairs / etc.
PLUGIN_CLASS     (class or factory)     use directly -- for plugins with no
                                        async setup or node-level dependencies
setup_plugin     (async callable)       async(node) -> factory-or-class, or
                                        None to skip; used when async init is
                                        needed (e.g. process-pool creation)
PROTO_MESSAGES   (iterable, optional)   tuple/list of (sig_enum, msg_class,
                                        strategy_enum, ttl_seconds) entries.
                                        Loader merges these into
                                        TraversalManager.sig_proto so the
                                        plugin's protocol message dispatches
                                        without core proto_msg.py edits.
PROTO_HANDLERS   (dict, optional)       sig_enum -> handler(manager, msg).
                                        For pure-rendezvous signals that have
                                        no plugin to run (e.g. SIG_CON_ID).
                                        Manager calls these BEFORE falling
                                        through to plugin-creation in
                                        recv_signal_msg.

A directory is skipped when its main.py defines neither PLUGIN_CLASS nor
setup_plugin (e.g. the upnp/ helper module).
"""
from typing import Any
import asyncio
import importlib
import os


PLUGINS_DIR = os.path.join(os.path.dirname(__file__), "plugins")


async def load_plugins(node: Any) -> None:
    """Discover, initialise, and install all traversal plugins under plugins/."""
    plugins_pkg = __name__.rsplit(".", 1)[0] + ".plugins"

    for entry in sorted(os.listdir(PLUGINS_DIR)):
        plugin_dir = os.path.join(PLUGINS_DIR, entry)
        if not os.path.isdir(plugin_dir):
            continue
        if not os.path.exists(os.path.join(plugin_dir, "main.py")):
            continue

        module_path = "{0}.{1}.main".format(plugins_pkg, entry)
        try:
            mod = importlib.import_module(module_path)
        except ImportError:
            continue

        if not hasattr(mod, "PLUGIN_CLASS") and not hasattr(mod, "setup_plugin"):
            continue

        plugin_name = getattr(mod, "PLUGIN_NAME", entry)
        plugin_conf = dict(getattr(mod, "PLUGIN_CONF", {}))

        if hasattr(mod, "setup_plugin"):
            try:
                factory = await mod.setup_plugin(node)
            except asyncio.CancelledError:
                raise
            except (OSError, ValueError, RuntimeError):
                continue
            if factory is None:
                continue
            plugin_conf["class"] = factory
        else:
            plugin_conf["class"] = mod.PLUGIN_CLASS

        node.traversal.install_plugin(plugin_name, plugin_conf)

        # Auto-register the plugin's protocol messages + rendezvous
        # handlers into the manager's runtime registries. Collisions
        # (two plugins claiming the same sig enum) raise loudly --
        # surfaces typos in plugin proto.py during dev rather than
        # silently overwriting a valid registration.
        proto_messages = getattr(mod, "PROTO_MESSAGES", None) or ()
        for entry in proto_messages:
            sig_enum, msg_class, strategy_enum, ttl = entry
            existing = node.traversal.sig_proto.get(sig_enum)
            if existing is not None and existing[0] is not msg_class:
                raise ValueError(
                    "PROTO_MESSAGES collision on sig {0}: {1!r} vs {2!r}".format(
                        sig_enum, existing[0].__name__, msg_class.__name__,
                    )
                )
            node.traversal.sig_proto[sig_enum] = [msg_class, strategy_enum, ttl]

        proto_handlers = getattr(mod, "PROTO_HANDLERS", None) or {}
        for sig_enum, handler in proto_handlers.items():
            existing = node.traversal.proto_handlers.get(sig_enum)
            if existing is not None and existing is not handler:
                raise ValueError(
                    "PROTO_HANDLERS collision on sig {0}: {1!r} vs {2!r}".format(
                        sig_enum, existing, handler,
                    )
                )
            node.traversal.proto_handlers[sig_enum] = handler

    node.traversal.install_plugin_done_callback(node.on_plugin_done)
