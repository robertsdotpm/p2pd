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
PROTO_MESSAGES   (iterable, optional)   tuple/list of (msg_class,
                                        strategy_enum, ttl_seconds) entries.
                                        Loader derives the wire name as
                                        "<plugin_name>.<class.__name__>",
                                        patches it onto the class as
                                        WIRE_NAME, and registers it under
                                        TraversalManager.sig_proto so the
                                        plugin's protocol message dispatches
                                        without core proto_msg.py edits.
                                        No SIG enum allocation needed --
                                        the qualified name is unique by
                                        Python's own naming.
PROTO_HANDLERS   (dict, optional)       msg_class -> handler(manager, msg).
                                        For pure-rendezvous signals with
                                        no plugin to run (e.g. ConIdMsg).
                                        Manager calls these BEFORE falling
                                        through to plugin-creation in
                                        recv_signal_msg. Loader resolves
                                        the class to its wire_name at
                                        install time.

A directory is skipped when its main.py defines neither PLUGIN_CLASS nor
setup_plugin (e.g. the upnp/ helper module).
"""
from typing import Any
import asyncio
import importlib
import os

from aionetiface import log, log_exception


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
            except (OSError, ValueError, RuntimeError) as exc:
                # Without this log, an intermittent setup failure
                # (ThreadPoolExecutor pressure, STUN init flake,
                # resource registration race) silently de-registers
                # the plugin and the next connect attempt gets
                # KeyError on plugin_name lookup with no forensics.
                log("plugin_loader: {0}.setup_plugin raised {1!r}; skipping".format(
                    plugin_name, exc,
                ))
                log_exception()
                continue
            if factory is None:
                # enable_punching=False is the legitimate None path,
                # but logging it costs nothing and disambiguates
                # "configured off" from "tried to load and failed
                # silently somewhere upstream".
                log("plugin_loader: {0}.setup_plugin returned None; skipping".format(
                    plugin_name,
                ))
                continue
            plugin_conf["class"] = factory
        else:
            plugin_conf["class"] = mod.PLUGIN_CLASS

        log("plugin_loader: registered {0}".format(plugin_name))
        node.traversal.install_plugin(plugin_name, plugin_conf)

        # Auto-register the plugin's protocol messages + rendezvous
        # handlers into the manager's runtime registries. Wire names
        # are derived as "<plugin_name>.<MsgClassName>" -- patched onto
        # the class as WIRE_NAME so instances pick it up at pack() time.
        # Collisions raise loudly (a typo in plugin proto.py shouldn't
        # silently overwrite a valid registration).
        proto_messages = getattr(mod, "PROTO_MESSAGES", None) or ()
        for entry in proto_messages:
            msg_class, strategy_enum, ttl = entry
            wire_name = "{0}.{1}".format(plugin_name, msg_class.__name__)
            # Patch class attribute so freshly-constructed instances
            # report the qualified name without explicit args.
            msg_class.WIRE_NAME = wire_name
            existing = node.traversal.sig_proto.get(wire_name)
            if existing is not None and existing[0] is not msg_class:
                raise ValueError(
                    "PROTO_MESSAGES collision on {0}: {1!r} vs {2!r}".format(
                        wire_name, existing[0].__name__, msg_class.__name__,
                    )
                )
            node.traversal.sig_proto[wire_name] = [msg_class, strategy_enum, ttl]

        proto_handlers = getattr(mod, "PROTO_HANDLERS", None) or {}
        for msg_class, handler in proto_handlers.items():
            # PROTO_HANDLERS is keyed by class; resolve to wire name
            # via WIRE_NAME (set above when proto_messages registered
            # the class). If a plugin lists a handler for a class it
            # didn't register in PROTO_MESSAGES, fall back to the
            # qualified-name derivation so the registration still
            # works -- avoids a chicken-and-egg ordering bug.
            wire_name = getattr(msg_class, "WIRE_NAME", "") or \
                "{0}.{1}".format(plugin_name, msg_class.__name__)
            existing = node.traversal.proto_handlers.get(wire_name)
            if existing is not None and existing is not handler:
                raise ValueError(
                    "PROTO_HANDLERS collision on {0}: {1!r} vs {2!r}".format(
                        wire_name, existing, handler,
                    )
                )
            node.traversal.proto_handlers[wire_name] = handler

    node.traversal.install_plugin_done_callback(node.on_plugin_done)
