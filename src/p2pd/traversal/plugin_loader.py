"""Traversal plugin loader.

Imports each ``plugins/<name>/main.py``; the @register decorator at
module scope appends the plugin class to ``plugin_registry``.  For
each registered class:

  - if it defines an ``async setup(cls, node)`` classmethod, await it
    and use its return value as the runtime factory (None opts out --
    the plugin stays unregistered for this node)
  - otherwise the class itself is the factory (vanilla constructor)

Plugin-class metadata read off the class:

  ``name``           install name in TraversalManager.plugin_loaders
                     (defaults to the directory name)
  ``conf``           overrides for timeout / max_pairs / etc.
  ``proto_messages`` tuple of (msg_class, strategy_enum, ttl_seconds);
                     loader derives the wire name as
                     "<plugin_name>.<class.__name__>", patches it onto
                     the class as WIRE_NAME, and registers it under
                     TraversalManager.sig_proto so the plugin's
                     protocol message dispatches without core
                     proto_msg.py edits.  No SIG enum allocation needed
                     -- the qualified name is unique by Python's own
                     naming.
  ``proto_handlers`` dict of msg_class -> handler(manager, msg) for
                     pure-rendezvous signals with no plugin to run
                     (e.g. ConIdMsg).  Manager calls these BEFORE
                     falling through to plugin-creation in
                     recv_signal_msg.

Plugins shipped as separate pip-installed packages are picked up via
the ``p2pd.strategies`` entry-point group when discover() runs.
"""
import asyncio
import importlib
import os

from aionetiface import log, log_exception
from .strategy_registry import plugin_registry, discover


PLUGINS_DIR = os.path.join(os.path.dirname(__file__), "plugins")


def import_internal_plugins():
    """Import every plugins/<name>/main.py so each module's @register
    decorator fires and appends to plugin_registry.  Idempotent --
    a re-import is a no-op for plugin_registry because @register
    guards against duplicate appends via class identity at module
    import time (Python only runs class body once per import).
    """
    plugins_pkg = __name__.rsplit(".", 1)[0] + ".plugins"
    for entry in sorted(os.listdir(PLUGINS_DIR)):
        plugin_dir = os.path.join(PLUGINS_DIR, entry)
        if not os.path.isdir(plugin_dir):
            continue
        if not os.path.exists(os.path.join(plugin_dir, "main.py")):
            continue
        try:
            importlib.import_module("{0}.{1}.main".format(plugins_pkg, entry))
        except ImportError:
            log_exception()


async def load_plugins(node):
    """Discover and install every registered traversal strategy onto node."""
    import_internal_plugins()
    discover()  # external entry-point plugins, if any

    for cls in list(plugin_registry):
        plugin_name = getattr(cls, "name", cls.__name__)
        plugin_conf = dict(getattr(cls, "conf", {}))

        setup = getattr(cls, "setup", None)
        if setup is not None:
            try:
                factory = await setup(node)
            except asyncio.CancelledError:
                raise
            except (OSError, ValueError, RuntimeError) as exc:
                log("plugin_loader: {0}.setup raised {1!r}; skipping".format(
                    plugin_name, exc,
                ))
                log_exception()
                continue
            if factory is None:
                log("plugin_loader: {0}.setup returned None; skipping".format(
                    plugin_name,
                ))
                continue
            plugin_conf["class"] = factory
        else:
            plugin_conf["class"] = cls

        log("plugin_loader: registered {0}".format(plugin_name))
        node.traversal.install_plugin(plugin_name, plugin_conf)

        # Register the plugin's protocol messages onto the manager's
        # runtime registries.  Wire names are derived as
        # "<plugin_name>.<MsgClassName>" -- patched onto the class as
        # WIRE_NAME so freshly-constructed instances pick it up at
        # pack() time.  Collisions raise loudly: a typo in proto.py
        # shouldn't silently overwrite a valid registration.
        for entry in getattr(cls, "proto_messages", ()) or ():
            msg_class, strategy_enum, ttl = entry
            wire_name = "{0}.{1}".format(plugin_name, msg_class.__name__)
            msg_class.WIRE_NAME = wire_name
            existing = node.traversal.sig_proto.get(wire_name)
            if existing is not None and existing[0] is not msg_class:
                raise ValueError(
                    "proto_messages collision on {0}: {1!r} vs {2!r}".format(
                        wire_name, existing[0].__name__, msg_class.__name__,
                    )
                )
            node.traversal.sig_proto[wire_name] = [msg_class, strategy_enum, ttl]

        for msg_class, handler in (getattr(cls, "proto_handlers", {}) or {}).items():
            wire_name = getattr(msg_class, "WIRE_NAME", "") or \
                "{0}.{1}".format(plugin_name, msg_class.__name__)
            existing = node.traversal.proto_handlers.get(wire_name)
            if existing is not None and existing is not handler:
                raise ValueError(
                    "proto_handlers collision on {0}: {1!r} vs {2!r}".format(
                        wire_name, existing, handler,
                    )
                )
            node.traversal.proto_handlers[wire_name] = handler

    node.traversal.install_plugin_done_callback(node.on_plugin_done)
