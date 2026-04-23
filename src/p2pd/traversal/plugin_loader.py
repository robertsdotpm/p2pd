"""Dynamic traversal plugin loader.

Scans the plugins/ directory for sub-packages that expose either a
PLUGIN_CLASS attribute or an async setup_plugin(node) function and
registers them with the node's TraversalManager.

Convention for each plugin's main.py
-------------------------------------
PLUGIN_NAME  (str, optional)          name under which the plugin is installed;
                                       defaults to the directory name
PLUGIN_CONF  (dict, optional)         overrides for timeout / max_pairs / etc.
PLUGIN_CLASS (class or factory)       use directly — for plugins with no async
                                       setup or node-level dependencies
setup_plugin (async callable)         async(node) -> factory-or-class, or None
                                       to skip; used when async init is needed
                                       (e.g. process-pool creation)

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

    node.traversal.install_plugin_done_callback(node.on_plugin_done)
