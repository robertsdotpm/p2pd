"""Plugin registry. `@register(phase=...)` tags a class and appends it
to plugin_registry. Lowercase class attributes (`name`, `transport`,
`route_types`) carry the rest. auto_connect filters this
list instead of hardcoded plugin-name tuples.
"""
plugin_registry = []


def register(phase):
    def deco(cls):
        cls.phase = phase
        plugin_registry.append(cls)
        return cls
    return deco


def discover():
    """Import external plugins advertised under entry-point group
    `p2pd.strategies`. Each ep.load() runs the module's @register
    decorators at import time. No-op if the metadata API isn't
    available (Python 3.5-3.7 without importlib_metadata installed).
    """
    try:
        from importlib.metadata import entry_points
    except ImportError:
        try:
            from importlib_metadata import entry_points
        except ImportError:
            return
    try:
        eps = entry_points(group="p2pd.strategies")
    except TypeError:
        eps = entry_points().get("p2pd.strategies", [])
    for ep in eps:
        try:
            ep.load()
        except (ImportError, AttributeError):
            continue
