"""Sibling-install consistency check.

Catches the deployment failure modes that produce silent stale-code
runs:

  1. **Partial path divergence.** Three repos installed under
     ~/projects, one cloned outside it (e.g. ~/aionetiface).  Imports
     resolve to the wrong checkout and sync_repos updates the right
     one, so the running code never matches the file that just got
     fetched.  Symptom: KeyError 'tcp_punch' or any other plugin
     vanishing intermittently with no traceback (plugin_loader's
     `except (OSError, ValueError, RuntimeError)` swallows the real
     error mid-startup).

  2. **Stale wheel shadowing the editable install.** A previous
     `pip install <pkg>` left a copy in site-packages.  A later
     `pip install -e ../<pkg>` adds an egg-link, but sys.path order
     can let the wheel copy win.  The dev checkout updates correctly
     but the running process never sees those updates.  Symptom: the
     `__file__` attribute of the loaded module points at
     site-packages.

The verification is opt-in via the `--verify_install` flag on the
p2pd demo and is also invoked by the test runner after every
pip-install pass.  Off by default so production callers aren't
forced into a particular install layout.
"""
from typing import Any, Dict, List, Optional
import importlib
import os


SIBLING_REPOS = ("aionetiface", "p2pd", "sidewire", "namebump")


def package_path(module_name: str) -> Optional[str]:
    """Return the absolute directory of *module_name*'s package, or None on import failure."""
    try:
        mod = importlib.import_module(module_name)
    except ImportError:
        return None
    file_path = getattr(mod, "__file__", None)
    if file_path is None:
        return None
    return os.path.dirname(os.path.abspath(file_path))


def install_root(pkg_path: str) -> Optional[str]:
    """Walk up to the directory that's shared by all four siblings.

    Editable layout: <projects>/<repo>/src/<pkg>/__init__.py
        -> install_root = <projects>   (parent of the per-repo dir)

    Wheel layout: <site-packages>/<pkg>/__init__.py
        -> install_root = <site-packages>

    The root is what we cross-check across siblings -- if all four
    share a root, the install is consistent.  Going only as far as
    the per-repo dir would always disagree across the four repos.
    """
    if not pkg_path:
        return None
    parent = os.path.dirname(pkg_path)
    # Editable layout has a 'src' wrapper; skip it AND the repo dir
    # to land on the parent that's the same across siblings.
    if os.path.basename(parent) == "src":
        return os.path.dirname(os.path.dirname(parent))
    return parent


def collect_install_info() -> Dict[str, Dict[str, Any]]:
    """Return a {repo: {pkg_path, install_root, error}} map for every sibling."""
    info = {}
    for name in SIBLING_REPOS:
        pkg_path = package_path(name)
        if pkg_path is None:
            info[name] = {"error": "import failed"}
            continue
        info[name] = {
            "pkg_path": pkg_path,
            "install_root": install_root(pkg_path),
        }
    return info


def format_install_info(info: Dict[str, Dict[str, Any]]) -> List[str]:
    """Return human-readable lines summarising each sibling's install path."""
    lines = []
    for name in SIBLING_REPOS:
        entry = info.get(name, {})
        if "error" in entry:
            lines.append("install_check: {0} -> {1}".format(name, entry["error"]))
        else:
            lines.append("install_check: {0} @ {1}".format(name, entry["pkg_path"]))
    return lines


def verify_sibling_installs(strict: bool = False) -> Dict[str, Dict[str, Any]]:
    """Audit + (optionally) enforce a consistent install layout for the four sibling repos.

    Returns the info dict on success.  When *strict* is True, raises
    RuntimeError if any of the following are detected:

      * A sibling failed to import.
      * A sibling's package path contains 'site-packages' (we expect
        editable installs from a checkout, never a built wheel).
      * The install_root values disagree across siblings (catches
        partial path divergence).

    The lines that get printed are deliberately also written by
    print() so the verification output shows up in subprocess capture
    (e.g. the demo's stdout) without needing the aionetiface log
    plumbing.  That's the whole point of the check -- when an install
    is broken, the regular log might not even initialise.
    """
    info = collect_install_info()
    for line in format_install_info(info):
        print(line)

    if not strict:
        return info

    errors = []

    failed_imports = [n for n, e in info.items() if "error" in e]
    if failed_imports:
        errors.append(
            "Sibling repos failed to import: {0}".format(failed_imports),
        )

    site_pkg_repos = [
        n for n, e in info.items()
        if e.get("pkg_path") and "site-packages" in e["pkg_path"]
    ]
    if site_pkg_repos:
        errors.append(
            "Imported from site-packages (expected editable checkout): {0} -> {1}".format(
                site_pkg_repos,
                {n: info[n]["pkg_path"] for n in site_pkg_repos},
            ),
        )

    install_roots = {
        e.get("install_root") for e in info.values()
        if e.get("install_root")
    }
    if len(install_roots) > 1:
        errors.append(
            "Sibling repos diverge across install roots: {0}".format(
                sorted(r for r in install_roots if r),
            ),
        )

    if errors:
        raise RuntimeError(
            "install_check failed:\n  " + "\n  ".join(errors),
        )

    return info


if __name__ == "__main__":
    import sys
    strict = "--strict" in sys.argv
    try:
        verify_sibling_installs(strict=strict)
    except RuntimeError as exc:
        print(repr(exc))
        sys.exit(2)
