# p2pd — project instructions

## Python compatibility

`requires-python = ">=3.5"` is intentional and must not be changed. Do not raise the minimum Python version under any circumstances.

## Dependency versions

Never add version pins to package dependencies in `setup.py`, `pyproject.toml`, or any requirements file. List packages by name only (e.g. `"ecdsa"` not `"ecdsa>=0.18"`). The only version constraint that may appear is `python_requires=">=3.5"`.

## String formatting

Never use f-string literals (`f"..."`). They require Python 3.6+ and break the 3.5 constraint. Use `.format()` or import and use `fstr(template, args_tuple)` from `aionetiface.utility.utils`:

```python
"value is {}".format(val)
fstr("value is {0}", (val,))
```

`fstr()` is a regex-based formatter and **only supports `{N}` positional placeholders**. Format-spec syntax (`{N!r}`, `{N!s}`, `{N:>5}`, `{N:.3f}`, etc.) raises `ValueError` because the regex captures the whole `1!r` and tries `int("1!r")`. If you want repr/str/formatted output, pre-format the value and pass the resulting string:

```python
# WRONG -- raises ValueError inside fstr at call time
log(fstr("name={0!r} count={1:>5}", (name, count)))

# RIGHT
log(fstr("name={0} count={1}", (repr(name), "%5d" % count)))
```

This bug bites silently because the `ValueError` from fstr in a logging call (e.g. inside an `except` handler that itself uses fstr with `!r`) cascades and can swallow the original exception — making the failure look like a hang or silent drop rather than a logging issue. Stick to plain `{N}` in every fstr template.

## Naming

Never use leading-underscore names for variables, attributes, methods, or functions (e.g. no `_foo`, `_cancel_tasks`, `_private`). Use plain names. The single exception is dunder names (`__init__`, `__all__`, etc.) which are required by Python itself.

## Print statements

Never remove or comment out `print()` calls. They are intentional debugging and observability hooks — leave them exactly as found.

## Error handling

- Use `ValueError` for invalid input at API boundaries.
- Use `AssertionError` (or bare `assert`) for internal invariants that should never be false.
- Do not use `RuntimeError` as a catch-all for invariant violations.
- Do not use `ast.literal_eval` on user-supplied input — parse it explicitly.
- Pick one error idiom per function: either return a sentinel value or raise — not both.

## Writing tests

**Never use pytest-specific code.** All tests use `unittest` with `AsyncTestCase` from `aionetiface.testing`.

### The required pattern

```python
import unittest
from aionetiface.testing import AsyncTestCase

class TestMyFeature(AsyncTestCase):
    async def asyncSetUp(self):
        # async setup — runs before each test
        self.node = await start_something()

    async def asyncTearDown(self):
        # async teardown — runs after each test
        await self.node.close()

    async def test_something(self):
        result = await self.node.do_thing()
        self.assertEqual(result, expected)

    async def test_skip_example(self):
        if condition:
            self.skipTest("reason")
        ...
```

### Rules

- Base class is always `AsyncTestCase` — never `unittest.TestCase`, `unittest.IsolatedAsyncioTestCase`, or any pytest class.
- Test methods are `async def` coroutines — the backport handles them on Python 3.5–3.7.
- Use `self.skipTest("reason")` — never `pytest.skip(...)`.
- Never import `pytest`. Never use `@pytest.mark.*` decorators.
- `aionetiface.testing` calls `aionetiface_setup_event_loop()`, applies the linecache no-op, and opens the Windows firewall rule automatically when imported. No conftest.py setup needed.

### Heavy tests live in their own file

The runner spawns one unittest subprocess per `test_*.py` file, so every file's tests share one Python process. Tests that start `Node`s, open MQTT/TCP connections, or spawn dispatcher tasks accumulate state across each test in that process — sockets in TIME_WAIT, MQTT sessions the broker is rate-limiting, dispatcher tasks the loop never fully drained. By the 4th or 5th heavy test in a single file, that residue can stall the next test long enough to hit the runner's per-file SIGKILL budget. We hit this in real life: `test_demo_smoke.py`, `test_docs_quickstart.py`, and `test_auto_connect.py` all had connectivity classes that hung 300s on multiple VMs until each heavy class was extracted into its own file.

Rule: when a class spins up real `Node`s / MQTT clients / TURN servers, move it into its own `test_*.py` so it gets a fresh subprocess. Keep network-free unit tests grouped together; isolate the heavy stuff. Put the heavy class's helpers into a sibling `<name>_helpers.py` (no `test_` prefix so the runner doesn't pick it up) and import from there. Reference layout: `test_auto_connect.py` keeps the unit-test classes; `test_auto_connect_ipv4.py` / `_ipv6` / `_reverse` / `_multi` / `_punch` / `_turn` each hold one AsyncTestCase class; shared helpers live in `auto_connect_helpers.py`.

### Running tests

Pull all four repos first:

```cmd
cd C:\Users\<user>\projects\p2pd && git fetch origin && git reset --hard origin/ai_experiment
cd C:\Users\<user>\projects\aionetiface && git fetch origin && git reset --hard origin/ai_experiment
cd C:\Users\<user>\projects\namebump && git fetch origin && git reset --hard origin/main
cd C:\Users\<user>\projects\sidewire && git fetch origin && git reset --hard origin/main
```

Run with `unittest discover` (sequential, reliable):

```sh
python -m unittest discover -s tests -p "test_*.py" -v
```

On Windows:

```cmd
C:\Users\<user>\.pyenv\pyenv-win\versions\3.8.6\python.exe -m unittest discover -s tests -p "test_*.py" -v
```

### asyncio debug mode

Never call `loop.set_debug(True)`. `IsolatedAsyncioTestCase` (Python 3.8+) sets it automatically, but `aionetiface.testing` neutralises the linecache overhead with a no-op patch.

### Install quirks (Python 3.5)

`setuptools>=68` uses Python 3.8+ syntax. On Python 3.5, bypass the build system:

```sh
pip install wheel "setuptools<50"
pip install --no-build-isolation --no-deps -e .
pip install --no-build-isolation --no-deps -e ../aionetiface
pip install --no-build-isolation --no-deps -e ../namebump
pip install --no-build-isolation --no-deps -e ../sidewire
```

On Python 3.5.0 specifically:

```sh
pip install "pathlib2==2.2.1" "pytest==4.6.11"
```

## PNP/MQTT propagation race after node startup

When `node_start` returns (or `setup_node` in `demo/__main__.py`), the node has put its PNP record on the configured PNP servers and subscribed to its MQTT signaling topic. Those operations may not yet be visible to every server in the pool. A peer that resolves this node's nickname, or routes signaling via its MQTT topic, in the immediate window after node startup completes can race a server that hasn't yet seen the put / accepted the subscribe, and will silently hang in the resolve or dispatch step.

**This affects every cross-node test in the matrix** — anything with a listener-then-connector flow. The connector side MUST allow a settling window of ~8 seconds before it starts resolving the listener's nickname. `demo/__main__.py:setup_node` enforces this with `await asyncio.sleep(8)` after `Nickname.put` completes; tests or callers that bypass `setup_node` must insert an equivalent sleep themselves before any cross-node lookup.

The full warning lives in the `node_start` docstring at `node/node_start.py`.
